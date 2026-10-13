"""Bounded file inspection without executing runners or following symbolic links."""
import hashlib
from itertools import islice
import json
from .structured import loads as bounded_json_loads
import os
import platform
import plistlib
import re
import stat
import struct
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .acquisition import unlinked
from .traversal import Budget, walk, TraversalLimit
from .discovery import match_rule, coverage, source_profile
from .conversations import parse_versioned
from .ollama_layers import recover_saved_messages
from .desktop_sqlite import read_desktop
from .llama_artifacts import inspect_llama

MAX_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 10000
COMMAND = re.compile(r"(?:^|[\s/\\;|&\"'])(?:llama-cli|llama-server|llama-completion|llama)(?:\.exe)?(?=[\s\"']|$)", re.I)


def is_link_or_reparse(path):
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def candidate(path):
    rule = match_rule(path)
    return (rule.runner, rule.kind) if rule else None


def extract_messages(value, pointer="", depth=0):
    """Extract only explicit role/content pairs; never infer undocumented fields."""
    if depth > 64:
        return
    if isinstance(value, dict):
        if value.get("role") in ("user", "assistant", "system", "tool") and isinstance(value.get("content"), str):
            yield {"record_locator": pointer or "/", "role": value["role"], "text": value["content"],
                   "timestamp": None, "timestamp_basis": "not interpreted"}
        for key, child in value.items():
            escaped = str(key).replace("~", "~0").replace("/", "~1")
            yield from extract_messages(child, pointer + "/" + escaped, depth + 1)
    elif isinstance(value, list):
        for i, child in enumerate(value):
            yield from extract_messages(child, pointer + "/" + str(i), depth + 1)


def inspect_file(path, runner, kind, max_bytes, recover_deleted=False):
    if kind == "desktop_sqlite":
        return read_desktop(path, max_bytes, __version__, recover_deleted)
    # O_NOFOLLOW guards the final component. Use an acquired, stable evidence tree;
    # this prototype does not guarantee atomic traversal on a changing live host.
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("not a regular file")
        limit = 24 if kind in {"gguf_header", "ollama_blob_probe"} else max_bytes
        data = stream.read(limit + (kind not in {"gguf_header", "ollama_blob_probe"}))
        after = os.fstat(stream.fileno())
    changed = (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
    finding = {
        "runner": runner, "artifact_type": kind, "source_path": str(path),
        "size_bytes": before.st_size,
        "filesystem_metadata": {"basis":"analyzed file; captured copies can have different creation/change times from the original", "size_bytes": before.st_size, "mode": oct(stat.S_IMODE(before.st_mode)), "inode": before.st_ino, "device": before.st_dev, "mtime_ns": before.st_mtime_ns, "ctime_ns": before.st_ctime_ns, "birthtime": getattr(before,"st_birthtime",None)},
        "filesystem_mtime_utc": datetime.fromtimestamp(before.st_mtime, timezone.utc).isoformat(),
        "mtime_meaning": "filesystem modification time; not proof of an interaction time",
        "parser_version": __version__, "validation": "experimental; synthetic fixtures only",
        "status": "parsed", "observations": [], "limitations": [],
        "source_changed_during_read": changed,
    }
    if changed:
        finding["limitations"].append("Source changed during inspection; reacquire before relying on this finding.")
    if kind == "ollama_blob_probe":
        if not data.startswith(b"GGUF"):
            return None
        kind = "gguf_header"
        finding["artifact_type"] = kind
    if kind == "gguf_header":
        finding["sha256"] = hashlib.sha256(data).hexdigest()
        finding["hash_scope"] = f"first {len(data)} bytes only; not whole model"
        if len(data) != 24 or data[:4] != b"GGUF":
            finding["status"] = "invalid_header"
            return finding
        version, tensors, metadata = struct.unpack("<IQQ", data[4:])
        finding["observations"] = [{"record_locator": "bytes 0–23", "version": version,
                                    "tensor_count": tensors, "metadata_count": metadata}]
        finding["status"] = "header_only" if version in {2, 3} else "unsupported_version"
        finding["limitations"] += ["Header inspection only; model structure and contents not validated.",
                                    "A GGUF header does not prove execution or identify a particular runner."]
        return finding
    if len(data) > max_bytes:
        if kind == "llama_signature_probe":
            finding["limitations"].append("Extension candidate only; signature not validated because file exceeds read limit.")
        finding.update(status="size_limit", sha256=None, hash_scope="not hashed")
        finding["limitations"].append("File exceeds configured read limit; content was not parsed.")
        return finding
    finding.update(sha256=hashlib.sha256(data).hexdigest(), hash_scope="complete bytes read")
    if kind == "llama_signature_probe":
        adapted = inspect_llama(data)
        if adapted is None: return None
        finding.update(adapted)
        finding["runner"] = "llama_cpp"
        finding["validation"] = "Observed on macOS llama.cpp build b11146; log signature and v10 token header only."
        return finding
    if kind in {"application_plist", "preferences_plist"}:
        try:
            values=plistlib.loads(data)
            if not isinstance(values,dict):raise ValueError('Expected plist dictionary')
            keys=('CFBundleName','CFBundleIdentifier','CFBundleShortVersionString','CFBundleVersion','LSMinimumSystemVersion') if kind=='application_plist' else ('SUHasLaunchedBefore','SUEnableAutomaticChecks','SUAutomaticallyUpdate','SULastCheckTime','NSQuitAlwaysKeepsWindows')
            # Serialize only bounded primitive values; plist dates/bytes are explicit text.
            values={k:(v.isoformat() if isinstance(v,datetime) else v if isinstance(v,(str,int,float,bool)) else '[non-scalar value omitted]') for k,v in values.items() if k in keys}
            finding['observations']=[{'record_locator':'plist root',('bundle_metadata' if kind=='application_plist' else 'preference_values'):{k:values[k] for k in keys if k in values}}]
            finding['validation']='Selected scalar plist fields; observed preference paths on the local macOS host.'
            finding['limitations'].append('Bundle/preference values are stored configuration, not authenticated proof of execution. Referenced paths are not followed. Preference timestamps are not chat times.')
        except (ValueError,plistlib.InvalidFileException,TypeError,OverflowError,RecursionError):finding['status']='parse_error'
        return finding
    try:
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            if kind != "shell_history" or path.name != ".zsh_history":
                raise
            # zsh Src/zsh.h: Meta (0x83) escapes the following byte XOR 32.
            # Strict fallback only: ordinary UTF-8 histories remain unchanged.
            decoded = bytearray()
            index = 0
            pairs = 0
            while index < len(data):
                value = data[index]
                if value == 0x83:
                    if index + 1 >= len(data):
                        raise ValueError("Truncated zsh Meta escape")
                    index += 1
                    value = data[index] ^ 32
                    if value != 0 and not 0x83 <= value <= 0xa2:
                        raise ValueError("Invalid zsh Meta escape")
                    pairs += 1
                decoded.append(value)
                index += 1
            text = decoded.decode("utf-8-sig")
            finding["text_decoding"] = {"encoding": "zsh Meta escapes then UTF-8", "meta_pairs": pairs}
            finding["limitations"].append("Zsh Meta escapes decoded for display; original bytes and hash preserved. Line locators refer to decoded text; multiline commands are not reconstructed.")
        if kind == "settings_json":
            value=bounded_json_loads(text)
            if not isinstance(value,dict):raise ValueError('Expected settings object')
            keys=('downloadsFolder','developerMode','enableLocalService','cliInstalled','defaultContextLength','appIntroAcceptedForBuild')
            finding['observations']=[{'record_locator':'/','settings':{k:value[k] for k in keys if k in value},'omitted_keys':sorted(set(value)-set(keys))}]
            finding['limitations'].append('Only selected configuration fields are displayed. Credential values and other fields remain unreported; referenced paths are not followed.')
            return finding
        if kind in {"manifest", "conversation_json", "saved_messages"}:
            value = bounded_json_loads(text)
            if kind == "saved_messages":
                finding["schema_adapter"] = "ollama-message-layer-array"
                finding["unparsed_records"] = []
                if not isinstance(value, list):
                    finding["status"] = "unsupported_schema"
                else:
                    for i, message in enumerate(value[:MAX_RECORDS]):
                        if isinstance(message, dict) and message.get("role") in ("user", "assistant", "system", "tool") and isinstance(message.get("content"), str):
                            finding["observations"].append({"record_locator": f"/{i}/content", "role": message["role"], "text": message["content"], "message_index": i, "timestamp": None, "timestamp_basis": "not stored in message layer"})
                        else:
                            finding["unparsed_records"].append({"record_locator": f"/{i}", "reason": "unsupported message shape"})
                    if len(value)>MAX_RECORDS:
                        finding["status"]="partial";finding["limitations"].append("Record limit reached: first 10000 stored messages only.")
                    if finding["unparsed_records"]:
                        finding["status"] = "partial" if finding["observations"] else "unsupported_schema"
            elif kind == "conversation_json":
                adapted = parse_versioned(value)
                if adapted is not None:
                    finding.update(adapted)
                    finding["limitations"].append("Versioned-block adapter observed on LM Studio 0.4.25 macOS. All versions retained; stored selected index reported when valid. Message timestamps not inferred.")
                else:
                    finding["schema_adapter"] = "generic-role-content"
                    finding["observations"] = list(islice(extract_messages(value), MAX_RECORDS + 1))
                    if len(finding["observations"]) > MAX_RECORDS:
                        finding["observations"] = finding["observations"][:MAX_RECORDS]
                        finding["status"] = "partial"
                        finding["limitations"].append("Record limit reached: first 10000 role/content records only.")
                    finding["limitations"].append("Generic role/content extraction only; branches, blocks and application schemas are not validated.")
                if not finding["observations"]:
                    finding["status"] = "unsupported_schema"
            elif isinstance(value, dict) and isinstance(value.get("layers"), list):
                finding["observations"] = [{"record_locator": "/", "schemaVersion": value.get("schemaVersion"),
                                            "config": value.get("config"), "layers": value["layers"]}]
                finding["limitations"].append("Manifest references are not verified against model blobs; presence does not prove execution.")
            else:
                finding["status"] = "unsupported_schema"
        else:
            for line_number, line in enumerate(text.splitlines(), 1):
                if not line.strip() or (kind == "shell_history" and not COMMAND.search(line)):
                    continue
                if len(finding["observations"])>=MAX_RECORDS:
                    finding["status"]="partial";finding["limitations"].append("Record limit reached: first 10000 matching lines only.");break
                finding["observations"].append({"record_locator": f"line {line_number}", "text": line,
                                                "timestamp": None, "timestamp_basis": "not interpreted"})
            if kind == "shell_history" and not finding["observations"]:
                return None
            finding["limitations"].append("Text preserved as source records; no execution, authorship, or exact event time inferred.")
    except (UnicodeError, ValueError, RecursionError) as exc:
        finding["status"] = "parse_error"
        finding["limitations"].append(f"{type(exc).__name__}: content could not be decoded or parsed")
    return finding


def scan(root, max_bytes=MAX_BYTES, source_os="unknown", recover_deleted=False, traversal_budget=None):
    rule_coverage = coverage(source_os)
    coverage_by_id = {r["rule_id"]: r for r in rule_coverage}
    root = Path(root)
    if is_link_or_reparse(root):
        raise ValueError("Evidence input must not be a symlink or reparse point")
    root = unlinked(root).resolve(strict=True)
    single_file = root.is_file()
    if not root.is_dir() and not single_file:
        raise ValueError("Evidence input must be a regular file or directory")
    report = {"tool": "Local LLM Forensics", "version": __version__, "evidence_root": str(root),
              "scan_started_utc": datetime.now(timezone.utc).isoformat(), "findings": [], "issues": [],
              "files_considered": 0, "analysis_host_os": platform.system(),
              "source_os": source_os, "source_os_basis": "operator declaration" if source_os != "unknown" else "not specified",
              "discovery_coverage": rule_coverage,
              "limitations": ["Experimental triage of existing files; optional recovery examines supported SQLite freelist residue, not deleted filesystem files.",
                              "No runner processes, APIs, network services or model inference are invoked.",
                              "Reading may affect filesystem access times. Use a read-only acquired copy for evidence work.",
                              "Detection uses known path patterns and .gguf filenames; it is not exhaustive.",
                              "No findings does not establish absence of local LLM use."]}

    def error(exc):
        report["issues"].append({"path": str(exc.filename), "status": "inaccessible", "detail": str(exc)})

    budget=traversal_budget if traversal_budget is not None else Budget()
    def limit(exc):report['issues'].append({'path':str(root),'status':'traversal_limit','detail':str(exc)})
    entries=walk(root,budget,error,limit,single_file)
    stopped=False
    for directory, dirs, files in entries:
        for name in list(dirs):
            p = Path(directory, name)
            try:
                linked = is_link_or_reparse(p)
            except OSError as exc:
                error(exc)
                if name in dirs:
                    dirs.remove(name)
                continue
            if linked:
                dirs.remove(name)
                report["issues"].append({"path": str(p), "status": "symlink_skipped"})
        for name in sorted(files):
            try:budget.check()
            except TraversalLimit as exc:
                limit(exc);stopped=True;break
            p = Path(directory, name)
            report["files_considered"] += 1
            try:
                linked = is_link_or_reparse(p)
            except OSError as exc:
                error(exc)
                if name in dirs:
                    dirs.remove(name)
                continue
            if linked:
                report["issues"].append({"path": str(p), "status": "symlink_skipped"})
                continue
            relative = Path(p.name) if single_file else p.relative_to(root)
            # Full path preserves known app context before broad signature probes.
            rule = match_rule(p, source_os) or match_rule(Path(root.name) / relative, source_os) or match_rule(relative, source_os)
            if not rule:
                continue
            coverage_by_id[rule.id]["candidate_files"] += 1
            coverage_by_id[rule.id]["status"] = "candidates_found"
            try:
                finding = inspect_file(p, rule.runner, rule.kind, max_bytes, recover_deleted)
                if finding:
                    finding["evidence_relative_path"] = relative.as_posix()
                    finding["discovery_rule"] = rule.id
                    if rule.id == "lmstudio-macos-trash":
                        finding["artifact_context"] = "OS Trash path; recoverable file, not carved deleted storage"
                        finding["limitations"].append("Trash location suggests removal from active storage; no deletion time or deleting actor is inferred.")
                    finding["source_profile_hint"] = source_profile(relative, source_os)
                    finding["id"] = f"artifact-{len(report['findings']) + 1}"
                    report["findings"].append(finding)
            except (OSError, ValueError, OverflowError) as exc:
                report["issues"].append({"path": str(p), "status": "inspection_failed", "detail": str(exc)})
        if stopped:break
    def inspect_linked(*args):
        budget.take()
        return inspect_file(*args)
    recover_saved_messages(report, max_bytes, inspect_linked)
    report["traversal"]=budget.snapshot()
    report["scan_finished_utc"] = datetime.now(timezone.utc).isoformat()
    return report
