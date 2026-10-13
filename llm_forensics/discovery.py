"""Host-independent rules for paths inside acquired evidence trees.

OS selections are operator declarations, not inferred facts. Shared rules remain
enabled for mixed evidence and portable applications. No source paths are followed.
"""
from dataclasses import dataclass
from fnmatch import fnmatchcase

SOURCE_OSES = ("unknown", "windows", "macos", "linux")


@dataclass(frozen=True)
class Rule:
    id: str
    runner: str
    kind: str
    pattern: str
    systems: tuple = ()


RULES = (
    Rule("ollama-preferences-macos", "ollama", "preferences_plist", "*/Library/Preferences/com.electron.ollama.plist", ("macos",)),
    Rule("lm_studio-preferences-macos", "lm_studio", "preferences_plist", "*/Library/Preferences/ai.elementlabs.lmstudio.plist", ("macos",)),
    Rule("lmstudio-app-logs-macos", "lm_studio", "log", "*/Library/Logs/LM Studio/*.log", ("macos",)),
    Rule("ollama-app-macos", "ollama", "application_plist", "*/Ollama.app/Contents/Info.plist", ("macos",)),
    Rule("lmstudio-app-macos", "lm_studio", "application_plist", "*/LM Studio.app/Contents/Info.plist", ("macos",)),
    Rule("lmstudio-settings", "lm_studio", "settings_json", "*/.lmstudio/settings.json"),
    Rule("lmstudio-legacy-settings", "lm_studio", "settings_json", "*/.cache/lm-studio/settings.json"),
    Rule("ollama-desktop-macos", "ollama", "desktop_sqlite", "*/Library/Application Support/Ollama/db.sqlite", ("macos",)),
    Rule("ollama-desktop-windows", "ollama", "desktop_sqlite", "*/AppData/Local/Ollama/db.sqlite", ("windows",)),
    Rule("ollama-model-blob", "ollama", "ollama_blob_probe", "*/.ollama/models/blobs/sha256-*"),
    Rule("ollama-history", "ollama", "cli_history", "*/.ollama/history"),
    Rule("ollama-manifest", "ollama", "manifest", "*/.ollama/models/manifests/*"),
    Rule("ollama-user-logs", "ollama", "log", "*/.ollama/logs/*.log"),
    Rule("ollama-windows-logs", "ollama", "log", "*/AppData/Local/Ollama/*.log", ("windows",)),
    Rule("ollama-linux-service", "ollama", "configuration_text", "*/systemd/system/ollama.service", ("linux",)),
    Rule("ollama-linux-overrides", "ollama", "configuration_text", "*/systemd/system/ollama.service.d/*.conf", ("linux",)),
    Rule("lmstudio-macos-trash", "lm_studio", "conversation_json", "*/.Trash/*.conversation.json", ("macos",)),
    Rule("lmstudio-legacy-chats", "lm_studio", "conversation_json", "*/.cache/lm-studio/conversations/*.json"),
    Rule("lmstudio-chats", "lm_studio", "conversation_json", "*/.lmstudio/conversations/*.json"),
    Rule("lmstudio-server-logs", "lm_studio", "log", "*/.lmstudio/server-logs/*.log"),
    Rule("lmstudio-home-pointer", "lm_studio", "configuration_text", "*/.lmstudio-home-pointer"),
    Rule("bash-history", "llama_cpp", "shell_history", "*/.bash_history"),
    Rule("zsh-history", "llama_cpp", "shell_history", "*/.zsh_history"),
    Rule("powershell-history", "llama_cpp", "shell_history", "*/ConsoleHost_history.txt", ("windows",)),
    Rule("llama-log-signature", "unknown", "llama_signature_probe", "*/*.log"),
    Rule("llama-cache-signature", "unknown", "llama_signature_probe", "*/*.cache"),
    Rule("llama-session-signature", "unknown", "llama_signature_probe", "*/*.session"),
    Rule("llama-bin-signature", "unknown", "llama_signature_probe", "*/*.bin"),
    Rule("gguf-extension", "unknown", "gguf_header", "*/*.gguf"),
)


def enabled_rules(source_os):
    if source_os not in SOURCE_OSES:
        raise ValueError("Unrecognized source OS")
    return [r for r in RULES if not r.systems or source_os == "unknown" or source_os in r.systems]


def match_rule(path, source_os="unknown"):
    # A caller may supply Windows notation while running on a Unix host.
    value = str(path).replace("\\", "/")
    value = "/" + value.lstrip("/")
    for rule in enabled_rules(source_os):
        pattern = rule.pattern
        # Do not collapse case distinctions on Linux/macOS evidence. Unknown
        # enables permissive candidate discovery and makes no OS attribution.
        if source_os in {"windows", "unknown"}:
            matched = fnmatchcase(value.casefold(), pattern.casefold())
        else:
            matched = fnmatchcase(value, pattern)
        if matched:
            return rule
    return None


def source_profile(path, source_os):
    """Best-effort path association, not an assertion about the human operator."""
    parts = str(path).replace("\\", "/").split("/")
    for index, part in enumerate(parts[:-1]):
        target = part.casefold() if source_os in {"windows", "unknown"} else part
        if target in ({"users", "home"} if source_os in {"windows", "unknown"} else {"Users", "home"}):
            return parts[index + 1]
    return None


def coverage(source_os):
    return [{"rule_id": r.id, "runner": r.runner, "pattern": r.pattern,
             "platforms": list(r.systems) or ["shared"], "candidate_files": 0,
             "status": "no_match_in_readable_scope"} for r in enabled_rules(source_os)]
