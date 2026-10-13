"""Exercise a packaged CLI using disposable synthetic evidence only."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

command = sys.argv[1:]
if not command:
    raise SystemExit("Usage: python smoke_cli.py <executable> [launcher arguments]")


def run(*args):
    return subprocess.run(command + list(args), check=True, capture_output=True, text=True)


run("--help")
run("--version")
with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary).resolve()
    evidence = root / "evidence"
    source = evidence / "Users" / "Analyst" / ".ollama" / "history"
    source.parent.mkdir(parents=True)
    data = b"SYNTHETIC_PACKAGED_CLI_CHECK\n"
    source.write_bytes(data)
    for mode in ("json", "html", "both"):
        output = root / mode
        run(str(evidence), "--source-os", "windows", "--format", mode, "--output", str(output))
        assert (output / "report.json").exists() == (mode in {"json", "both"})
        assert (output / "report.html").exists() == (mode in {"html", "both"})
        if mode in {"json", "both"}:
            result = json.loads((output / "report.json").read_text(encoding="utf-8"))
            assert result["source_os"] == "windows"
            assert len(result["findings"]) == 1
            assert result["findings"][0]["sha256"] == hashlib.sha256(data).hexdigest()
    custom = root / "custom-home"
    custom.mkdir()
    (custom / "history").write_bytes(data)
    case = root / "captured-case"
    run("--ollama-home", str(custom), "--acquire", "--source-os", "macos",
        "--timeline", "--strict", "--format", "both", "--output", str(case))
    report = json.loads((case / "report.json").read_text())
    assert report["findings"][0]["original_source_path"] == str(custom / "history")
    assert (case / "timeline.json").exists()
    run("--verify-case", str(case))
    run('--verify-package', str(case))
    run('--bundle-case', str(case), '--output', str(root/'bundle'))
    import tarfile
    with tarfile.open(root/'bundle/case.tar.gz') as archive:
        archive.extractall(root/'relocated',filter='data')
    run('--verify-package',str(root/'relocated/case'))
    manifest = json.loads((case / "acquisition-manifest.json").read_text())
    copied = case / manifest["files"][0]["case_path"]
    copied.write_bytes(b"deliberately tampered synthetic evidence")
    failed = subprocess.run(command + ["--verify-case", str(case)], capture_output=True)
    assert failed.returncode == 1, "Tampered capture was not rejected"
    failed_package=subprocess.run(command+['--verify-package',str(case)],capture_output=True)
    assert failed_package.returncode==1, 'Tampered package was not rejected' 
    incomplete = subprocess.run(command + ["--extra-path", str(root / "missing"),
        "--acquire", "--strict", "--output", str(root / "partial")], capture_output=True)
    assert incomplete.returncode == 3, "Incomplete case did not return strict exit 3"
    run('--compare', str(root / 'json'), str(root / 'both'), '--output', str(root / 'comparison'))
    comparison = json.loads((root / 'comparison/comparison.json').read_text())
    assert comparison['summary'] == {'unchanged': 1}
    expected = root / 'expected.json'
    expected.write_text(json.dumps({'schema_version': 1, 'scope': {'runner': 'ollama', 'artifact_type': 'cli_history', 'record_kind': 'current'}, 'records': [{'text': 'SYNTHETIC_PACKAGED_CLI_CHECK'}]}))
    run('--score-records', str(expected), str(root / 'json'), '--output', str(root / 'score'))
    assert json.loads((root / 'score/accuracy.json').read_text())['exact_match']
    run('--self-test', '--output', str(root / 'self-test'))
    assert json.loads((root / 'self-test/validation-results.json').read_text())['passed']
    assert source.read_bytes() == data
    assert (custom / "history").read_bytes() == data
print("Packaged CLI smoke checks passed: help, version, export modes, capture, custom home, timeline, tamper detection, strict exits, comparison, exact scoring, validation kit and source preservation.")
