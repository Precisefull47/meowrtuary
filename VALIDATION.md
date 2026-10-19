# Verification scope — 1.5.0

Release validation uses the complete isolated QA workflow, a fresh native-package
extraction, controlled runner artifacts and browser report acceptance. The automated
workflow records commands, environment, per-check results and hashes in local JSON
reports. Private evidence, personal paths and native desktop screenshots are not
published with the product.

The 19 October 2026 local run passed all 21 automated stages. External gates
remain separate. Final artifact-specific results accompany the GitHub release.

## Acceptance matrix

| Area | Evidence and scope |
| --- | --- |
| Product unit tests | PASS: 273 tests on 1.5.0 release source |
| QA unit tests | PASS: 13 QA tests on 1.5.0 release source |
| CLI integration | Actual native/portable PTYs: seven operations, arrows/numbers, text, explicit confirmation, Back/Cancel/Quit, resize, interruptions and terminal restoration |
| Forensic integrity | Controlled fixtures, acquisition hashes, source preservation, tamper detection, sealed case verification and packaging |
| Reports | Browser acceptance of large and empty reports, search, provenance, narrow layouts, selected-section printing and cancellation in Google Chrome 155.0.8059.82 |
| Native file pickers | Simulated adapters tested; actual native Terminal/file-picker acceptance blocked by computer-use access restrictions |
| Real runners | Controlled observations listed below; not generalized to every release or mode |
| Extracted executable | Fresh extraction, manifest/link verification, version, doctor, self-test and packaged workflows |
| Independent Mac | NOT TESTED on a second physical Mac |
| Code signing | No Developer ID signature or notarization |

The published release record supplies final archive identity and executed automation
results. The automated suite does not silently waive missing external acceptance.
A release version is not a claim that every mandatory deployment gate passed.

## Controlled real-runner observations

Host: macOS 27.0.1 (26A434), ARM64. Build interpreter: Python 3.14.7.
Common model: Smollm2 135M GGUF, SHA-256
`f535f83ec568d040f88ddc04a199fa6da90923bbb41d4dcaed02caa924d6ef57`.
Experiments used isolated profiles, known prompts, retained original artifacts and
separate output cases. Recovery was compared with known content and source hashes.

| Runner | Observed recovery | Limit |
| --- | --- | --- |
| Ollama 0.34.0 | Known CLI prompt recovered exactly from retained history | CLI reply unavailable; HTTP API prompt/reply unavailable in this experiment |
| LM Studio 0.4.25+1, llama.cpp runtime 2.47.0 | Known saved GUI prompt and reply recovered exactly | Applies to the tested saved JSON format/profile |
| llama.cpp 0.5.0-dev, build 11146, commit 7fe450e19 | Prompt/continuation from recognized log; conditional cache decoding with matching GGUF | Raw text/token evidence does not authenticate roles or timestamps |

Reanalysis of preserved controlled artifacts tests parser behavior against real
runner output. It is distinct from creating a new conversation on each build.
Historical candidate browser and runner records remain separate from release-package
checks; executable version, hashes and rerun results identify the final artifact.

## Reproduce

Read qa/README.md and run `python3 qa/run.py --allow-missing-external` on macOS ARM64.
The flag permits an automated-only success exit; it does not certify external gates.
Reports are stored under qa/runs and packages under the reported isolated worktree.
Do not test destructively against original evidence or overwrite validated archives.
