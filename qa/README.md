# Autonomous macOS QA

One full automated run:

```sh
python3 qa/run.py --allow-missing-external
```

Without `--allow-missing-external`, exit 2 means automated checks passed but mandatory external acceptance is missing. Exit 1 means failed, blocked or partial automation. Exit 0 with the flag means only the automated gate passed; read `deployment_ready` and `production_ready` separately.

Use Python 3.13+ on macOS ARM64 with Git. The native builder uses `.venv-build/bin/python` when available, otherwise the current Python; override with `--build-python`. Install the pinned build-requirements in a development environment, not the product. The QA scripts themselves use the standard library.

The runner snapshots an explicit allowlist of source, tests, top-level documents and validation scripts into a private Git repository and a fresh qa/* worktree. Cases, binaries, model downloads and historical captured data are excluded. It builds a new candidate there and tests fresh extractions. It does not overwrite the current product build, modify original evidence, merge or publish. No OpenAI API key is needed: the daily Codex automation is the reasoning/repair agent, while this script is the deterministic executor.

`qa/runs/<unique-id>/` contains report.json, READINESS.md, source-manifest.json, per-test unit JSON, menu-coverage.json, logs, synthetic results, archive identity and packaged menu results. The candidate archive remains in its reported worktree. `qa/state/repairs` records repair reservations and outcomes. Read AGENT.md for the bounded diagnose–fix–retest procedure. Existing run files are never reused.

Actual native GUI acceptance, real-runner conversation tests and independent physical-Mac deployment are explicitly NOT TESTED by default and block deployment readiness. Mocked file pickers and PTYs cannot satisfy them. Historical manual evidence does not automatically carry over to a new source/package. A future witnessed acceptance record must be reviewed separately; this initial executor deliberately does not offer a switch that marks these gates passed.

The workflow under `.github/workflows/` runs on push, pull request, manual dispatch and daily on an ARM64 macOS runner, with an architecture assertion and read-only repository permissions. It uploads QA results only, not candidate binaries or evidence. It performs no AI repairs, merges or publication. Until the project is in a GitHub repository and the workflow runs there, CI is configured but not validated remotely.

Source references: [Codex scheduled tasks](https://learn.chatgpt.com/docs/automations?surface=app) and [GitHub runner labels](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/choose-the-runner-for-a-job). Local scheduled work requires the desktop environment to be available; scheduling is not an always-on hosted service guarantee.

Each execution is bounded to 30 minutes, and individual stages have shorter timeouts. When process enumeration is blocked, timeout cleanup is limited to the spawned process group; the failed attempt records that limitation and must not be treated as a pass. The scheduled agent has a 60-minute visit cap and a persistent three-attempt repair budget.
