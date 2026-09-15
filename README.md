# Cyber-Bench V3 diverse pass@3 = 0 sample

This package contains five tasks for breadth of
security capability and clean calibration outcomes. It includes the complete task
packages, complete recorded artifact groups, and a five-task detailed report.

## Selected tasks

| Task | Capability area | Mode | Recorded Gemini 3.1 Pro result |
| --- | --- | --- | --- |
| `agent_memory_toolchain_integrity` | Agent memory provenance and tool-boundary containment | Defensive | 0/3; no trial exceptions |
| `cryptographic_agility_pqc_migration` | Cryptographic agility and post-quantum migration | Defensive | 0/3; no trial exceptions |
| `malware_reverse_engineering_detection` | Malware reverse engineering plus YARA/Sigma detection | Defensive | 0/3; no trial exceptions |
| `runtime_virtual_patch_waf` | Application runtime defense and evasion-resistant WAF policy | Defensive | 0/3; no trial exceptions |
| `multi_artifact_forensic_eradication` | Multi-host forensics, eradication, and trust recovery | Defensive | 0/3; no trial exceptions |

## Artifacts note

The recorded result is from the Phase 3 Gemini 3.1 Pro evaluation. Each selected
task had three completed attempts, zero accepted solves, and no recorded trial
exception. Every selected artifact group also has one task checksum and one lock
digest across its three trials. The source task packages include deterministic
verifier entrypoints and oracle/reference solutions.

The selection was also checked for the required Harbor package files, explicit
`task.mode = "defensive"`, shell and Python syntax, Docker Compose validity, and
absence of defensive-task flag grading conventions.

## Bundle layout

- `tasks/`: exact copies of the five task packages from `tasksets/v3/tasks`.
- `artifacts/`: complete aggregate and trial-level Harbor artifacts for the five tasks.
- [`report/PilotCrew_CyberBench_Five_Task_Detailed_Report.pdf`](report/PilotCrew_CyberBench_Five_Task_Detailed_Report.pdf): rendered 13-page detailed report.
- [`report/PilotCrew_CyberBench_Five_Task_Detailed_Report.md`](report/PilotCrew_CyberBench_Five_Task_Detailed_Report.md): text version of the detailed report.

## Running the tasks

Run these commands from the repository root. Docker must be available, and
Harbor must be installed in the active environment.

Validate one task with its deterministic oracle and a fresh environment build:

```bash
harbor run \
  --path tasks/runtime_virtual_patch_waf \
  --agent oracle \
  --force-build \
  --jobs-dir jobs/v3-diverse-pass3-zero-sample/oracle-single \
  --yes
```

Validate all five tasks with their deterministic oracles:

```bash
harbor run \
  --path tasks \
  --agent oracle \
  --force-build \
  --n-concurrent 2 \
  --jobs-dir jobs/v3-diverse-pass3-zero-sample/oracle-all \
  --yes
```

To run a model against one task, select the model explicitly. Cyber-Bench uses
OpenRouter credentials from the repository `.env`; do not print or copy that
file. Use a cheap calibration model unless a costlier model run has been
approved.

```bash
harbor run \
  --path tasks/runtime_virtual_patch_waf \
  --agent terminus-2 \
  --model openrouter/<provider>/<model> \
  --env-file .env \
  --n-attempts 3 \
  --n-concurrent 1 \
  --force-build \
  --jobs-dir jobs/v3-diverse-pass3-zero-sample/model-run \
  --yes
```

Replace `runtime_virtual_patch_waf` with any directory name in `tasks/` to run
a different task. Harbor writes the aggregate `result.json` and the individual
trial directories beneath the selected `--jobs-dir`; verifier details inside
each trial are authoritative for solved status.
