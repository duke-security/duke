# Reproducible T1110 End-to-End Demonstration

This document walks through Duke's **T1110 — Brute Force (Password
Spraying)** scenario end to end: simulate the observable telemetry, detect
it as a behaviour-based finding, investigate it as evidence, plan a
dry-run response, validate the detection pipeline, write the advisory
incident report, and render the guided learning path.

All commands run from the **repository root** (the directory that contains
`README.md` and `.gitignore`). No machine-specific paths are used; every
output goes to the gitignored `data/events/` and `reports/` directories, so
running this demonstration creates **no tracked files** and requires
**no credentials, network service, or external provider**.

## 0. Environment

- Python 3.11 or later, with the package installed in editable mode (see
  [docs/development/environment-setup.md](../development/environment-setup.md)).
- Confirm Duke is available:

```bash
python -m duke.cli.app version
```

Expected output (`exit 0`):

```
Duke version 0.1.0
```

## Caveats before you start

- A **finding is an analytic signal, not proof of compromise.** Detection
  infers a behaviour pattern from the *observable* shape of authentication
  outcomes; it never labels an account as compromised or an actor as an
  attacker.
- **Response actions are proposed only.** Every action is dry-run, requires
  approval, and is `status=PLANNED`. Nothing is ever executed by these
  commands.

## 1. `scenarios` — what is registered

```bash
python -m duke.cli.app scenarios
```

Expected output (`exit 0`): exactly two production scenarios, each with all
seven capabilities.

```
Registered scenarios
- T1078 — Valid Accounts: Compromised Identity
    Slug: t1078_valid_accounts
    Capabilities: simulation, detection, investigation, response, validation, reporting, learning
    Aliases: valid-accounts
- T1110 — Brute Force: Password Spraying
    Slug: t1110_brute_force
    Capabilities: simulation, detection, investigation, response, validation, reporting, learning
    Aliases: brute-force, T1110.003
```

This command **prints** a listing; it writes nothing and never runs a
capability.

## 2. `simulate` — generate the observable telemetry (**writes an artefact**)

```bash
python -m duke.cli.app simulate T1110 --output data/events/t1110-demo.json
```

Expected output (`exit 0`):

```
Simulation complete
Scenario: Brute Force: Password Spraying
Technique: T1110
Entities generated: 10
Events generated: 8
Saved: data/events/t1110-demo.json
```

This is the **only** stage that writes a file in this walkthrough's
analysis commands: the normalized JSON artefact at `data/events/t1110-demo.json`.
The 8 events model one benign baseline authentication, six evenly-spaced
failed authentications against six distinct accounts from a single external
source, and one later successful authentication to a previously targeted
account — with no credential material and no real authentication.

## 3. `detect` — produce a behaviour-based finding (**prints only**)

```bash
python -m duke.cli.app detect T1110 --input data/events/t1110-demo.json
```

Expected output (`exit 0`):

```
Detection complete
Events analysed: 8
Findings: 1
- Password spray against multiple distinct accounts
    Detection: password-spraying-window
    Technique: T1110
    Severity: high
    Confidence: 80/100
    Supporting events: 7
```

The detector groups events by source actor, evaluates a sliding 30-minute
window, and requires at least five distinct accounts failed from one source.
The later success is credited only as supporting evidence. This command
**prints** the finding and writes nothing.

## 4. `investigate` — evidence-led investigation (**prints only**)

```bash
python -m duke.cli.app investigate T1110 --input data/events/t1110-demo.json
```

Expected output (`exit 0`) includes:

```
Investigation complete
Finding: Password spray against multiple distinct accounts
Technique: T1110
Severity: high
Confidence: 80/100
Involved entities: 7
Evidence items: 7
...
Confirmed facts:
Analyst assessments:
Unresolved questions:
```

Investigation produces **7 evidence items** from the finding's referenced
events, a chronological **timeline**, the involved entities, and cautious
confirmed facts, analyst assessments, and unresolved questions. It never
claims compromise or attribution. This command **prints** the analysis and
writes nothing.

## 5. `respond` — dry-run response planning (**prints only**)

```bash
python -m duke.cli.app respond T1110 --input data/events/t1110-demo.json
```

Expected output (`exit 0`) begins:

```
Response plan complete (DRY RUN — nothing executed)
Incident: Preliminary T1110 password-spraying response (status: open, severity: high)
Finding: Password spray against multiple distinct accounts
Actions proposed: 9 — all dry-run, all require approval
```

The response plan correlates the finding into a preliminary incident and
proposes **9 dry-run, approval-gated actions** grouped by category
(containment, evidence preservation, investigation follow-up, recovery).
**Nothing is executed**; this command **prints** the plan and writes
nothing.

## 6. `validate` — deterministic detection validation (**prints only**)

```bash
python -m duke.cli.app validate T1110 --input data/events/t1110-demo.json
```

Expected output (`exit 0`):

```
Validation complete: 19/19 cases passed
```

Validation reruns the detection → investigation → response pipeline over a
fixed ordered catalogue of **19 in-memory mutations** of the artefact (the
source artefact file is never modified), reporting pass/fail per case and a
final `19/19 cases passed`. This command **prints** the suite and writes
nothing.

## 7. `report` — advisory incident report (**writes an artefact**)

```bash
python -m duke.cli.app report T1110 \
  --input data/events/t1110-demo.json \
  --output reports/t1110-demo.md
```

Expected output (`exit 0`):

```
Report complete
Report ID: <uuid>
Validation: 19/19 cases passed
Saved: reports/t1110-demo.md
```

`duke report` loads the artefact and orchestrates **detection, validation,
investigation, and response for exactly one finding**, then renders a
deterministic advisory report with **12 sections** (report identification,
executive summary, scope and methodology, finding, involved entities,
chronological timeline, evidence register, analysis, recommended response,
validation summary, limitations, conclusion) and writes it to
`reports/t1110-demo.md`. Re-running with `--force` reproduces byte-identical
output.

## 8. `learn` — guided learning (**prints only**)

```bash
python -m duke.cli.app learn T1110
python -m duke.cli.app learn T1110 --step detection
```

Expected output (`exit 0`): an overview of the **11-step** deterministic
learning path, or (with `--step detection`) Step 6 "Detection reasoning"
(step IDs are the registered learning-step IDs). Learning renders static
metadata only; it never executes, grades, or persists progress.

## Expected exit codes

| Command | Exit code | Writes a file? |
|---|---|---|
| `scenarios` | 0 | no |
| `simulate T1110 ...` | 0 | yes — `data/events/t1110-demo.json` |
| `detect T1110 ...` | 0 | no |
| `investigate T1110 ...` | 0 | no |
| `respond T1110 ...` | 0 | no |
| `validate T1110 ...` | 0 | no |
| `report T1110 ...` | 0 | yes — `reports/t1110-demo.md` |
| `learn T1110` / `--step` | 0 | no |

Commands that **print analysis** (`detect`, `investigate`, `respond`,
`validate`, `learn`, `scenarios`) write nothing. Commands that **write
artefacts** are `simulate` (JSON telemetry) and `report` (Markdown).
An unknown technique or a missing capability exits with code **2**; a
missing or malformed input artefact, or an `--output` file that already
exists without `--force`, exits with code **1**.

## Verified values (T1110 canonical corpus)

- entities: **10** · events: **8**
- findings: **1** (severity **HIGH**, confidence **80**)
- supporting events: **7** · evidence items: **7**
- planned dry-run response actions: **9**
- validation cases: **19** (19/19 passed)
- report sections: **12** · learning steps: **11**

### About the severity casing

Duke's severity value is the enum member **`HIGH`** (semantic severity).
The CLI renders it through the enum's string value, so the terminal prints
it in **lowercase `high`** (for example `Severity: high`). Both refer to the
same value; `high` is simply how the `HIGH` member displays in CLI output.

## Cleanup

The demonstration creates two disposable files, both gitignored:

```bash
rm -f data/events/t1110-demo.json reports/t1110-demo.md
```

This removes only the demonstration output; it never touches source files,
tests, or tracked documentation. You can also simply leave them in place —
neither `data/events/` nor `reports/` is tracked by git.
