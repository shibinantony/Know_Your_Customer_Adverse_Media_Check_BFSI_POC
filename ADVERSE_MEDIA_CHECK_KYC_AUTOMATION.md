# Adverse Media Check KYC Automation

Consolidated on: 2026-07-01

## Executive Summary

This project is a local proof of concept for a governed Adverse Media Check (AMC) automation flow in a KYC context. The current version proves the hypothesis that an agentic screening workflow can be wrapped with policy controls before model access, during action execution, and after report generation.

The PoC is intentionally synthetic. It uses no real customer data, no production bank data, no Azure tenant dependency, no ADIB tenant dependency, and no Docker dependency. The implementation is designed to run directly on a personal VM with Python.

The demonstrated flow is:

```text
Synthetic KYC intake
    -> AMC agent runner
    -> CITADEL governed AI gateway
    -> Mock adverse-media model
    -> AGT-style action policy engine
    -> Tamper-evident audit log
    -> Deterministic PDF screening reports
```

## What The Hypothesis Tests

The starting hypothesis was that AMC automation for KYC needs more than a model call. A useful solution must control what the agent can send to the model, which evidence paths it can use, which high-risk actions require human rationale, which actions are prohibited, and whether the resulting activity can be audited.

This PoC validates that hypothesis through a small governed pipeline:

- A gateway authenticates the AMC agent before model access.
- The gateway blocks prompt-injection patterns before forwarding requests.
- The gateway masks synthetic PII before forwarding payloads to the model.
- An AGT-style policy engine evaluates the agent's proposed actions.
- Justification-required actions are allowed only when rationale is present.
- Denied actions stop the workflow.
- Every gateway and policy event is written to a hash-chained audit trail.
- A report is generated for each KYC entity, including governed blocked outcomes.

## Implemented Architecture

| Layer | File | Role |
| --- | --- | --- |
| Synthetic intake | `data/sample_intake.xlsx` | Three synthetic entities representing low, medium, and high-risk AMC outcomes |
| KYC dossier | `data/sample_kyc_document.md` | Human-readable synthetic KYC cases and scenario coverage |
| AMC orchestrator | `run_amc_poc.py` | Reads intake, calls gateway, applies action policy, writes PDF reports |
| Governed AI gateway | `app/gateway/middleware.py` | FastAPI proxy for authentication, quota, scanning, masking, correlation, and telemetry |
| Mock AMC model | `app/gateway/middleware.py` | Deterministic local model provider for low, medium, and high-risk results |
| AGT policy engine | `app/policies/agt_engine.py` | Action governance matrix for allow, deny, and justification-required decisions |
| Gateway policy | `config/gateway_policy.yml` | Token, quota, PII, prompt-injection, model, and audit settings |
| Agent policy | `config/agent_policy.yml` | AMC action allow/deny/justification rules |
| Audit logger | `app/audit/hash_logger.py` | SQLite and JSONL append-only audit logs with SHA-256 hash chaining |
| Generated reports | `reports/*.pdf` and `reports/run_summary.json` | Deterministic evidence outputs for the three synthetic entities |

## End-To-End Flow

1. The runner loads exactly three synthetic KYC rows from `data/sample_intake.xlsx`.
2. For each row, it sends a screening request to the CITADEL gateway with a correlation ID.
3. The gateway authenticates the bearer token from `config/gateway_policy.yml`.
4. The gateway checks request quota limits.
5. The gateway scans payload text for prompt-injection patterns.
6. The gateway masks configured PII patterns before model forwarding.
7. The mock AMC model returns a deterministic risk result and recommended action sequence.
8. The AGT policy engine evaluates each proposed action from the intake.
9. The runner stops if a required justification is missing or a denied action is reached.
10. A deterministic PDF report and JSON run summary are written to `reports/`.
11. Gateway, orchestrator, and AGT events are logged to SQLite and JSONL with linked hashes.

## Governance Controls

### Gateway Controls

The gateway is the pre-model control point. It currently implements:

- Bearer-token authentication using SHA-256 token hashes.
- Per-token request quota checks.
- Maximum request body size.
- Prompt-injection detection using configurable regular expressions.
- PII masking for email, UAE Emirates ID, IBAN-like values, and phone numbers.
- Correlation ID injection and propagation through `x-correlation-id`.
- Structured audit events for authentication failures, quota rejections, prompt-injection blocks, model errors, and successful requests.

### Agent Action Controls

The AGT policy engine is the agent-action control point. The current policy is default-deny and explicitly defines these actions:

| Action | Effect | Meaning |
| --- | --- | --- |
| `screen_entity` | Allow | Baseline entity screening is permitted |
| `search_approved_source` | Allow | Evidence lookup is limited to approved synthetic sources |
| `generate_report` | Allow | Deterministic report generation is permitted |
| `assign_high_risk` | Justification required | High-risk assignment must include analyst rationale |
| `override_match` | Justification required | Possible name-match override must include analyst rationale |
| `search_unapproved_source` | Deny | Source is outside the approved evidence boundary |
| `delete_evidence` | Deny | Evidence deletion is prohibited |

### Audit Controls

The audit layer is designed to show tamper evidence, not only logging. Each event includes:

- Timestamp.
- Actor.
- Correlation ID.
- Event type.
- Structured details.
- Previous event hash.
- Current event hash.

The audit logger writes the same event stream to SQLite and JSONL. Verification recomputes every hash, checks chain continuity, checks duplicate hashes, and compares SQLite records with JSONL records by ordinal position.

The current audit verification result is valid:

```json
{
  "valid": true,
  "db_event_count": 18,
  "jsonl_event_count": 18,
  "issues": []
}
```

## Synthetic KYC And AMC Cases

| Entity | Persona | Expected AMC Outcome | Current Result |
| --- | --- | --- | --- |
| `AMC-001` | Low | Clean KYC pass with allowed actions only | Completed |
| `AMC-002` | Medium | Near-name match requires analyst rationale | Completed after `override_match` justification |
| `AMC-003` | High | Denied source and evidence-deletion path must be blocked | Blocked by policy at `search_unapproved_source` |

### AMC-001: Low Clean Pass

`AMC-001` represents a clean synthetic onboarding case. The mock model returns a low risk score of `8`, no adverse-media indicators, and approved evidence labels. The action sequence is:

```text
screen_entity -> search_approved_source -> generate_report
```

All actions are allowed and the final status is `completed`.

### AMC-002: Medium Name-Match Review

`AMC-002` represents a synthetic near-name adverse-media match. The mock model returns a medium risk score of `61` and sends the case to analyst review. The action sequence is:

```text
screen_entity -> search_approved_source -> override_match -> generate_report
```

The `override_match` action is not simply allowed. It is recorded as `justification_required`, and the provided analyst rationale is logged before the report is generated. The final status is `completed`.

### AMC-003: High Denied Action Path

`AMC-003` represents a high-risk synthetic trigger. The mock model returns a high risk score of `92` and recommends a path that includes an unapproved source and evidence deletion. The action sequence is:

```text
screen_entity -> search_unapproved_source -> delete_evidence -> generate_report
```

The policy engine blocks the flow at `search_unapproved_source`. Because the first denied action stops evaluation, `delete_evidence` is represented in the scenario design but is not executed in the runtime decision list. A governed PDF report is still emitted with the blocked outcome. The final status is `blocked_by_policy`.

## Scenario Coverage

The generated KYC dossier reports complete coverage for the synthetic control scenarios:

| Scenario | Coverage |
| --- | --- |
| Low clean KYC pass | Covered |
| Medium name-match review | Covered |
| High denied source trigger | Covered |
| Denied evidence deletion | Covered in scenario design |
| Allowed entity screening | Covered |
| Approved-source search | Covered |
| Report generation | Covered |
| Match override justification | Covered |
| Policy denial | Covered |
| PII masking | Covered |
| Prompt-injection blocking | Covered |
| Invalid token rejection | Covered |
| Correlation telemetry | Covered |
| Audit hash-chain verification | Covered |

The coverage file reports `14` required scenarios, `14` covered scenarios, and no missing scenarios.

## Generated Evidence

The current generated evidence set is:

| Output | Purpose |
| --- | --- |
| `reports/AMC-001_amc_report.pdf` | Low-risk completed AMC report |
| `reports/AMC-002_amc_report.pdf` | Medium-risk completed report with justification-required action |
| `reports/AMC-003_amc_report.pdf` | High-risk blocked-by-policy report |
| `reports/run_summary.json` | Machine-readable summary of model results, decisions, statuses, and report paths |
| `logs/audit_chain.sqlite3` | Structured audit event store |
| `logs/audit_chain.jsonl` | Append-only JSONL audit mirror |

## How To Run The PoC

From an Ubuntu VM:

```bash
cd ~/CITADEL
chmod +x setup_vm.sh
./setup_vm.sh
source .venv/bin/activate
python run_amc_poc.py --no-autostart-gateway
python -m app.audit.hash_logger verify --db logs/audit_chain.sqlite3 --jsonl logs/audit_chain.jsonl
```

To regenerate the synthetic KYC dossier:

```bash
python scripts/create_sample_kyc_document.py --output-dir data
```

To regenerate the synthetic intake:

```bash
python scripts/create_sample_intake.py --output data/sample_intake.xlsx
```

## Current Boundary Of The PoC

This is a hypothesis-stage implementation with deterministic synthetic behavior. The current version does not yet provide:

- Real adverse-media source connectors.
- Real sanctions, PEP, law-enforcement, litigation, or negative-news data feeds.
- Entity resolution beyond synthetic personas.
- Fuzzy matching or transliteration handling.
- Human analyst UI for review, approval, and escalation.
- Role-based access control for analysts, compliance managers, or auditors.
- Production secrets management.
- Production-grade deployment hardening.
- Formal test suite around every negative control.
- Case management integration.
- Model evaluation against real labeled AMC outcomes.

## Recommended Next Steps

1. Add formal automated tests for gateway authentication, prompt-injection blocking, PII masking, quota rejection, AGT denials, justification-required actions, and audit verification.
2. Add explicit runtime tests for `delete_evidence` denial rather than only representing it in the high-risk scenario design.
3. Add a small analyst-review artifact for `AMC-002`, such as an approval note or review disposition.
4. Add a source adapter interface so approved and unapproved source behavior can be tested without changing the orchestrator.
5. Add entity-resolution and name-screening logic for spelling variants, aliases, Arabic/English transliteration, and near-name matching.
6. Add a case lifecycle model: created, screened, review_required, escalated, cleared, rejected, and archived.
7. Add a production architecture section for identity, secrets, model routing, evidence storage, retention, and audit export.
8. Decide whether generated artifacts such as PDFs, SQLite logs, and JSONL logs should be committed to GitHub or regenerated locally.

## GitHub Readiness Notes

Before pushing this repository publicly, review whether generated logs and reports should be included. They are synthetic, but generated audit databases and PDFs can still create unnecessary repository noise. A clean GitHub version would usually include:

- Source code.
- Config templates.
- Synthetic generators.
- Synthetic markdown and JSON sample cases.
- README and this consolidated document.

It would usually exclude:

- `.venv/`.
- `__pycache__/`.
- Runtime logs.
- SQLite WAL/SHM files.
- Generated PDFs, unless they are intentionally kept as demo evidence.

## Bottom Line

The current work is a credible local AMC/KYC automation hypothesis. It demonstrates the most important governance idea: the agent does not get unrestricted access to the model or unrestricted authority to act. The gateway controls model access and sensitive data exposure, the AGT policy engine controls action execution, and the audit chain gives evidence that the governed path was followed.
