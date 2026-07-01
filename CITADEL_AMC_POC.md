# CITADEL-Governed AMC PoC

This PoC demonstrates how a CITADEL gateway can govern an agentic Adverse Media Check pipeline before model access and before high-risk actions execute.

It is designed for direct deployment on a personal Ubuntu VM using Python scripts and a virtual environment. It intentionally avoids Docker, Azure production resources, ADIB tenant resources, and real customer data.

## Implemented Components

| Component | File | Function |
| --- | --- | --- |
| Governed AI Gateway | `app/gateway/middleware.py` | FastAPI proxy with token identity, quota checks, prompt-injection detection, PII masking, correlation IDs, and audit telemetry |
| AGT Policy Engine | `app/policies/agt_engine.py` | Action governance matrix for allowed, denied, and justification-required states |
| Tamper-Evident Audit | `app/audit/hash_logger.py` | SQLite and JSONL append-only audit log with SHA-256 hash chaining |
| Gateway Policy | `config/gateway_policy.yml` | Identity, quota, PII, prompt-injection, model, and audit settings |
| Agent Policy | `config/agent_policy.yml` | AMC action policy matrix |
| End-to-End Runner | `run_amc_poc.py` | Reads synthetic Excel intake, calls the gateway, evaluates AGT actions, and emits PDF reports |
| Synthetic KYC Dossier | `data/sample_kyc_document.md` | Human-readable KYC cases and governance scenario coverage |
| KYC Generator | `scripts/create_sample_kyc_document.py` | Recreates the KYC dossier, structured cases, and coverage report |

## Architecture

```text
data/sample_intake.xlsx
        |
        v
run_amc_poc.py --------------+
        |                    |
        v                    v
FastAPI CITADEL Gateway   AGT Policy Engine
        |                    |
        v                    v
Mock AMC Model           HashChainLogger
        |                    |
        +---------> reports/*.pdf
                     logs/audit_chain.sqlite3
                     logs/audit_chain.jsonl
```

## VM Setup

```bash
cd ~/CITADEL
chmod +x setup_vm.sh
./setup_vm.sh
```

The setup script creates `.venv`, installs dependencies, initializes the audit database, creates `data/sample_intake.xlsx`, and starts the FastAPI gateway on port `8000`.

## Execute The PoC

```bash
source .venv/bin/activate
python run_amc_poc.py --no-autostart-gateway
```

The runner processes exactly three synthetic rows:

- `AMC-001`: Low, clean entity.
- `AMC-002`: Medium, name-match review with logged justification.
- `AMC-003`: High, denied action trigger.

## Generate Synthetic KYC Dossier

```bash
python scripts/create_sample_kyc_document.py --output-dir data
```

Generated files:

```text
data/sample_kyc_document.md
data/sample_kyc_cases.json
data/kyc_scenario_coverage.json
```

The coverage report confirms these scenarios are represented:

- Low clean KYC pass.
- Medium name-match review with `override_match` justification.
- High denied `search_unapproved_source`.
- Denied `delete_evidence`.
- PII masking for synthetic email, phone, Emirates ID, and IBAN-like values.
- Prompt-injection blocking.
- Invalid token rejection.
- Correlation telemetry.
- Tamper-evident audit verification.
## Verify Tamper Evidence

```bash
python -m app.audit.hash_logger verify --db logs/audit_chain.sqlite3 --jsonl logs/audit_chain.jsonl
```

Expected result:

```json
{
  "valid": true
}
```

Each event hash is recomputed from canonical JSON and checked against the previous event hash. SQLite and JSONL records are also compared ordinally.

## View Recent Audit Events

```bash
python -m app.audit.hash_logger tail --db logs/audit_chain.sqlite3 --jsonl logs/audit_chain.jsonl --limit 10
```

Optional SQLite inspection:

```bash
sqlite3 logs/audit_chain.sqlite3 "select id,event_type,actor,substr(previous_hash,1,16),substr(event_hash,1,16) from audit_events order by id;"
```

## Generated Reports

After a successful run:

```text
reports/AMC-001_amc_report.pdf
reports/AMC-002_amc_report.pdf
reports/AMC-003_amc_report.pdf
reports/run_summary.json
```

The PDFs use a fixed report timestamp and ReportLab invariant output mode for deterministic document generation.
