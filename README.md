# CITADEL-Governed ADIB AMC Starter PoC

This repository is a VM-native proof of concept for the CITADEL gateway pattern around a synthetic Adverse Media Check agentic pipeline.

Flow: `AMC Agent -> Governed AI Gateway (CITADEL) -> Mock AMC Model -> AGT Policy Engine -> Tamper-Evident Audit -> PDF Reports`

The implementation has no Azure tenant dependency, no tenant dependency, no Docker dependency, and no real customer data.

## Quick Start On Ubuntu VM

```bash
cd ~/CITADEL
chmod +x setup_vm.sh
./setup_vm.sh
source .venv/bin/activate
python run_amc_poc.py --no-autostart-gateway
python -m app.audit.hash_logger verify --db logs/audit_chain.sqlite3 --jsonl logs/audit_chain.jsonl
```

Generated outputs:

- `data/sample_intake.xlsx`
- `reports/AMC-001_amc_report.pdf`
- `reports/AMC-002_amc_report.pdf`
- `reports/AMC-003_amc_report.pdf`
- `reports/run_summary.json`
- `logs/audit_chain.sqlite3`
- `logs/audit_chain.jsonl`

## Direct Terminal Commands

Initialize the audit store:

```bash
source .venv/bin/activate
python -m app.audit.hash_logger init --db logs/audit_chain.sqlite3 --jsonl logs/audit_chain.jsonl
```

Start the gateway in the background:

```bash
nohup python -m app.gateway.middleware --config config/gateway_policy.yml > logs/gateway.out 2>&1 &
echo "$!" > logs/gateway.pid
```

Run the synthetic AMC flow:

```bash
python run_amc_poc.py --no-autostart-gateway
```

Verify the tamper-evident hash chain:

```bash
python -m app.audit.hash_logger verify --db logs/audit_chain.sqlite3 --jsonl logs/audit_chain.jsonl
python -m app.audit.hash_logger tail --db logs/audit_chain.sqlite3 --jsonl logs/audit_chain.jsonl --limit 10
```

Inspect the SQLite chain directly:

```bash
sqlite3 logs/audit_chain.sqlite3 "select id,event_type,actor,substr(previous_hash,1,16),substr(event_hash,1,16) from audit_events order by id;"
```

Stop the background gateway:

```bash
kill "$(cat logs/gateway.pid)"
```

## Governance Behavior

Gateway controls in `app/gateway/middleware.py`:

- Bearer-token identity verification using SHA-256 token hashes from `config/gateway_policy.yml`.
- Per-token request quota checks.
- Prompt-injection detection using configured regex patterns.
- PII masking for email, phone, UAE Emirates ID, and IBAN-like strings before model forwarding.
- Correlation ID injection through `x-correlation-id`.
- Structured telemetry written to the tamper-evident audit logger.

AGT controls in `app/policies/agt_engine.py`:

- Allowed actions: `screen_entity`, `search_approved_source`, `generate_report`.
- Justification-required actions: `assign_high_risk`, `override_match`.
- Denied actions: `search_unapproved_source`, `delete_evidence`.

Audit controls in `app/audit/hash_logger.py`:

- Every event is written to SQLite and JSONL.
- Every event includes `previous_hash` and `event_hash`.
- The event hash is computed over canonical JSON containing timestamp, actor, correlation ID, event type, details, and previous hash.
- Verification recomputes every hash and compares the SQLite and JSONL records.

## Synthetic Personas

| Entity ID | Persona | Expected Outcome |
| --- | --- | --- |
| AMC-001 | Low clean persona | Completes with allowed actions only |
| AMC-002 | Medium name match | Completes after logging `override_match` justification |
| AMC-003 | High denied trigger | Blocks at `search_unapproved_source` and still emits a governed report |

## Synthetic KYC Document

Create or refresh the sample KYC dossier:

```bash
python scripts/create_sample_kyc_document.py --output-dir data
```

This creates:

- `data/sample_kyc_document.md`
- `data/sample_kyc_cases.json`
- `data/kyc_scenario_coverage.json`

The KYC dossier covers clean pass, medium name-match justification, high-risk denied source, denied evidence deletion, PII masking, prompt-injection blocking, invalid token rejection, correlation telemetry, and audit hash-chain verification.
## Local Demo Token

The local demo token used by `run_amc_poc.py` is:

```text
citadel-agent-dev-token
```

The gateway stores only its SHA-256 hash in `config/gateway_policy.yml`.
