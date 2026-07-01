from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import Any

import httpx
import pandas as pd
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from app.audit.hash_logger import HashChainLogger
from app.policies.agt_engine import AGTPolicyEngine, JustificationRequired, PolicyDenied
from scripts.create_sample_intake import create_sample_intake


ROOT = Path(__file__).resolve().parent
DATA_PATH = ROOT / "data" / "sample_intake.xlsx"
KYC_DOCUMENT_PATH = ROOT / "data" / "sample_kyc_document.md"
REPORTS_DIR = ROOT / "reports"
LOGS_DIR = ROOT / "logs"
GATEWAY_POLICY = ROOT / "config" / "gateway_policy.yml"
AGENT_POLICY = ROOT / "config" / "agent_policy.yml"
AUDIT_DB = LOGS_DIR / "audit_chain.sqlite3"
AUDIT_JSONL = LOGS_DIR / "audit_chain.jsonl"
GATEWAY_URL = os.environ.get("CITADEL_GATEWAY_URL", "http://127.0.0.1:8000")
GATEWAY_TOKEN = os.environ.get("CITADEL_GATEWAY_TOKEN", "citadel-agent-dev-token")
REPORT_DATE = "2026-06-29T00:00:00Z"


def gateway_healthcheck(base_url: str) -> bool:
    try:
        response = httpx.get(f"{base_url}/health", timeout=2.0)
        return response.status_code == 200 and response.json().get("status") == "ok"
    except Exception:
        return False


def start_gateway_if_needed(base_url: str) -> subprocess.Popen[str] | None:
    if gateway_healthcheck(base_url):
        return None

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    log_handle = (LOGS_DIR / "gateway_autostart.out").open("a", encoding="utf-8")
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "app.gateway.middleware",
            "--config",
            str(GATEWAY_POLICY),
            "--host",
            "127.0.0.1",
            "--port",
            "8000",
        ],
        cwd=str(ROOT),
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        text=True,
    )

    for _ in range(30):
        if gateway_healthcheck(base_url):
            return process
        if process.poll() is not None:
            raise RuntimeError(f"gateway exited early with code {process.returncode}")
        time.sleep(0.25)
    process.terminate()
    raise RuntimeError("gateway did not become healthy within 7.5 seconds")


def stop_autostarted_gateway(process: subprocess.Popen[str] | None) -> None:
    if process is None:
        return
    if process.poll() is not None:
        return
    if os.name == "nt":
        process.terminate()
    else:
        process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()


def ensure_inputs() -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if not DATA_PATH.exists():
        create_sample_intake(DATA_PATH)
    HashChainLogger(AUDIT_DB, AUDIT_JSONL).initialize()


def read_intake() -> pd.DataFrame:
    frame = pd.read_excel(DATA_PATH, engine="openpyxl", dtype=str).fillna("")
    required = {
        "entity_id",
        "entity_name",
        "risk_persona",
        "source_request",
        "action_sequence",
        "justification",
        "synthetic_email",
        "synthetic_phone",
        "synthetic_emirates_id",
        "notes",
    }
    missing = sorted(required - set(frame.columns))
    if missing:
        raise ValueError(f"sample intake missing required columns: {missing}")
    if len(frame.index) != 3:
        raise ValueError(f"sample intake must contain exactly 3 synthetic rows; found {len(frame.index)}")
    return frame


def call_gateway(row: dict[str, str], correlation_id: str) -> dict[str, Any]:
    entity_name = row["entity_name"]
    payload = {
        "entity_id": row["entity_id"],
        "entity_name": entity_name,
        "risk_hint": row["risk_persona"],
        "source_request": row["source_request"],
        "prompt": (
            "Screen this synthetic AMC entity using approved local demo evidence only. "
            f"Entity={entity_name}; contact={row['synthetic_email']}; "
            f"phone={row['synthetic_phone']}; emirates_id={row['synthetic_emirates_id']}."
        ),
        "messages": [
            {
                "role": "system",
                "content": "You are a local synthetic AMC screening model behind the CITADEL governed gateway.",
            },
            {
                "role": "user",
                "content": f"Return a concise risk assessment for {entity_name}.",
            },
        ],
        "metadata": {
            "pipeline": "citadel_amc_poc",
            "risk_persona": row["risk_persona"],
            "notes": row["notes"],
        },
    }
    headers = {
        "authorization": f"Bearer {GATEWAY_TOKEN}",
        "content-type": "application/json",
        "x-correlation-id": correlation_id,
    }
    with httpx.Client(timeout=10.0) as client:
        response = client.post(f"{GATEWAY_URL}/v1/chat/completions", json=payload, headers=headers)
    try:
        body = response.json()
    except Exception:
        body = {"raw_body": response.text}
    if response.status_code != 200:
        raise RuntimeError(f"gateway rejected request for {row['entity_id']}: {response.status_code} {body}")
    return body


def evaluate_actions(
    row: dict[str, str],
    screening: dict[str, Any],
    engine: AGTPolicyEngine,
    correlation_id: str,
) -> tuple[list[dict[str, Any]], str, str]:
    decisions: list[dict[str, Any]] = []
    final_status = "completed"
    denial_reason = ""

    for action in [item.strip() for item in row["action_sequence"].split(";") if item.strip()]:
        try:
            decision = engine.evaluate_action(
                action,
                actor="amc_agent",
                correlation_id=correlation_id,
                entity_id=row["entity_id"],
                justification=row["justification"] if action in {"assign_high_risk", "override_match"} else None,
                metadata={
                    "risk_persona": row["risk_persona"],
                    "model_risk_level": screening.get("risk_level"),
                    "model_risk_score": screening.get("risk_score"),
                    "source_request": row["source_request"],
                },
            )
            decisions.append(decision.as_dict())
        except JustificationRequired as exc:
            final_status = "blocked_missing_justification"
            denial_reason = str(exc)
            decisions.append(
                {
                    "action": action,
                    "effect": "justification_missing",
                    "reason": str(exc),
                    "entity_id": row["entity_id"],
                }
            )
            break
        except PolicyDenied as exc:
            final_status = "blocked_by_policy"
            denial_reason = str(exc)
            decisions.append(
                {
                    "action": action,
                    "effect": "deny",
                    "reason": str(exc),
                    "entity_id": row["entity_id"],
                }
            )
            break

    return decisions, final_status, denial_reason


def _draw_wrapped(c: canvas.Canvas, text: str, x: float, y: float, width_chars: int, leading: int = 14) -> float:
    for line in textwrap.wrap(text, width=width_chars) or [""]:
        c.drawString(x, y, line)
        y -= leading
    return y


def write_pdf_report(result: dict[str, Any]) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORTS_DIR / f"{result['entity_id']}_amc_report.pdf"
    c = canvas.Canvas(str(report_path), pagesize=A4, invariant=1)
    width, height = A4
    y = height - 54

    c.setTitle(f"CITADEL AMC Report {result['entity_id']}")
    c.setAuthor("CITADEL AMC PoC")
    c.setFont("Helvetica-Bold", 16)
    c.drawString(54, y, "CITADEL-Governed AMC Screening Report")
    y -= 26
    c.setFont("Helvetica", 9)
    c.drawString(54, y, f"Report timestamp UTC: {REPORT_DATE}")
    y -= 14
    c.drawString(54, y, f"Correlation ID: {result['correlation_id']}")
    y -= 24

    c.setFont("Helvetica-Bold", 12)
    c.drawString(54, y, "Entity")
    y -= 16
    c.setFont("Helvetica", 10)
    for label in ("entity_id", "entity_name", "risk_persona", "source_request"):
        c.drawString(72, y, f"{label}: {result[label]}")
        y -= 14

    y -= 8
    c.setFont("Helvetica-Bold", 12)
    c.drawString(54, y, "Gateway Screening")
    y -= 16
    c.setFont("Helvetica", 10)
    screening = result["screening"]
    c.drawString(72, y, f"risk_level: {screening.get('risk_level')}")
    y -= 14
    c.drawString(72, y, f"risk_score: {screening.get('risk_score')}")
    y -= 14
    y = _draw_wrapped(c, f"summary: {screening.get('summary')}", 72, y, 92)

    y -= 8
    c.setFont("Helvetica-Bold", 12)
    c.drawString(54, y, "AGT Decisions")
    y -= 16
    c.setFont("Helvetica", 10)
    for decision in result["decisions"]:
        y = _draw_wrapped(
            c,
            f"{decision.get('action')}: {decision.get('effect')} - {decision.get('reason')}",
            72,
            y,
            92,
        )
        if y < 90:
            c.showPage()
            c.setFont("Helvetica", 10)
            y = height - 54

    y -= 8
    c.setFont("Helvetica-Bold", 12)
    c.drawString(54, y, "Outcome")
    y -= 16
    c.setFont("Helvetica", 10)
    c.drawString(72, y, f"final_status: {result['final_status']}")
    y -= 14
    if result["denial_reason"]:
        y = _draw_wrapped(c, f"denial_reason: {result['denial_reason']}", 72, y, 92)
    y -= 8
    c.drawString(72, y, f"audit_last_hash: {result['audit_last_hash']}")
    c.save()
    return report_path


def run_flow() -> list[dict[str, Any]]:
    ensure_inputs()
    frame = read_intake()
    audit_logger = HashChainLogger(AUDIT_DB, AUDIT_JSONL)
    engine = AGTPolicyEngine(AGENT_POLICY, audit_logger)
    results: list[dict[str, Any]] = []

    for row_number, row in enumerate(frame.to_dict(orient="records"), start=1):
        correlation_id = f"citadel-amc-{row['entity_id'].lower()}"
        audit_logger.log_event(
            event_type="orchestrator.entity_started",
            actor="run_amc_poc",
            correlation_id=correlation_id,
            details={"entity_id": row["entity_id"], "row_number": row_number},
        )
        gateway_response = call_gateway(row, correlation_id)
        screening = dict(gateway_response["screening"])
        decisions, final_status, denial_reason = evaluate_actions(row, screening, engine, correlation_id)
        verification = audit_logger.verify()
        result = {
            "entity_id": row["entity_id"],
            "entity_name": row["entity_name"],
            "risk_persona": row["risk_persona"],
            "source_request": row["source_request"],
            "correlation_id": correlation_id,
            "screening": screening,
            "decisions": decisions,
            "final_status": final_status,
            "denial_reason": denial_reason,
            "audit_last_hash": verification.last_event_hash,
        }
        report_path = write_pdf_report(result)
        result["report_path"] = str(report_path.relative_to(ROOT))
        audit_logger.log_event(
            event_type="orchestrator.report_generated",
            actor="run_amc_poc",
            correlation_id=correlation_id,
            details={
                "entity_id": row["entity_id"],
                "final_status": final_status,
                "report_path": result["report_path"],
            },
        )
        results.append(result)

    summary_path = REPORTS_DIR / "run_summary.json"
    summary_path.write_text(json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the CITADEL-governed synthetic AMC PoC")
    parser.add_argument("--no-autostart-gateway", action="store_true")
    args = parser.parse_args()

    gateway_process: subprocess.Popen[str] | None = None
    try:
        ensure_inputs()
        if not args.no_autostart_gateway:
            gateway_process = start_gateway_if_needed(GATEWAY_URL)
        elif not gateway_healthcheck(GATEWAY_URL):
            raise RuntimeError(f"gateway is not healthy at {GATEWAY_URL}")

        results = run_flow()
        print(json.dumps({"processed": len(results), "results": results}, indent=2, sort_keys=True))
        verification = HashChainLogger(AUDIT_DB, AUDIT_JSONL).verify()
        print(json.dumps({"audit_verification": verification.as_dict()}, indent=2, sort_keys=True))
        return 0 if verification.valid else 1
    finally:
        stop_autostarted_gateway(gateway_process)


if __name__ == "__main__":
    raise SystemExit(main())
