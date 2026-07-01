from __future__ import annotations

import argparse
import asyncio
import hmac
import json
import os
import re
import time
import uuid
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

import httpx
import uvicorn
import yaml
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.audit.hash_logger import HashChainLogger


@dataclass(frozen=True)
class Principal:
    client_id: str
    actor: str
    token_hash: str
    quota: dict[str, int]


@dataclass(frozen=True)
class ScanResult:
    masked_payload: dict[str, Any]
    pii_findings: list[dict[str, str]]
    prompt_injection_findings: list[dict[str, str]]


class TokenAuthority:
    def __init__(self, tokens: list[dict[str, Any]]) -> None:
        self._principals: dict[str, Principal] = {}
        for token in tokens:
            token_hash = str(token["token_hash"]).lower()
            self._principals[token_hash] = Principal(
                client_id=str(token["client_id"]),
                actor=str(token.get("actor", token["client_id"])),
                token_hash=token_hash,
                quota={
                    "requests_per_minute": int(token.get("quota", {}).get("requests_per_minute", 60)),
                    "requests_per_day": int(token.get("quota", {}).get("requests_per_day", 1000)),
                },
            )

    def authenticate(self, authorization: str | None) -> Principal:
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise PermissionError("missing bearer token")

        token_hash = sha256(token.encode("utf-8")).hexdigest().lower()
        for configured_hash, principal in self._principals.items():
            if hmac.compare_digest(token_hash, configured_hash):
                return principal
        raise PermissionError("invalid bearer token")


class QuotaManager:
    def __init__(self) -> None:
        self._minute_windows: dict[str, tuple[int, int]] = {}
        self._day_windows: dict[str, tuple[str, int]] = {}
        self._lock = asyncio.Lock()

    async def check_and_increment(self, principal: Principal) -> dict[str, Any]:
        async with self._lock:
            now = int(time.time())
            minute_window = now // 60
            day_key = time.strftime("%Y-%m-%d", time.gmtime(now))

            configured_minute, minute_count = self._minute_windows.get(
                principal.token_hash, (minute_window, 0)
            )
            if configured_minute != minute_window:
                minute_count = 0

            configured_day, day_count = self._day_windows.get(principal.token_hash, (day_key, 0))
            if configured_day != day_key:
                day_count = 0

            minute_limit = principal.quota["requests_per_minute"]
            day_limit = principal.quota["requests_per_day"]
            if minute_count >= minute_limit:
                return {
                    "allowed": False,
                    "reason": "minute_quota_exceeded",
                    "minute_count": minute_count,
                    "minute_limit": minute_limit,
                    "day_count": day_count,
                    "day_limit": day_limit,
                }
            if day_count >= day_limit:
                return {
                    "allowed": False,
                    "reason": "daily_quota_exceeded",
                    "minute_count": minute_count,
                    "minute_limit": minute_limit,
                    "day_count": day_count,
                    "day_limit": day_limit,
                }

            minute_count += 1
            day_count += 1
            self._minute_windows[principal.token_hash] = (minute_window, minute_count)
            self._day_windows[principal.token_hash] = (day_key, day_count)
            return {
                "allowed": True,
                "reason": "within_quota",
                "minute_count": minute_count,
                "minute_limit": minute_limit,
                "day_count": day_count,
                "day_limit": day_limit,
            }


class ContentScanner:
    def __init__(self, policy: dict[str, Any]) -> None:
        self.prompt_patterns = [
            {
                "name": str(item["name"]),
                "pattern": re.compile(str(item["pattern"]), re.IGNORECASE | re.DOTALL),
            }
            for item in policy.get("prompt_injection_patterns", [])
        ]
        self.pii_patterns = [
            {
                "name": str(item["name"]),
                "pattern": re.compile(str(item["pattern"]), re.IGNORECASE),
                "replacement": str(item["replacement"]),
            }
            for item in policy.get("pii_patterns", [])
        ]

    def scan_payload(self, payload: dict[str, Any]) -> ScanResult:
        pii_findings: list[dict[str, str]] = []
        prompt_findings: list[dict[str, str]] = []
        masked_payload = self._walk(payload, "$", pii_findings, prompt_findings)
        if not isinstance(masked_payload, dict):
            raise ValueError("gateway payload must be a JSON object")
        return ScanResult(
            masked_payload=masked_payload,
            pii_findings=pii_findings,
            prompt_injection_findings=prompt_findings,
        )

    def _walk(
        self,
        value: Any,
        path: str,
        pii_findings: list[dict[str, str]],
        prompt_findings: list[dict[str, str]],
    ) -> Any:
        if isinstance(value, dict):
            return {
                str(key): self._walk(child, f"{path}.{key}", pii_findings, prompt_findings)
                for key, child in value.items()
            }
        if isinstance(value, list):
            return [
                self._walk(child, f"{path}[{index}]", pii_findings, prompt_findings)
                for index, child in enumerate(value)
            ]
        if isinstance(value, str):
            return self._scan_string(value, path, pii_findings, prompt_findings)
        return value

    def _scan_string(
        self,
        text: str,
        path: str,
        pii_findings: list[dict[str, str]],
        prompt_findings: list[dict[str, str]],
    ) -> str:
        for item in self.prompt_patterns:
            if item["pattern"].search(text):
                prompt_findings.append({"path": path, "pattern": item["name"]})

        masked = text
        for item in self.pii_patterns:
            if item["pattern"].search(masked):
                pii_findings.append({"path": path, "pattern": item["name"]})
                masked = item["pattern"].sub(item["replacement"], masked)
        return masked


class ModelProvider:
    async def complete(
        self, payload: dict[str, Any], principal: Principal, correlation_id: str
    ) -> dict[str, Any]:
        raise NotImplementedError


class MockAMCModelProvider(ModelProvider):
    def __init__(self, model_name: str) -> None:
        self.model_name = model_name

    async def complete(
        self, payload: dict[str, Any], principal: Principal, correlation_id: str
    ) -> dict[str, Any]:
        entity_id = str(payload.get("entity_id", "unknown"))
        entity_name = str(payload.get("entity_name", "unknown"))
        risk_hint = str(payload.get("risk_hint", "LOW")).upper()
        source_request = str(payload.get("source_request", "approved_public_source"))

        profiles = {
            "LOW": {
                "risk_level": "Low",
                "risk_score": 8,
                "summary": "No synthetic adverse-media indicators found in approved sources.",
                "recommended_actions": ["screen_entity", "search_approved_source", "generate_report"],
                "evidence": ["approved_registry_clean_profile", "approved_news_archive_no_hits"],
            },
            "MEDIUM": {
                "risk_level": "Medium",
                "risk_score": 61,
                "summary": "Synthetic near-name media match found; analyst review is required before disposition.",
                "recommended_actions": [
                    "screen_entity",
                    "search_approved_source",
                    "override_match",
                    "generate_report",
                ],
                "evidence": ["approved_news_archive_near_name_match", "analyst_review_queue"],
            },
            "HIGH": {
                "risk_level": "High",
                "risk_score": 92,
                "summary": "Synthetic high-risk indicator requests a denied evidence path and must be blocked.",
                "recommended_actions": [
                    "screen_entity",
                    "search_unapproved_source",
                    "delete_evidence",
                    "generate_report",
                ],
                "evidence": ["synthetic_denied_source_trigger"],
            },
        }
        profile = profiles.get(risk_hint, profiles["LOW"])
        request_id = sha256(f"{correlation_id}:{entity_id}:{entity_name}".encode("utf-8")).hexdigest()[:20]

        screening = {
            "entity_id": entity_id,
            "entity_name": entity_name,
            "risk_level": profile["risk_level"],
            "risk_score": profile["risk_score"],
            "summary": profile["summary"],
            "source_request": source_request,
            "evidence": profile["evidence"],
            "recommended_actions": profile["recommended_actions"],
            "model_provider": "mock",
        }
        return {
            "id": f"citadel-mock-{request_id}",
            "object": "chat.completion",
            "model": self.model_name,
            "correlation_id": correlation_id,
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": profile["summary"],
                    },
                }
            ],
            "screening": screening,
        }


class HttpModelProvider(ModelProvider):
    def __init__(self, endpoint: str, api_key_env: str, timeout_seconds: float) -> None:
        self.endpoint = endpoint
        self.api_key_env = api_key_env
        self.timeout_seconds = timeout_seconds

    async def complete(
        self, payload: dict[str, Any], principal: Principal, correlation_id: str
    ) -> dict[str, Any]:
        api_key = os.environ.get(self.api_key_env)
        if not api_key:
            raise RuntimeError(f"real model provider requested but {self.api_key_env} is not set")

        headers = {
            "authorization": f"Bearer {api_key}",
            "content-type": "application/json",
            "x-correlation-id": correlation_id,
        }
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.post(self.endpoint, json=payload, headers=headers)
            response.raise_for_status()
            model_response = response.json()
        if not isinstance(model_response, dict):
            raise RuntimeError("real model provider returned a non-object JSON payload")
        model_response.setdefault("correlation_id", correlation_id)
        return model_response


def load_gateway_policy(path: str | Path) -> dict[str, Any]:
    policy_path = Path(path)
    if not policy_path.exists():
        raise FileNotFoundError(f"gateway policy file not found: {policy_path}")
    with policy_path.open("r", encoding="utf-8") as handle:
        policy = yaml.safe_load(handle) or {}
    if not isinstance(policy, dict):
        raise ValueError("gateway policy must be a YAML mapping")
    for required in ("gateway", "tokens", "pii_patterns", "prompt_injection_patterns"):
        if required not in policy:
            raise ValueError(f"gateway policy missing required field: {required}")
    return policy


def create_model_provider(policy: dict[str, Any]) -> ModelProvider:
    model_config = dict(policy["gateway"].get("model", {}))
    provider = str(model_config.get("provider", "mock")).lower()
    if provider == "mock":
        return MockAMCModelProvider(str(model_config.get("mock_model_name", "citadel-mock-amc-v1")))
    if provider == "http":
        return HttpModelProvider(
            endpoint=str(model_config["endpoint"]),
            api_key_env=str(model_config.get("api_key_env", "CITADEL_REAL_MODEL_API_KEY")),
            timeout_seconds=float(model_config.get("timeout_seconds", 20)),
        )
    raise ValueError(f"unsupported model provider: {provider}")


def create_app(config_path: str | Path = "config/gateway_policy.yml") -> FastAPI:
    policy = load_gateway_policy(config_path)
    gateway_config = dict(policy["gateway"])
    security = dict(gateway_config.get("security", {}))
    audit_config = dict(gateway_config.get("audit", {}))

    logger = HashChainLogger(
        audit_config.get("sqlite_path", "logs/audit_chain.sqlite3"),
        audit_config.get("jsonl_path", "logs/audit_chain.jsonl"),
    )
    logger.initialize()
    token_authority = TokenAuthority(list(policy["tokens"]))
    quota_manager = QuotaManager()
    scanner = ContentScanner(policy)
    model_provider = create_model_provider(policy)

    app = FastAPI(
        title="CITADEL Governed AI Gateway",
        version=str(gateway_config.get("version", "1.0.0")),
        docs_url="/docs",
        redoc_url=None,
    )
    app.state.gateway_policy = policy

    @app.middleware("http")
    async def inject_correlation_id(request: Request, call_next: Any) -> JSONResponse:
        correlation_id = request.headers.get("x-correlation-id") or f"citadel-{uuid.uuid4().hex}"
        request.state.correlation_id = correlation_id
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception as exc:
            logger.log_event(
                event_type="gateway.unhandled_exception",
                actor="gateway",
                correlation_id=correlation_id,
                details={"path": request.url.path, "error": type(exc).__name__},
            )
            raise
        elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
        response.headers["x-correlation-id"] = correlation_id
        response.headers["x-citadel-gateway"] = str(gateway_config.get("policy_id", "citadel-gateway"))
        response.headers["x-citadel-latency-ms"] = str(elapsed_ms)
        return response

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "policy_id": gateway_config.get("policy_id"),
            "model_provider": gateway_config.get("model", {}).get("provider", "mock"),
        }

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> JSONResponse:
        correlation_id = str(request.state.correlation_id)
        actor = "unknown"
        principal: Principal | None = None

        body = await request.body()
        max_body_bytes = int(security.get("max_body_bytes", 65536))
        if len(body) > max_body_bytes:
            logger.log_event(
                event_type="gateway.request_rejected",
                actor="gateway",
                correlation_id=correlation_id,
                details={"reason": "body_too_large", "body_bytes": len(body), "max_body_bytes": max_body_bytes},
            )
            return JSONResponse(status_code=413, content={"error": "request body too large"})

        try:
            principal = token_authority.authenticate(request.headers.get("authorization"))
            actor = principal.actor
        except PermissionError as exc:
            logger.log_event(
                event_type="gateway.auth_failed",
                actor="anonymous",
                correlation_id=correlation_id,
                details={"reason": str(exc), "path": request.url.path},
            )
            return JSONResponse(status_code=401, content={"error": "unauthorized"})

        quota = await quota_manager.check_and_increment(principal)
        if not quota["allowed"]:
            logger.log_event(
                event_type="gateway.quota_rejected",
                actor=actor,
                correlation_id=correlation_id,
                details={"client_id": principal.client_id, "quota": quota},
            )
            return JSONResponse(status_code=429, content={"error": quota["reason"], "quota": quota})

        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            logger.log_event(
                event_type="gateway.request_rejected",
                actor=actor,
                correlation_id=correlation_id,
                details={"reason": "invalid_json", "error": str(exc)},
            )
            return JSONResponse(status_code=400, content={"error": "invalid JSON payload"})

        if not isinstance(payload, dict):
            return JSONResponse(status_code=400, content={"error": "payload must be a JSON object"})

        scan = scanner.scan_payload(payload)
        if scan.prompt_injection_findings and bool(security.get("block_prompt_injection", True)):
            logger.log_event(
                event_type="gateway.prompt_injection_blocked",
                actor=actor,
                correlation_id=correlation_id,
                details={
                    "client_id": principal.client_id,
                    "findings": scan.prompt_injection_findings,
                    "pii_findings": scan.pii_findings,
                },
            )
            return JSONResponse(
                status_code=400,
                content={
                    "error": "prompt injection pattern detected",
                    "correlation_id": correlation_id,
                    "findings": scan.prompt_injection_findings,
                },
            )

        forwarded_payload = (
            scan.masked_payload if bool(security.get("mask_pii_before_model", True)) else payload
        )

        try:
            model_response = await model_provider.complete(forwarded_payload, principal, correlation_id)
        except Exception as exc:
            logger.log_event(
                event_type="gateway.model_error",
                actor=actor,
                correlation_id=correlation_id,
                details={
                    "client_id": principal.client_id,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
            )
            return JSONResponse(status_code=502, content={"error": "model provider failure"})

        logger.log_event(
            event_type="gateway.request_completed",
            actor=actor,
            correlation_id=correlation_id,
            details={
                "client_id": principal.client_id,
                "path": request.url.path,
                "pii_findings": scan.pii_findings,
                "prompt_injection_findings": scan.prompt_injection_findings,
                "quota": quota,
                "model": model_response.get("model"),
            },
        )
        return JSONResponse(
            content=model_response,
            headers={
                "x-correlation-id": correlation_id,
                "x-citadel-pii-masked": str(bool(scan.pii_findings)).lower(),
            },
        )

    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the CITADEL FastAPI gateway")
    parser.add_argument("--config", default="config/gateway_policy.yml")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args(argv)

    policy = load_gateway_policy(args.config)
    gateway_config = dict(policy["gateway"])
    host = args.host or str(gateway_config.get("host", "0.0.0.0"))
    port = args.port or int(gateway_config.get("port", 8000))

    app = create_app(args.config)
    uvicorn.run(app, host=host, port=port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
