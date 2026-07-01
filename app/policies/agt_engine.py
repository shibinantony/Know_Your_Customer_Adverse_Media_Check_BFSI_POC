from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from app.audit.hash_logger import HashChainLogger


class PolicyDenied(Exception):
    """Raised when AGT policy explicitly denies an action."""


class JustificationRequired(Exception):
    """Raised when an action requires a human-readable justification but none was supplied."""


@dataclass(frozen=True)
class PolicyDecision:
    action: str
    effect: str
    reason: str
    justification: str | None
    correlation_id: str
    actor: str
    entity_id: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "effect": self.effect,
            "reason": self.reason,
            "justification": self.justification,
            "correlation_id": self.correlation_id,
            "actor": self.actor,
            "entity_id": self.entity_id,
        }


class AGTPolicyEngine:
    """AGT-style action governance matrix for the AMC pipeline."""

    def __init__(
        self,
        policy_path: str | Path = "config/agent_policy.yml",
        audit_logger: HashChainLogger | None = None,
    ) -> None:
        self.policy_path = Path(policy_path)
        self.policy = self._load_policy(self.policy_path)
        self.policy_id = str(self.policy["policy_id"])
        self.default_effect = str(self.policy.get("default_effect", "deny")).lower()
        self.actions: dict[str, dict[str, Any]] = dict(self.policy["actions"])
        self.audit = dict(self.policy.get("audit", {}))
        self.audit_logger = audit_logger

    @property
    def decision_matrix(self) -> dict[str, list[str]]:
        matrix = {"allow": [], "justification_required": [], "deny": []}
        for action, spec in self.actions.items():
            effect = str(spec.get("effect", "deny")).lower()
            matrix.setdefault(effect, []).append(action)
        return matrix

    def evaluate_action(
        self,
        action: str,
        *,
        actor: str,
        correlation_id: str,
        entity_id: str,
        justification: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        normalized_action = action.strip()
        if not normalized_action:
            raise ValueError("action cannot be empty")

        spec = dict(self.actions.get(normalized_action) or {})
        effect = str(spec.get("effect", self.default_effect)).lower()
        reason = str(spec.get("reason") or f"default_{effect}")
        metadata = metadata or {}

        if effect == "allow":
            decision = PolicyDecision(
                action=normalized_action,
                effect="allow",
                reason=reason,
                justification=None,
                correlation_id=correlation_id,
                actor=actor,
                entity_id=entity_id,
            )
            if bool(self.audit.get("log_allowed", True)):
                self._log_decision(decision, metadata)
            return decision

        if effect == "justification_required":
            clean_justification = (justification or "").strip()
            if not clean_justification:
                decision = PolicyDecision(
                    action=normalized_action,
                    effect="justification_missing",
                    reason=reason,
                    justification=None,
                    correlation_id=correlation_id,
                    actor=actor,
                    entity_id=entity_id,
                )
                self._log_decision(decision, metadata)
                raise JustificationRequired(
                    f"Action '{normalized_action}' requires justification under policy '{self.policy_id}'"
                )

            decision = PolicyDecision(
                action=normalized_action,
                effect="justification_required",
                reason=reason,
                justification=clean_justification,
                correlation_id=correlation_id,
                actor=actor,
                entity_id=entity_id,
            )
            if bool(self.audit.get("log_justification", True)):
                self._log_decision(decision, metadata)
            return decision

        if effect == "deny":
            decision = PolicyDecision(
                action=normalized_action,
                effect="deny",
                reason=reason,
                justification=justification,
                correlation_id=correlation_id,
                actor=actor,
                entity_id=entity_id,
            )
            if bool(self.audit.get("log_denied", True)):
                self._log_decision(decision, metadata)
            raise PolicyDenied(
                f"Action '{normalized_action}' is denied by policy '{self.policy_id}': {reason}"
            )

        raise ValueError(f"Unsupported policy effect '{effect}' for action '{normalized_action}'")

    def _log_decision(self, decision: PolicyDecision, metadata: dict[str, Any]) -> None:
        if self.audit_logger is None:
            return
        self.audit_logger.log_event(
            event_type=f"agt.action.{decision.effect}",
            actor=decision.actor,
            correlation_id=decision.correlation_id,
            details={
                "policy_id": self.policy_id,
                "action": decision.action,
                "entity_id": decision.entity_id,
                "reason": decision.reason,
                "justification": decision.justification,
                "metadata": metadata,
            },
        )

    @staticmethod
    def _load_policy(path: Path) -> dict[str, Any]:
        if not path.exists():
            raise FileNotFoundError(f"AGT policy file not found: {path}")
        with path.open("r", encoding="utf-8") as handle:
            policy = yaml.safe_load(handle) or {}
        if not isinstance(policy, dict):
            raise ValueError(f"AGT policy must be a YAML mapping: {path}")
        if "policy_id" not in policy:
            raise ValueError("AGT policy missing required field: policy_id")
        if "actions" not in policy or not isinstance(policy["actions"], dict):
            raise ValueError("AGT policy missing required mapping: actions")
        return policy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate a CITADEL AGT policy action")
    parser.add_argument("--policy", default="config/agent_policy.yml")
    parser.add_argument("--db", default="logs/audit_chain.sqlite3")
    parser.add_argument("--jsonl", default="logs/audit_chain.jsonl")
    parser.add_argument("--action", required=True)
    parser.add_argument("--actor", default="amc_agent")
    parser.add_argument("--correlation-id", default="manual")
    parser.add_argument("--entity-id", default="manual")
    parser.add_argument("--justification", default=None)
    args = parser.parse_args(argv)

    engine = AGTPolicyEngine(args.policy, HashChainLogger(args.db, args.jsonl))
    try:
        decision = engine.evaluate_action(
            args.action,
            actor=args.actor,
            correlation_id=args.correlation_id,
            entity_id=args.entity_id,
            justification=args.justification,
        )
    except (PolicyDenied, JustificationRequired) as exc:
        print(json.dumps({"allowed": False, "error": str(exc)}, indent=2))
        return 2

    print(json.dumps({"allowed": True, "decision": decision.as_dict()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
