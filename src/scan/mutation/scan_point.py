"""
변형기 1단계 — RequestTarget(scan_targets.json) -> ScanPoint 목록 변환

scannable_params 기준으로 추출한 뒤 control 파라미터/보안 토큰 값을 제외하고,
파라미터 위치를 query/form/json으로 정규화한 ScanPoint를 타겟마다 생성한다.
"""

from __future__ import annotations

import re

from .models import ScanPoint

# 폼 제출/액션 의미를 가진 값 모음 — Submit=Submit 같은 control 파라미터 판별용
_CONTROL_ACTION_WORDS = frozenset({
    "submit", "login", "search", "change", "update", "delete",
    "create", "register", "logout", "reset", "cancel", "sign",
    "upload", "clear", "add", "remove",
})

_HEX_TOKEN_RE = re.compile(r'^[0-9a-fA-F]{16,}$')


# 값이 파라미터 이름과 같거나 control 액션 단어로만 구성되면 control 파라미터로 판정
def _is_control_param(name: str, value: str) -> bool:
    v = (value or "").strip().lower()
    if not v:
        return False
    if v == (name or "").strip().lower():
        return True
    words = set(v.replace("+", " ").split())
    return bool(words & _CONTROL_ACTION_WORDS)


# 16자 이상 hex 문자열이면 보안 토큰(세션 ID 등)으로 판정
def _is_security_token(value: str) -> bool:
    return bool(_HEX_TOKEN_RE.match((value or "").strip()))


# int() 변환 가능 여부로 value_type("number" 또는 "string") 판정
def _is_numeric(value: str) -> bool:
    try:
        int(value)
        return True
    except (TypeError, ValueError):
        return False


# param_location을 query/form/json으로 정규화 (body -> form, 나머지는 그대로 통과)
def _normalize_location(location: str) -> str:
    return "form" if location == "body" else location


# 타겟 목록에서 스캔 가능한 파라미터만 추출해 ScanPoint 목록으로 변환
def build_scan_points(targets: list[dict]) -> list[ScanPoint]:
    scan_points: list[ScanPoint] = []

    for idx, target in enumerate(targets):
        target_id = f"t{idx}"
        params = target.get("params") or {}
        scannable = set(target.get("scannable_params") or params.keys())
        location = _normalize_location(target.get("param_location", "query"))

        for name, value in params.items():
            if name not in scannable:
                continue
            if _is_control_param(name, value):
                continue
            if _is_security_token(value):
                continue

            scan_points.append(ScanPoint(
                target_id=target_id,
                name=name,
                location=location,
                original_value=str(value),
                value_type="number" if _is_numeric(value) else "string",
            ))

    return scan_points
