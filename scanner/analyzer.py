"""
executor 결과 목록 → finding 목록

단일 진입점: analyze(results) → List[dict]

탐지 방법 × confidence
  XSS   marker (onerror=alert 등)           confirmed
  XSS   페이로드 반사 (HTML 인코딩 없음)    suspected
  SQLi  DB 에러 패턴 (match_error)          confirmed
  SQLi  UNION 컬럼수 불일치 에러            confirmed
  SQLi  status=500 + SQLI_ERROR_META        suspected
  SQLi  elapsed >= 4.5s + SQLI_TIME_*       confirmed
  SQLi  boolean true/false 응답 5%+ 차이    confirmed
  SQLi  boolean 응답 동일 + DB 에러 동반    suspected
  SQLi  boolean 쌍 없음                     candidate
  SQLi  ORDER BY 응답 10%+ 차이             confirmed
  SQLi  ORDER BY 응답 동일                  candidate
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import List, Optional, Tuple

from scanner.payload.sqli import match_error

# ── XSS 탐지 ─────────────────────────────────────────────────────

_XSS_MARKERS = (
    "onerror=alert",
    "onload=alert",
    "onerror=eval",
    "ontoggle=alert",
    "onmouseover=alert",
    "onfocus=alert",
    "onstart=alert",
    "onanimationstart=alert",
    "src=x onerror",
    "<script>alert",
    "javascript:alert",
    "href=javascript:",
    "<svg/onload",
    "<svg onload",
    "<details open ontoggle",
    "onerror=prompt",
    "onerror=alert`",
    "onmouseover=alert`",
)

# 마커 주변에 HTML 엔티티가 있으면 인코딩된 것으로 간주 (false positive 방지)
_ENCODED_TOKENS = ("&lt;", "&gt;", "&quot;", "&#x3c;", "&#60;", "&#x3e;", "&#62;")


def _is_encoded(body: str, idx: int, marker_len: int, window: int = 10) -> bool:
    surrounding = body[max(0, idx - window): idx + marker_len + window]
    return any(tok in surrounding for tok in _ENCODED_TOKENS)


def _find_xss(result: dict) -> Optional[Tuple[str, str]]:
    """(confidence, evidence) or None"""
    body_raw = result.get("response_body") or ""
    if not body_raw:
        return None
    body_lower = body_raw.lower()

    # 1) marker 탐지 → confirmed
    for marker in _XSS_MARKERS:
        idx = body_lower.find(marker)
        if idx == -1:
            continue
        if _is_encoded(body_raw, idx, len(marker)):
            continue
        return ("confirmed", f"XSS 마커 노출: '{marker}'")

    # 2) 페이로드 전체 반사 → suspected (실행됐다는 보장 없음)
    payload = str(result.get("payload") or "").lower().strip()
    if len(payload) >= 4 and payload in body_lower:
        return ("suspected", "페이로드 본문 반사 (HTML 인코딩 없음, 실행 여부 미확인)")

    return None


# ── SQLi 단건 탐지 ────────────────────────────────────────────────

_SLEEP_THRESHOLD = 4.5
_SQLI_TIME_TYPES = {
    "SQLI_TIME_MYSQL", "SQLI_TIME_PGSQL",
    "SQLI_TIME_MSSQL", "SQLI_TIME_ORACLE",
}
def _find_sqli_single(result: dict) -> Optional[Tuple[str, str, str]]:
    """(confidence, method, evidence) or None"""
    elapsed = float(result.get("elapsed") or 0.0)
    status = result.get("status")
    body = (result.get("response_body") or "").lower()
    ptype = result.get("payload_type") or ""

    # 1) time-based — SQLI_TIME_* 타입에만 적용해 우연한 서버 지연 제외
    if elapsed >= _SLEEP_THRESHOLD and ptype in _SQLI_TIME_TYPES:
        return ("confirmed", "time_based",
                f"응답 지연 {elapsed:.2f}s >= {_SLEEP_THRESHOLD}s [{ptype}]")

    # 2) DB 에러 패턴 — sqli.py match_error()에 모든 DB 에러 시그니처 통합
    hit = match_error(body)
    if hit:
        db_type, fragment = hit
        method = "union_based" if ptype == "SQLI_UNION" else "error_based"
        return ("confirmed", method,
                f"DB 에러 노출 [{db_type}]: '{fragment[:60]}'")

    # 3) HTTP 500 + SQLI_ERROR_META — 안전값 재확인 없으므로 suspected
    if status == 500 and ptype == "SQLI_ERROR_META":
        pl = str(result.get("payload") or "")[:40]
        return ("suspected", "error_based",
                f"HTTP 500 응답 + SQLI_ERROR_META payload: '{pl}'")

    return None


# ── SQLi 그룹 탐지 ────────────────────────────────────────────────

_BOOL_GROUP_THRESHOLD = 0.05    # true/false 응답 크기 5% 이상 차이 → confirmed
_ORDERBY_DIFF_THRESHOLD = 0.10  # ORDER BY 응답 크기 10% 이상 차이 → confirmed

_BOOL_TRUE_RE = re.compile(
    r"1\s*=\s*1"
    r"|'\s*([a-z0-9])\s*'\s*=\s*'\s*\1"
    r"|\bor\s+1\b"
    r"|\band\s+1\s*=\s*1"
    r"|\btrue\b"
    r"|length\(.+\)\s*>\s*0"
    r"|exists\s*\("
    r"|case\s+when\s*\(\s*1\s*=\s*1",
    re.IGNORECASE,
)
_BOOL_FALSE_RE = re.compile(
    r"1\s*=\s*2"
    r"|1\s*=\s*0"
    r"|\band\s+1\s*=\s*2"
    r"|\bfalse\b"
    r"|\band\s+0\b"
    r"|case\s+when\s*\(\s*1\s*=\s*2",
    re.IGNORECASE,
)

def _body_len(r: dict) -> int:
    return len(r.get("response_body") or "")


def _has_db_error(body: str) -> bool:
    return match_error(body) is not None


def _bool_classify(r: dict) -> str:
    """payload를 'true'/'false'/'or_true'/'unknown'으로 분류.

    OR_TRUE는 별도 'or_true'로 반환해 _detect_boolean이 AND_TRUE와 분리 처리한다.
    family suffix 우선: or_*_true → 'or_true', *_true → 'true', *_false → 'false'.
    regex는 suffix fallback 전 단계로만 동작.
    """
    family = r.get("payload_family") or ""
    if family.endswith("_true"):
        return "or_true" if family.startswith("or_") else "true"
    if family.endswith("_false"):
        return "false"
    payload = r.get("payload") or ""
    if _BOOL_TRUE_RE.search(payload):
        return "true"
    if _BOOL_FALSE_RE.search(payload):
        return "false"
    return "unknown"


def _compare_bool(pos_items: list[dict], false_items: list[dict], label: str) -> Optional[Tuple[str, str, dict]]:
    """pos_items(true or or_true) vs false_items 비교. 공통 로직."""
    if not pos_items or not false_items:
        return None

    best = max(pos_items, key=_body_len)
    avg_pos = sum(_body_len(r) for r in pos_items) / len(pos_items)
    avg_false = sum(_body_len(r) for r in false_items) / len(false_items)
    diff = abs(avg_pos - avg_false) / max(avg_pos, avg_false, 1)

    if diff >= _BOOL_GROUP_THRESHOLD:
        direction = f"{label}>false" if avg_pos > avg_false else f"{label}<false"
        return (
            "confirmed",
            f"Boolean SQLi ({label}): pos_len={avg_pos:.0f} false_len={avg_false:.0f} diff={diff:.1%} ({direction})",
            best,
        )

    has_err = any(
        _has_db_error((r.get("response_body") or "").lower())
        for r in (*pos_items, *false_items)
    )
    if has_err:
        return (
            "suspected",
            f"Boolean SQLi ({label}): 응답 크기 동일 (diff={diff:.1%}) + DB 에러 동반",
            best,
        )

    return (
        "candidate",
        f"Boolean SQLi candidate ({label}): pos {len(pos_items)}개 / false {len(false_items)}개, 응답 동일 (diff={diff:.1%})",
        best,
    )


def _detect_boolean(group: list[dict]) -> Optional[Tuple[str, str, dict]]:
    """(confidence, evidence, best_result) or None

    1차: AND_TRUE vs AND_FALSE 비교
    2차 폴백: AND_TRUE 없을 때 OR_TRUE vs AND_FALSE 비교 (OR 우회 시나리오)
    OR_TRUE는 AND_TRUE 평균 계산에 포함하지 않는다.
    """
    true_items: list[dict] = []
    false_items: list[dict] = []
    or_items: list[dict] = []
    for r in group:
        c = _bool_classify(r)
        if c == "true":
            true_items.append(r)
        elif c == "false":
            false_items.append(r)
        elif c == "or_true":
            or_items.append(r)

    # 1차: AND_TRUE vs AND_FALSE
    if true_items and false_items:
        return _compare_bool(true_items, false_items, "true")

    # 2차 폴백: OR_TRUE vs AND_FALSE (AND_TRUE 응답이 없는 경우)
    if or_items and false_items:
        return _compare_bool(or_items, false_items, "or_true")

    # false_items만 있는 경우: 비교 기준 응답 없어 boolean 판정 불가 → None
    candidates = true_items or or_items
    if candidates:
        kind = "TRUE" if true_items else "OR_TRUE"
        has_err = any(_has_db_error((r.get("response_body") or "").lower()) for r in candidates)
        err_note = " + DB 에러 동반" if has_err else ""
        return (
            "candidate",
            f"Boolean SQLi candidate ({kind} only): {len(candidates)}개 페이로드{err_note}",
            max(candidates, key=_body_len),
        )

    return None


def _detect_orderby(group: list[dict]) -> Optional[Tuple[str, str, dict]]:
    """(confidence, evidence, best_result) or None"""
    if not group:
        return None

    if len(group) == 1:
        sample = (group[0].get("response_body") or "").lower()
        err_note = " + DB 에러 동반" if _has_db_error(sample) else ""
        return (
            "candidate",
            f"ORDER BY SQLi candidate: 단일 페이로드{err_note}",
            group[0],
        )

    lengths = [_body_len(r) for r in group]
    min_len, max_len_v = min(lengths), max(lengths)
    if max_len_v == 0:
        return None
    diff = (max_len_v - min_len) / max_len_v

    has_unknown_col = any(
        "unknown column" in (r.get("response_body") or "").lower()
        for r in group
    )

    if diff >= _ORDERBY_DIFF_THRESHOLD or has_unknown_col:
        extra = " + 'unknown column' 에러" if has_unknown_col else ""
        return (
            "confirmed",
            f"ORDER BY SQLi: {len(group)}개 응답 분산 (min={min_len}b max={max_len_v}b diff={diff:.1%}){extra}",
            max(group, key=_body_len),
        )

    db_note = " + DB 에러 동반" if any(_has_db_error((r.get("response_body") or "").lower()) for r in group) else ""
    return (
        "candidate",
        f"ORDER BY SQLi candidate: {len(group)}개 응답 동일 (diff={diff:.1%}){db_note}",
        group[0],
    )


# ── finding 생성 헬퍼 ─────────────────────────────────────────────

def _make_finding(
    result: dict,
    vuln_type: str,
    method: str,
    confidence: str,
    evidence: str,
) -> dict:
    return {
        "vuln_type":      vuln_type,
        "method":         method,
        "confidence":     confidence,
        "url":            result.get("url"),
        "param":          result.get("inject_param"),
        "payload":        result.get("payload"),
        "payload_type":   result.get("payload_type"),
        "payload_family": result.get("payload_family"),
        "evidence":       evidence,
        "elapsed":        result.get("elapsed"),
        "status":         result.get("status"),
        "meta":           result.get("meta") or {},
    }


# ── 메인 진입점 ───────────────────────────────────────────────────

def analyze(results: List[dict]) -> List[dict]:
    """executor 결과 목록 → finding 목록.

    - 에러가 있는 result는 건너뜀 (응답 없음 = 탐지 불가)
    - time-based 탐지를 위해 response_body 없는 result도 elapsed만으로 처리
    - (url, param, payload) 조합 중복 finding 제거
    """
    findings: List[dict] = []
    seen: set[tuple] = set()

    # boolean/orderby 그룹 분석을 위해 단건 탐지를 통과한 결과를 누적
    group_candidates: list[dict] = []

    for r in results:
        if r.get("error"):
            continue

        vuln = (r.get("meta") or {}).get("vuln_scan", "")

        if vuln == "xss":
            hit = _find_xss(r)
            if hit:
                confidence, evidence = hit
                ptype = r.get("payload_type") or ""
                if ptype == "STORED_XSS":
                    vuln_type, xss_method = "XSS", "stored_xss"
                elif ptype == "DOM_XSS":
                    vuln_type, xss_method = "XSS", "dom_xss"
                elif ptype == "OPEN_REDIRECT":
                    vuln_type, xss_method = "OPEN_REDIRECT", "open_redirect"
                else:
                    vuln_type, xss_method = "XSS", "reflected_xss"
                key = (r.get("url"), r.get("inject_param"), r.get("payload"))
                if key not in seen:
                    seen.add(key)
                    findings.append(_make_finding(r, vuln_type, xss_method, confidence, evidence))

        elif vuln == "sqli":
            hit = _find_sqli_single(r)
            if hit:
                confidence, method, evidence = hit
                key = (r.get("url"), r.get("inject_param"), r.get("payload"))
                if key not in seen:
                    seen.add(key)
                    findings.append(_make_finding(r, "SQLI", method, confidence, evidence))
            elif r.get("response_body"):
                if (_bool_classify(r) != "unknown" or r.get("payload_type") == "SQLI_ORDERBY"):
                    group_candidates.append(r)

    # ── boolean / orderby 그룹 분석 ──────────────────────────────
    bool_groups: dict[tuple, list[dict]] = defaultdict(list)
    orderby_groups: dict[tuple, list[dict]] = defaultdict(list)

    for r in group_candidates:
        key = (r.get("url"), r.get("inject_param"))
        payload = r.get("payload") or ""
        if r.get("payload_type") == "SQLI_ORDERBY":
            orderby_groups[key].append(r)
        else:
            bool_groups[key].append(r)

    for _, group in bool_groups.items():
        hit = _detect_boolean(group)
        if hit:
            confidence, evidence, best = hit
            key = (best.get("url"), best.get("inject_param"), best.get("payload"))
            if key not in seen:
                seen.add(key)
                findings.append(_make_finding(best, "SQLI", "boolean", confidence, evidence))

    for _, group in orderby_groups.items():
        hit = _detect_orderby(group)
        if hit:
            confidence, evidence, best = hit
            key = (best.get("url"), best.get("inject_param"), best.get("payload"))
            if key not in seen:
                seen.add(key)
                findings.append(_make_finding(best, "SQLI", "orderby", confidence, evidence))

    return findings
