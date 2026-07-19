"""
executor 결과 목록 → finding 목록

진입점:
  analyze_xss_probe(probe_results)  → (reflected_params, suspected_findings)
  analyze(results)                  → findings

탐지 방법 × confidence
  XSS   마커 노출 (onerror=alert 등)       confirmed
  XSS   probe 반사 확인                     suspected
  SQLi  DB 에러 패턴 (match_error)          confirmed
  SQLi  elapsed >= 4.5s + SQLI_TIME_*       confirmed
  SQLi  status=500 + SQLI_ERROR_META        suspected
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

# ── DB 에러 패턴 (sqli.py에서 이동) ──────────────────────────────

_ERROR_PATTERNS: dict[str, list[re.Pattern]] = {
    "MySQL": [
        re.compile(r"you have an error in your sql syntax", re.I),
        re.compile(r"com\.mysql\.jdbc\.exceptions", re.I),
        re.compile(r"org\.gjt\.mm\.mysql", re.I),
        re.compile(r"the used select statements have a different number of columns", re.I),
        re.compile(r"column count doesn't match", re.I),
        re.compile(r"warning: mysql", re.I),
        re.compile(r"supplied argument is not a valid mysql", re.I),
        re.compile(r"mysql_fetch|mysql_num_rows|mysql_query", re.I),
        re.compile(r"duplicate entry", re.I),
    ],
    "PostgreSQL": [
        re.compile(r"org\.postgresql\.util\.PSQLException", re.I),
        re.compile(r"each union query must have the same number of columns", re.I),
        re.compile(r"unterminated quoted string at or near", re.I),
        re.compile(r"syntax error at or near", re.I),
        re.compile(r"pg_query", re.I),
    ],
    "Oracle": [
        re.compile(r"ORA-\d{5}", re.I),
        re.compile(r"SQL command not properly ended", re.I),
        re.compile(r"query block has incorrect number of result columns", re.I),
    ],
    "MSSQL": [
        re.compile(r"com\.microsoft\.sqlserver\.jdbc", re.I),
        re.compile(r"\[Microsoft\]|\[SQLServer\]", re.I),
        re.compile(r"80040e14|800a0bcd|80040e57", re.I),
        re.compile(r"all queries in an sql statement containing a union operator must have an equal number", re.I),
        re.compile(r"microsoft ole db provider for sql server", re.I),
        re.compile(r"unclosed quotation mark", re.I),
        re.compile(r"quoted string not properly terminated", re.I),
        re.compile(r"invalid column name|invalid object name", re.I),
    ],
    "SQLite": [
        re.compile(r'near ".+": syntax error', re.I),
        re.compile(r"SQLITE_ERROR", re.I),
        re.compile(r"SELECTs to the left and right of UNION do not have the same number of result columns", re.I),
    ],
    "Hypersonic": [
        re.compile(r"org\.hsql|hSql\.", re.I),
        re.compile(r"Unexpected token , requires FROM in statement", re.I),
        re.compile(r"Column count does not match in statement", re.I),
    ],
    "DB2": [
        re.compile(r"com\.ibm\.db2\.jcc|COM\.ibm\.db2\.jdbc", re.I),
    ],
    "Generic": [
        re.compile(r"java\.sql\.SQLException", re.I),
        re.compile(r"org\.hibernate", re.I),
        re.compile(r"ODBC driver does not support", re.I),
        re.compile(r"division by zero", re.I),
    ],
}


def match_error(response_body: str) -> Optional[Tuple[str, str]]:
    """응답 body에서 DB 에러 패턴 탐지. 매치 시 (db_type, matched_text) 반환."""
    for db_type, patterns in _ERROR_PATTERNS.items():
        for pat in patterns:
            m = pat.search(response_body)
            if m:
                return (db_type, m.group())
    return None


# ── XSS 탐지 ─────────────────────────────────────────────────────

_XSS_MARKERS = (
    "onerror=alert",
    "onload=alert",
    "onerror=eval",
    "ontoggle=alert",
    "onmouseover=alert",
    "onfocus=alert",
    "onstart=alert",
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

    for marker in _XSS_MARKERS:
        idx = body_lower.find(marker)
        if idx == -1:
            continue
        if _is_encoded(body_raw, idx, len(marker)):
            continue
        return ("confirmed", f"XSS 마커 노출: '{marker}'")

    payload = str(result.get("payload") or "").lower().strip()
    if len(payload) >= 4 and payload in body_lower:
        return ("suspected", "페이로드 본문 반사 (HTML 인코딩 없음, 실행 여부 미확인)")

    return None


# ── XSS probe 분석 ────────────────────────────────────────────────

def _detect_xss_context(body: str, token: str) -> str:
    """token 주변 문자열로 HTML 컨텍스트 추론."""
    idx = body.lower().find(token.lower())
    if idx == -1:
        return "body"
    before = body[max(0, idx - 100): idx].lower()

    # <script 블록 안에서 아직 </script>가 닫히지 않은 경우
    last_open  = before.rfind("<script")
    last_close = before.rfind("</script")
    if last_open != -1 and last_open > last_close:
        return "script"

    # =" 또는 =' 로 끝나면 속성값 컨텍스트
    stripped = before.rstrip()
    if stripped.endswith('="') or stripped.endswith("='"):
        return "attr_value"

    return "body"


def _detect_escaped_chars(body: str, token: str) -> set:
    """escape probe 응답에서 인코딩된 문자 집합 반환."""
    idx = body.lower().find(token.lower())
    if idx == -1:
        return set()
    # token 이후 30자 안에서 인코딩 여부 확인
    window = body[idx: idx + len(token) + 30]
    escaped = set()
    if any(e in window for e in ("&lt;", "&#60;", "&#x3c;", "&#X3C;")):
        escaped.add("<")
    if any(e in window for e in ("&gt;", "&#62;", "&#x3e;", "&#X3E;")):
        escaped.add(">")
    if any(e in window for e in ("&quot;", "&#34;", "&#x22;", "&#X22;")):
        escaped.add('"')
    if any(e in window for e in ("&#39;", "&#x27;", "&#X27;", "&apos;")):
        escaped.add("'")
    return escaped


def analyze_xss_probe(probe_results: list[dict]) -> tuple[dict, list[dict]]:
    """XSS 1단계 probe 결과 분석.

    반환:
      reflected_params : {(url, param_name): {"context": str, "escaped_chars": set}}
      suspected_findings : 반사 확인된 파라미터에 대한 suspected finding 목록
    """
    # (url, param) → {probe_type → result}
    probe_map: dict[tuple, dict] = {}

    for r in probe_results:
        if r.get("error"):
            continue
        meta = r.get("meta") or {}
        probe_type = meta.get("xss_probe_type")
        if not probe_type:
            continue

        url   = r.get("url")
        param = r.get("inject_param")
        key   = (url, param)

        if key not in probe_map:
            probe_map[key] = {}
        # 같은 probe_type 결과가 여러 개면 먼저 온 것 사용
        probe_map[key].setdefault(probe_type, r)

    reflected_params: dict[tuple, dict] = {}
    suspected_findings: list[dict] = []

    for (url, param), probe_data in probe_map.items():
        reflect_result = probe_data.get("reflection")
        escape_result  = probe_data.get("escape")

        if not reflect_result:
            continue

        body  = reflect_result.get("response_body") or ""
        meta  = reflect_result.get("meta") or {}
        token = meta.get("xss_probe_token") or ""

        if not token or token not in body:
            continue  # 반사 안됨

        context      = _detect_xss_context(body, token)
        escaped_chars: set = set()

        if escape_result:
            escape_body  = escape_result.get("response_body") or ""
            escape_meta  = escape_result.get("meta") or {}
            escape_token = escape_meta.get("xss_probe_token") or token
            escaped_chars = _detect_escaped_chars(escape_body, escape_token)

        reflected_params[(url, param)] = {
            "context":      context,
            "escaped_chars": escaped_chars,
        }

        suspected_findings.append({
            "vuln_type":      "XSS",
            "method":         "reflected_xss",
            "confidence":     "suspected",
            "url":            url,
            "param":          param,
            "payload":        reflect_result.get("payload"),
            "payload_type":   "XSS_PROBE",
            "payload_family": "probe_reflection",
            "evidence":       (
                f"XSS 반사 확인 (context={context}, "
                f"escaped={sorted(escaped_chars) if escaped_chars else 'none'})"
            ),
            "elapsed":        reflect_result.get("elapsed"),
            "status":         reflect_result.get("status"),
            "meta":           meta,
        })

    return reflected_params, suspected_findings


# ── SQLi 단건 탐지 ────────────────────────────────────────────────

_SLEEP_THRESHOLD = 4.5
_SQLI_TIME_TYPES = {
    "SQLI_TIME_MYSQL", "SQLI_TIME_PGSQL",
    "SQLI_TIME_MSSQL", "SQLI_TIME_ORACLE",
}


def _find_sqli_single(result: dict) -> Optional[Tuple[str, str, str]]:
    """(confidence, method, evidence) or None"""
    elapsed = float(result.get("elapsed") or 0.0)
    status  = result.get("status")
    body    = (result.get("response_body") or "").lower()
    ptype   = result.get("payload_type") or ""

    if elapsed >= _SLEEP_THRESHOLD and ptype in _SQLI_TIME_TYPES:
        return ("confirmed", "time_based",
                f"응답 지연 {elapsed:.2f}s >= {_SLEEP_THRESHOLD}s [{ptype}]")

    hit = match_error(body)
    if hit:
        db_type, fragment = hit
        method = "union_based" if ptype == "SQLI_UNION" else "error_based"
        return ("confirmed", method,
                f"DB 에러 노출 [{db_type}]: '{fragment[:60]}'")

    if status == 500 and ptype == "SQLI_ERROR_META":
        pl = str(result.get("payload") or "")[:40]
        return ("suspected", "error_based",
                f"HTTP 500 응답 + SQLI_ERROR_META payload: '{pl}'")

    return None


# ── SQLi 그룹 탐지 ────────────────────────────────────────────────

_BOOL_GROUP_THRESHOLD   = 0.05
_ORDERBY_DIFF_THRESHOLD = 0.10

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
    family = r.get("payload_family") or ""
    # attack_requests family: "boolean_boolean_true_0" 형식
    if "boolean_true" in family or family.endswith("_true"):
        return "or_true" if "or_" in family else "true"
    if "boolean_false" in family or family.endswith("_false"):
        return "false"
    # payload 텍스트 fallback
    payload = r.get("payload") or ""
    if _BOOL_TRUE_RE.search(payload):
        return "true"
    if _BOOL_FALSE_RE.search(payload):
        return "false"
    return "unknown"


def _compare_bool(pos_items: list, false_items: list, label: str) -> Optional[Tuple[str, str, dict]]:
    if not pos_items or not false_items:
        return None

    best      = max(pos_items, key=_body_len)
    avg_pos   = sum(_body_len(r) for r in pos_items)   / len(pos_items)
    avg_false = sum(_body_len(r) for r in false_items)  / len(false_items)
    diff      = abs(avg_pos - avg_false) / max(avg_pos, avg_false, 1)

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


def _detect_boolean(group: list) -> Optional[Tuple[str, str, dict]]:
    true_items, false_items, or_items = [], [], []
    for r in group:
        c = _bool_classify(r)
        if c == "true":       true_items.append(r)
        elif c == "false":    false_items.append(r)
        elif c == "or_true":  or_items.append(r)

    if true_items and false_items:
        return _compare_bool(true_items, false_items, "true")
    if or_items and false_items:
        return _compare_bool(or_items, false_items, "or_true")

    candidates = true_items or or_items
    if candidates:
        kind    = "TRUE" if true_items else "OR_TRUE"
        has_err = any(_has_db_error((r.get("response_body") or "").lower()) for r in candidates)
        err_note = " + DB 에러 동반" if has_err else ""
        return (
            "candidate",
            f"Boolean SQLi candidate ({kind} only): {len(candidates)}개 페이로드{err_note}",
            max(candidates, key=_body_len),
        )

    return None


def _detect_orderby(group: list) -> Optional[Tuple[str, str, dict]]:
    if not group:
        return None

    if len(group) == 1:
        sample   = (group[0].get("response_body") or "").lower()
        err_note = " + DB 에러 동반" if _has_db_error(sample) else ""
        return (
            "candidate",
            f"ORDER BY SQLi candidate: 단일 페이로드{err_note}",
            group[0],
        )

    lengths    = [_body_len(r) for r in group]
    min_len    = min(lengths)
    max_len_v  = max(lengths)
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

    db_note = " + DB 에러 동반" if any(
        _has_db_error((r.get("response_body") or "").lower()) for r in group
    ) else ""
    return (
        "candidate",
        f"ORDER BY SQLi candidate: {len(group)}개 응답 동일 (diff={diff:.1%}){db_note}",
        group[0],
    )


# ── finding 생성 헬퍼 ─────────────────────────────────────────────

def _make_finding(result: dict, vuln_type: str, method: str, confidence: str, evidence: str) -> dict:
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


# ── mutation 재전송 검증 ──────────────────────────────────────────
#
# mutations.json의 mutated_payload를 실제로 재전송한 응답을 보고
# WAF/PHPIDS 우회 성공 여부를 판정한다.

_BLOCK_PATTERNS = [
    re.compile(r"hacking attempt detected", re.I),
    re.compile(r"attack detected", re.I),
    re.compile(r"request blocked", re.I),
    re.compile(r"you have been blocked", re.I),
    re.compile(r"phpids", re.I),
    re.compile(r"security violation", re.I),
    re.compile(r"blocked by", re.I),
]


def _is_blocked(body: str) -> bool:
    return any(p.search(body) for p in _BLOCK_PATTERNS)


def analyze_mutation_verify(results: List[dict]) -> List[dict]:
    """mutation 재전송 결과 → 우회(bypass) 성공 여부 판정 목록.

    build_mutation_tasks()가 만든 task의 결과만 처리한다 (meta.mutation_verify=True).
    """
    verified: List[dict] = []

    for r in results:
        if r.get("error"):
            continue
        meta = r.get("meta") or {}
        if not meta.get("mutation_verify"):
            continue

        body      = r.get("response_body") or ""
        vuln_type = meta.get("vuln_type", "")
        blocked   = _is_blocked(body)
        bypassed  = False
        evidence  = ""

        if vuln_type == "XSS":
            payload   = str(r.get("payload") or "")
            reflected = bool(payload) and payload.lower() in body.lower()
            bypassed  = reflected and not blocked
            if blocked:
                evidence = "WAF/PHPIDS 차단 페이지 응답 — 우회 실패"
            elif reflected:
                evidence = "변형 payload가 필터링 없이 그대로 반사됨 — 우회 성공"
            else:
                evidence = "payload 미반사 (필터링 또는 컨텍스트 불일치) — 우회 실패"

        elif vuln_type == "SQLI":
            hit = _find_sqli_single(r)
            bypassed = hit is not None and not blocked
            if blocked:
                evidence = "WAF/PHPIDS 차단 페이지 응답 — 우회 실패"
            elif hit:
                evidence = hit[2]
            else:
                evidence = "SQLi 징후 재현 안 됨 — 우회 실패"

        else:
            continue

        verified.append({
            "vuln_type":        vuln_type,
            "url":              r.get("url"),
            "param":            r.get("inject_param"),
            "original_payload": meta.get("original_payload"),
            "mutated_payload":  r.get("payload"),
            "mutation_desc":    meta.get("mutation_desc"),
            "blocked":          blocked,
            "bypassed":         bypassed,
            "evidence":         evidence,
            "status":           r.get("status"),
        })

    return verified


# ── 메인 진입점 ───────────────────────────────────────────────────

def analyze(results: List[dict]) -> List[dict]:
    """SQLi + XSS 2단계 attack 결과 → finding 목록.

    XSS probe 결과(payload_type=XSS_PROBE)는 건너뜀 — analyze_xss_probe()에서 처리.
    """
    findings: List[dict] = []
    seen: set[tuple] = set()
    group_candidates: list[dict] = []

    for r in results:
        if r.get("error"):
            continue

        vuln  = (r.get("meta") or {}).get("vuln_scan", "")
        ptype = r.get("payload_type") or ""

        if vuln == "xss":
            if ptype == "XSS_PROBE":
                continue  # probe 결과는 analyze_xss_probe()에서 처리
            hit = _find_xss(r)
            if hit:
                confidence, evidence = hit
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
                if _bool_classify(r) != "unknown" or ptype == "SQLI_ORDERBY":
                    group_candidates.append(r)

    # ── boolean / orderby 그룹 분석 ──────────────────────────────
    bool_groups:    dict[tuple, list] = defaultdict(list)
    orderby_groups: dict[tuple, list] = defaultdict(list)

    for r in group_candidates:
        key = (r.get("url"), r.get("inject_param"))
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
