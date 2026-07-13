from urllib.parse import urlparse

from scan.normalize.importer import _parse_response_status, _parse_headers_block
from scan.normalize.target import RequestTarget


# RequestTarget -> raw HTTP 요청 텍스트 재조립 (요청줄 + 헤더 + Cookie + 바디)
def _build_raw_request(target: RequestTarget) -> str:
    parsed = urlparse(target.url)
    path = parsed.path + (f"?{parsed.query}" if parsed.query else "")

    lines = [f"{target.method} {path} HTTP/1.1"]
    for k, v in target.headers.items():
        lines.append(f"{k}: {v}")
    if target.cookies:  # importer가 헤더에서 빼놓은 cookie, Cookie 헤더로 재조립
        cookie_str = "; ".join(f"{k}={v}" for k, v in target.cookies.items())
        lines.append(f"Cookie: {cookie_str}")

    request_text = "\r\n".join(lines) + "\r\n\r\n"
    if target.request_body:
        request_text += target.request_body
    return request_text


# target을 그대로 전송, 응답 dict 리턴 (zap_message_id로 그룹 연결)
# send_request()는 list[dict] 형태로 리턴, dict는 importer.py가 다루는 raw ZAP 메시지와 동일한 구조
def send(target: RequestTarget, zap) -> dict:
    raw_request = _build_raw_request(target)
    result = zap.core.send_request(request=raw_request, followredirects=False)
    msg = result[0]

    return {
        "zap_message_id": target.zap_message_id,
        "response_status": _parse_response_status(msg.get("responseHeader", "")),
        "response_headers": _parse_headers_block(msg.get("responseHeader", "")),
        "response_body": msg.get("responseBody", ""),
    }
