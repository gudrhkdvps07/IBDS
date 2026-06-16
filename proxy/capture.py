import json
import os
import sys
from urllib.parse import parse_qs, urlparse
from mitmproxy import http

# proxy/ 하위에 있으므로 프로젝트 루트를 sys.path에 추가 -> core 같은 패키지를 import하기 위함.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from core.session_context import (
    create_new_capture,
    get_capture_dir,
    get_proxy_history_path,
)


# 캡처에서 제외할 정적 파일 확장자
STATIC_EXTENSIONS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".svg",
    ".map", ".webp", ".bmp", ".pdf", ".zip",
)


# TARGET_URL 환경변수에서 scope 필터링에 쓸 host, port 추출
def _target_host_port() -> tuple[str, int | None]:
    target_url = os.getenv("TARGET_URL", "")
    if not target_url:
        return "", None  # TARGET_URL 미설정 시 빈 문자열 반환 -> 전체 트래픽 캡처
    parsed = urlparse(target_url)
    return parsed.hostname or "", parsed.port


# 정적 파일 요청 여부 확인 (쿼리스트링 제거 후 확장자 비교)
def _is_static(path: str) -> bool:
    bare = path.split("?")[0].lower()
    return any(bare.endswith(ext) for ext in STATIC_EXTENSIONS)


# Cookie 헤더 문자열을 dict로 파싱
def _parse_cookies(cookie_header: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            cookies[k.strip()] = v.strip()
    return cookies


# 쿼리스트링 파싱 -> [{name, value}] 리스트로 변환
def _params_as_list(qs: str) -> list[dict[str, str]]:
    result = []
    for name, values in parse_qs(qs, keep_blank_values=True).items():  # parse_qs는 같은 키에 여러 값이 올 수 있어서 루프로 펼쳐서 저장
        for value in values: 
            result.append({"name": name, "value": value})
    return result


class CaptureAddon:
    # mitmproxy 시작 시 호출해 항상 새 capture 생성
    def __init__(self) -> None:
        self._host, self._port = _target_host_port()
        self._capture_id = create_new_capture()  # .current_capture 덮어씀
        os.makedirs(get_capture_dir(self._capture_id), exist_ok=True)
        self._output_file = get_proxy_history_path(self._capture_id)
        print(f"[capture] target={self._host}:{self._port}")
        print(f"[capture] → {self._output_file}")

    # TARGET_URL 기준으로 scope 내 요청인지 확인
    # _host가 비어 있으면 전체 허용
    def _in_scope(self, req: http.Request) -> bool:
        if not self._host:
            return True
        if req.host != self._host:
            return False
        if self._port is not None and req.port != self._port:
            return False
        return True

    # 요청마다 호출 -> scope/정적파일 필터링 후 record를 jsonl에 append
    def request(self, flow: http.HTTPFlow) -> None:
        req = flow.request

        if not self._in_scope(req):
            return
        if _is_static(req.path):
            return

        parsed = urlparse(req.pretty_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # GET 쿼리스트링 파라미터
        parameters = _params_as_list(parsed.query)

        content_type = req.headers.get("content-type", "")
        body = ""
        if req.method == "POST":
            try:
                body = req.text
            except Exception:
                pass
            # form 데이터면 파라미터로도 파싱해서 추가
            if "application/x-www-form-urlencoded" in content_type:
                try:
                    parameters += _params_as_list(body)
                except Exception:
                    pass

        cookies = _parse_cookies(req.headers.get("cookie", ""))

        record = {
            "method": req.method,
            "scheme": parsed.scheme,
            "host": req.host,
            "port": req.port,
            "path": parsed.path,
            "full_url": req.pretty_url,
            "base_url": base_url,
            "parameters": parameters,
            "content_type": content_type,
            "body": body,
            "cookies": cookies,
            "headers": dict(req.headers),
        }

        with open(self._output_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

        print(f"[capture] {req.method} {req.pretty_url}  params={len(parameters)}")


addons = [CaptureAddon()]
