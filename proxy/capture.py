"""
크롤러 HTTP 요청을 captured_requests.jsonl에 저장

실행:
    mitmdump -s capture.py -p 8081
"""
import json
import os
from urllib.parse import parse_qs, urlparse

from mitmproxy import http

STATIC_EXTENSIONS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".svg",
    ".map", ".webp", ".bmp", ".pdf", ".zip",
)

OUTPUT_FILE = os.getenv("CAPTURE_OUTPUT", "results/captured_requests.jsonl")

# TARGET_URL 환경변수에서 (hostname, port) 추출
def _target_host_port() -> tuple[str, int | None]:
    target_url = os.getenv("TARGET_URL", "http://localhost:8080")
    if not target_url:
        return "", None
    parsed = urlparse(target_url)
    return parsed.hostname or "", parsed.port


def _is_static(path: str) -> bool:
    bare = path.split("?")[0].lower()
    return any(bare.endswith(ext) for ext in STATIC_EXTENSIONS)


def _parse_cookies(cookie_header: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            cookies[k.strip()] = v.strip()
    return cookies


# query string → [{"name": k, "value": v}, ...]  (중복 키 보존)
def _params_as_list(qs: str) -> list[dict[str, str]]:
    result = []
    for name, values in parse_qs(qs, keep_blank_values=True).items():
        for value in values:
            result.append({"name": name, "value": value})
    return result


class CaptureAddon:
    def __init__(self) -> None:
        self._host, self._port = _target_host_port()
        print(f"[capture] target={self._host}:{self._port}  output={OUTPUT_FILE}")

    def _in_scope(self, req: http.Request) -> bool:
        if not self._host:
            return True
        if req.host != self._host:
            return False
        if self._port is not None and req.port != self._port:
            return False
        return True

    def request(self, flow: http.HTTPFlow) -> None:
        req = flow.request

        if not self._in_scope(req):
            return
        if _is_static(req.path):
            return

        parsed = urlparse(req.pretty_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # GET query string 파라미터
        parameters = _params_as_list(parsed.query)

        # POST application/x-www-form-urlencoded 파라미터
        if req.method == "POST":
            ct = req.headers.get("content-type", "")
            if "application/x-www-form-urlencoded" in ct:
                try:
                    parameters += _params_as_list(req.text)
                except Exception:
                    pass

        cookies = _parse_cookies(req.headers.get("cookie", ""))

        record = {
            "method": req.method,
            "full_url": req.pretty_url,
            "base_url": base_url,
            "parameters": parameters,
            "cookies": cookies,
            "headers": dict(req.headers),
        }

        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

        print(f"[capture] {req.method} {req.pretty_url}  params={len(parameters)}")


addons = [CaptureAddon()]
