import os
import urllib3

import requests

# PROXY_URL 환경변수가 설정된 경우 session에 mitmproxy 프록시를 적용
def apply_proxy(session: requests.Session) -> None:
    proxy_url = os.getenv("PROXY_URL", "")
    if not proxy_url:
        return

    session.proxies = {"http": proxy_url, "https": proxy_url}
    # mitmproxy 자체 인증서로 인한 SSL 검증 오류 억제
    session.verify = False
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    print(f"[PROXY] session proxied via {proxy_url}")
