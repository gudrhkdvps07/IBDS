import json
import os
import urllib3
import requests

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_CONFIG_PATH = os.path.join(_PROJECT_ROOT, "config", "proxy_config.json")


def _load_proxy_config(config_path: str = _DEFAULT_CONFIG_PATH) -> dict:
    try:
        with open(config_path, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

# 프록시 URL 생성
def build_proxy_url(
    host: str | None = None,
    port: int | None = None,
    config_path: str = _DEFAULT_CONFIG_PATH,
) -> str:
    
    """
    URL 생성시 우선순위:
    1. 함수 인자 host / port
    2. config/proxy_config.json
    3. 환경변수 DEFAULT_PROXY_HOST / DEFAULT_PROXY_PORT
    4. 기본값 127.0.0.1:8081
    """

    cfg = _load_proxy_config(config_path)

    if not cfg.get("enabled", True):
        return ""

    resolved_host = host or cfg.get("host") or os.getenv("DEFAULT_PROXY_HOST", "127.0.0.1")
    resolved_port = port or cfg.get("port") or int(os.getenv("DEFAULT_PROXY_PORT", "8081"))

    return f"http://{resolved_host}:{resolved_port}"


def apply_proxy(
    session: requests.Session,
    host: str | None = None,
    port: int | None = None,
) -> None:
    proxy_url = build_proxy_url(host=host, port=port)
    if not proxy_url:
        return

    session.proxies = {"http": proxy_url, "https": proxy_url}
    session.verify = False
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    print(f"[PROXY] session proxied via {proxy_url}")
