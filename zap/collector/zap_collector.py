import re
import time

from zapv2 import ZAPv2

from utilities.file_utils import load_json

SESSION_NAME = "IBDSSession"
CONTEXT_NAME = "IBDSContext"
_COOKIE_RULE_DESC = "ibds-cookie-inject"


# ZAP 수집 인프라 래퍼 (세션/Context/Spider만 담당, Active Scan 없음)
class ZapCollector:
    def __init__(self, host="127.0.0.1", port=8081, api_key="changeme"):
        proxies = {"http": f"http://{host}:{port}", "https": f"http://{host}:{port}"}
        self.zap = ZAPv2(proxies=proxies, apikey=api_key)

    @classmethod
    def from_config(cls, config_path):
        cfg = load_json(config_path, default={})
        return cls(
            host=cfg.get("host", "127.0.0.1"),
            port=cfg.get("port", 8081),
            api_key=cfg.get("api_key", "changeme"),
        )

    # 이전 실행 기록이 섞이지 않도록 매 실행마다 세션 새로 생성
    def new_session(self, name=SESSION_NAME):
        self.zap.core.new_session(name=name, overwrite=True)
        print(f"[ZAP] 세션 생성: {name}")

    # target 도메인 외 트래픽을 프록시 단에서 전역 제외 (범위 축소용, 위험 URL 필터링과는 별개)
    def restrict_to_target_domain(self, target_url: str):
        regex = f"^(?:(?!{re.escape(target_url)}).)*$"
        self.zap.core.exclude_from_proxy(regex=regex)
        print(f"[ZAP] 전역 제외(target 외부 도메인): {regex}")

    # Context 생성 + target include 등록
    def setup_context(self, target_url: str, name=CONTEXT_NAME) -> str:
        context_id = self.zap.context.new_context(contextname=name)
        include_regex = f"{target_url}.*"
        self.zap.context.include_in_context(contextname=name, regex=include_regex)
        print(f"[ZAP] Context 생성: {name} (id={context_id}), include: {include_regex}")
        return context_id

    # logout/reset/delete 등 위험 URL을 Context에서 제외, Spider 실행 전 필수 호출
    def exclude_danger_urls(self, patterns: list[str], name=CONTEXT_NAME):
        for pattern in patterns:
            self.zap.context.exclude_from_context(contextname=name, regex=pattern)
        print(f"[ZAP] Context 위험 URL 제외 {len(patterns)}건 등록")

    # 로그인 세션 쿠키를 모든 프록시 요청 헤더에 주입 (Replacer 룰, 인증 Context 미사용)
    def set_session_cookie(self, cookies: dict):
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        self.zap.replacer.add_rule(
            description=_COOKIE_RULE_DESC, enabled=True,
            matchtype="REQ_HEADER", matchregex=False,
            matchstring="Cookie", replacement=cookie_str,
        )

    def clear_session_cookie(self):
        self.zap.replacer.remove_rule(description=_COOKIE_RULE_DESC)

    # ZAP 사이트 트리에 target 직접 접근 등록 (Spider 시작 전 준비)
    def access_target(self, target_url: str):
        self.zap.core.access_url(url=target_url, followredirects=True)
        time.sleep(2)  # 사이트 트리 반영 대기

    # Spider 실행, 완료(100%)까지 폴링
    def run_spider(self, target_url: str, context_name=CONTEXT_NAME):
        scan_id = self.zap.spider.scan(url=target_url, recurse=True, contextname=context_name)
        time.sleep(2)
        while int(self.zap.spider.status(scan_id)) < 100:
            print(f"\r[SPIDER] {self.zap.spider.status(scan_id)}%", end="", flush=True)
            time.sleep(2)
        print("\r[SPIDER] 100% 완료")

    # Ajax Spider 실행 (payload 전송기가 아닌 JS 기반 요청 발견용), stopped까지 폴링
    def run_ajax_spider(self, target_url: str):
        self.zap.ajaxSpider.scan(url=target_url, inscope=True)
        time.sleep(2)
        while self.zap.ajaxSpider.status != "stopped":
            print(f"\r[AJAX SPIDER] {self.zap.ajaxSpider.status}", end="", flush=True)
            time.sleep(2)
        print("\r[AJAX SPIDER] stopped")

    # raw 메시지 일부만 조회 (필드 구조 확인용)
    def get_messages_sample(self, base_url: str, count=3):
        return self.zap.core.messages(baseurl=base_url, start=0, count=count)

    # 전체 메시지 조회 (페이지네이션)
    def get_all_messages(self, base_url: str, page_size=200):
        all_msgs, start = [], 0
        while True:
            batch = self.zap.core.messages(baseurl=base_url, start=start, count=page_size)
            all_msgs.extend(batch)
            if len(batch) < page_size:
                break
            start += page_size
        return all_msgs
