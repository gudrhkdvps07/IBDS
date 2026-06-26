"""
크롤러 오케스트레이션

전체 크롤링 흐름을 실행하는 부분임
"""

import json
import os
import sys
import time
from collections import deque
from dataclasses import asdict
from datetime import datetime
from urllib.parse import parse_qs, urlparse
import requests
from dotenv import load_dotenv

from authentication.auth import LOGIN_URL, ensure_login_url, login as _do_login, make_session
from crawl.models import PageResult
from crawl.config import CrawlConfig
from crawl.url_filter import UrlFilter
from crawl.parser import HtmlParser
from crawl.input_tracker import InputTracker
from crawl.form_handler import FormHandler

load_dotenv()

BASE_URL = os.getenv("TARGET_URL", "http://localhost:8080")
_RUN_TS = datetime.now().strftime("%Y%m%d_%H%M%S")  # 이번 실행 시각을 파일에 넣기 위한 부분
OUTPUT_FILE = os.getenv("OUTPUT_FILE", f"results/run_{_RUN_TS}/crawl_result.json")


# 인증, 수집, 파싱, 저장을 담당하는 크롤러 클래스
class Crawler:
    def __init__(
        self,
        base_url: str = BASE_URL,
        init_cookies: dict | None = None,
        skip_auth: bool = False,
        proxy_host: str | None = None,
        proxy_port: int | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.session = make_session(proxy_host=proxy_host, proxy_port=proxy_port)
        self.init_cookies = init_cookies
        self.skip_auth = skip_auth
        self.auth_cookies: dict = {}
        self.visited: set[str] = set()
        self.queue: deque[str] = deque()
        self.results: list[PageResult] = []

        self.filter = UrlFilter(self.base_url)
        self.parser = HtmlParser()
        self.tracker = InputTracker(CrawlConfig.MIN_PAGES, CrawlConfig.STAGNATION_LIMIT)
        self.form_handler = FormHandler(self.session, CrawlConfig.TIMEOUT)

    # 로그인 수행 및 인증 쿠키 저장
    def login(self, login_url: str = "") -> bool:
        success, cookies = _do_login(self.session, url=login_url, base_url=self.base_url)
        if success:
            self.auth_cookies = cookies
        return success

    # URL 하나에 GET 요청을 보내고 응답 반환
    def _fetch(self, url: str) -> requests.Response | None:
        try:
            return self.session.get(url, timeout=CrawlConfig.TIMEOUT, allow_redirects=True) # 성공시 응답 반환
        except requests.RequestException as exc:
            print(f"[ERROR] 응답 실패 : {url} ({exc})", file=sys.stderr)
            return None

    # 외부 쿠키 또는 로그인 URL 기반 인증 준비
    def _prepare_auth(self) -> None:
        if self.skip_auth:
            return

        if self.init_cookies: # 쿠키 인증
            self.session.cookies.update(self.init_cookies)
            self.auth_cookies = dict(self.init_cookies)
            print(f"[AUTH] 인증 쿠키 사용 : {list(self.init_cookies.keys())}")
            return

        login_url = os.getenv("LOGIN_URL", LOGIN_URL) or ensure_login_url(self.base_url)
        if login_url: # 로그인 인증
            if not self.login(login_url):
                print("[WARN] 로그인 실패. guest로 계속합니다.", file=sys.stderr)
        else:
            print("[AUTH] login URL 찾기 실패. guest로 계속합니다.")


    # 응답 페이지에서 입력 구조와 링크 추출
    def _process_page(self, url: str, resp: requests.Response) -> PageResult:
        result = PageResult(url=url, status_code=resp.status_code)

        parsed_url = urlparse(url) # 구조별로 URL 나눔
        if parsed_url.query:       # 쿼리 있으면 dict로 바꿔 저장
            result.query_params = parse_qs(parsed_url.query, keep_blank_values=True)

        content_type = resp.headers.get("content-type", "") 
        if not self.parser.is_html(content_type, resp.text):  # 응답이 HTML인지 확인
            return result

        # HTML 본문에서 제목, 폼, 링크 추출
        parsed = self.parser.parse(resp.text, url)
        result.page_title = parsed.title

        found_new_input = False

        for form in parsed.forms:
            result.forms.append(asdict(form))
            if self.tracker.add_form(form): # 이 form 구조가 처음 보는 입력 구조인지 확인
                found_new_input = True
            submitted = self.form_handler.submit(form) # form 제출해보기
            if submitted is not None:  # 성공해서 응답 있으면
                norm = self.filter.normalize(submitted.url) # fragment 제거
                if norm not in self.visited: # 제출 결과로 이동한 URL이 있고, 아직 방문 안했으면 큐에 추가
                    self.queue.append(norm)

        # 위험 링크는 기록만 하고 방문 제외
        for raw_link in parsed.links:
            link = self.filter.normalize(raw_link)
            if not self.filter.can_visit(link):
                continue
            if self.filter.is_danger_link(link):
                result.danger_links.append({"url": link, "method": "GET", "reason": "danger_url"})
                continue
            result.links.append(link)
            if link not in self.visited:
                self.queue.append(link)

        if self.tracker.add_query_url(url):
            found_new_input = True

        self.tracker.update_stagnation(found_new_input)
        return result

    # 큐 기반 페이지 순회 및 크롤링 실행
    def crawl(self, extra_seeds: list[str] | None = None, progress_callback=None) -> list[PageResult]:
        self._prepare_auth()

        self.queue.append(self.filter.normalize(self.base_url + "/"))
        for seed in (extra_seeds or []):
            self.queue.append(seed)

        crawled = 0
        while self.queue and crawled < CrawlConfig.MAX_PAGES:
            url = self.filter.normalize(self.queue.popleft())

            if url in self.visited or not self.filter.can_visit(url):
                continue
            self.visited.add(url)

            print(f"[{crawled + 1:03d}] {url}")
            resp = self._fetch(url)
            if resp is None:
                crawled += 1
                continue

            result = self._process_page(url, resp)
            self.results.append(result)
            crawled += 1

            if progress_callback:
                progress_callback(crawled, CrawlConfig.MAX_PAGES)
            if self.tracker.should_stop(crawled):
                print("[STOP] 최근동안 새로운 입력 구조를 발견하지 못했습니다.")
                break
            time.sleep(CrawlConfig.DELAY)

        return self.results

    # 수집 결과 JSON 파일 저장
    def save(self, path: str = OUTPUT_FILE) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in self.results], f, ensure_ascii=False, indent=2)
        print(f"[CRAWLER] saved: {path}")

    # 수집 결과 요약 출력
    def summary(self) -> None:
        forms = sum(len(p.forms) for p in self.results)
        queries = sum(1 for p in self.results if p.query_params)
        print(f"[CRAWLER] pages={len(self.results)}, forms={forms}, query_pages={queries}")


if __name__ == "__main__":
    import os as _os
    from utilities.file_utils import load_json as _load_json
    from authentication.auth import get_auth_cookies as _get_auth_cookies

    # 단독 실행 시 target_config.json 기반 설정 로드
    _config = _load_json(
        _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "config", "target_config.json"), {}
    )
    _base_url = _config.get("target_url", BASE_URL)
    _init_cookies = _get_auth_cookies(_config.get("auth", {}), base_url=_base_url) or None

    crawler = Crawler(_base_url, init_cookies=_init_cookies)
    crawler.crawl()
    crawler.save(OUTPUT_FILE)
    crawler.summary()
