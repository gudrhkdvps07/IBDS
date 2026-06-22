"""
이미 뽑힌 form, query구조가 처음 보는 구조인지 확인
"""

from urllib.parse import parse_qs, urlparse
from crawl.models import Form


# 입력 구조 중복 여부와 정체 상태를 추적하는 클래스
class InputTracker:
    def __init__(self, min_pages: int, stagnation_limit: int):
        self.min_pages = min_pages
        self.stagnation_limit = stagnation_limit
        self._seen: set[tuple] = set()
        self._no_new_input_pages = 0

    # 신규 폼 구조 등록 여부 반환
    def add_form(self, form: Form) -> bool:
        sig = self._form_signature(form)
        before = len(self._seen)
        self._seen.add(sig)
        return len(self._seen) > before

    # 신규 쿼리 파라미터 구조 등록 여부 반환
    def add_query_url(self, url: str) -> bool:
        sig = self._query_signature(url)
        if not sig:
            return False
        before = len(self._seen)
        self._seen.add(sig)
        return len(self._seen) > before

    # 새 입력 구조가 없는 페이지가 연속으로 몇 개였는지 세는 부분
    def update_stagnation(self, found_new: bool) -> None:
        if found_new:
            self._no_new_input_pages = 0
        else:
            self._no_new_input_pages += 1

    # 최소 페이지 이후 새로운 입력구조 미발견될 경우 stop
    def should_stop(self, crawled: int) -> bool:
        return crawled >= self.min_pages and self._no_new_input_pages >= self.stagnation_limit

    # 폼 구조 비교용 서명 생성
    def _form_signature(self, form: Form) -> tuple:
        parsed = urlparse(form.action)
        return (
            "FORM",
            form.method.upper(),
            parsed.path or form.action,
            tuple(sorted(f.name for f in form.fields if f.name)),
        )

    # URL 쿼리 구조 비교용 서명 생성
    def _query_signature(self, url: str) -> tuple | None:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return None
        return ("QUERY", "GET", parsed.path or "/", tuple(sorted(params.keys())))
