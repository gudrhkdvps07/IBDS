import re
from urllib.parse import urlparse

from crawl.config import EXCLUDE_PATTERNS, DANGER_LINK_PATTERNS


# 크롤링 대상 URL의 범위와 위험도를 판별하는 클래스
class UrlFilter:
    def __init__(self, base_url: str):
        self._parsed_base = urlparse(base_url.rstrip("/"))

    # fragment를 제거한 표준 URL 생성
    def normalize(self, url: str) -> str:
        return urlparse(url)._replace(fragment="").geturl()

    # base_url과 같은 호스트인지 확인
    def is_in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and parsed.netloc == self._parsed_base.netloc

    # 정적 파일 또는 로그아웃 등 제외 대상 확인
    def is_excluded(self, url: str) -> bool:
        return any(re.search(p, url, re.IGNORECASE) for p in EXCLUDE_PATTERNS)

    # GET 링크만으로 변경 요청이 발생할 가능성 확인
    def is_danger_link(self, url: str) -> bool:
        parsed = urlparse(url)
        target = f"{parsed.path}?{parsed.query}"
        return any(re.search(p, target, re.IGNORECASE) for p in DANGER_LINK_PATTERNS)

    # 방문 가능한 URL 여부 확인
    def can_visit(self, url: str) -> bool:
        return self.is_in_scope(url) and not self.is_excluded(url)