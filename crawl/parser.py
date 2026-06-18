from urllib.parse import urljoin
from bs4 import BeautifulSoup  # type: ignore[reportMissingModuleSource]

from crawl.models import Form, FormField, ParsedPage


# HTML 문서에서 폼과 링크를 추출하는 파서 클래스
class HtmlParser:
    # 응답이 HTML 문서인지 판별
    def is_html(self, content_type: str, body: str) -> bool:
        return "html" in content_type.lower() or "<html" in body[:500].lower()

    # HTML 문자열을 ParsedPage 구조로 변환
    def parse(self, html: str, page_url: str) -> ParsedPage:
        soup = BeautifulSoup(html, "lxml")
        return ParsedPage(
            title=self._parse_title(soup),
            forms=self._parse_forms(soup, page_url),
            links=self._parse_links(soup, page_url),
        )

    # title 태그 텍스트 추출
    def _parse_title(self, soup: BeautifulSoup) -> str:
        tag = soup.find("title")
        return tag.get_text(strip=True) if tag else ""

    # form 태그와 하위 입력 필드 추출
    def _parse_forms(self, soup: BeautifulSoup, page_url: str) -> list[Form]:
        forms = []
        for form_tag in soup.find_all("form"):
            action = urljoin(page_url, form_tag.get("action") or page_url)
            method = (form_tag.get("method") or "GET").upper()
            enctype = form_tag.get("enctype") or "application/x-www-form-urlencoded"

            fields = []
            for inp in form_tag.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                # select 태그의 선택지 값 수집
                options = (
                    [opt.get("value", opt.text.strip()) for opt in inp.find_all("option")]
                    if inp.name == "select"
                    else []
                )
                fields.append(FormField(
                    name=name,
                    field_type=inp.get("type") or inp.name,
                    value=inp.get("value", ""),
                    options=options,
                ))

            forms.append(Form(action=action, method=method, fields=fields, enctype=enctype))
        return forms

    # a 태그 href를 절대 URL 목록으로 변환
    def _parse_links(self, soup: BeautifulSoup, page_url: str) -> list[str]:
        return [urljoin(page_url, a["href"]) for a in soup.find_all("a", href=True)]
