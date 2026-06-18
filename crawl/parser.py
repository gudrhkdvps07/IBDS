import re
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
        base_url = self._resolve_base_url(soup, page_url)
        return ParsedPage(
            title=self._parse_title(soup),
            forms=self._parse_forms(soup, base_url),
            links=self._parse_links(soup, base_url),
        )

    # <base href>가 있으면 상대 URL 해석 기준을 해당 URL로 교체
    def _resolve_base_url(self, soup: BeautifulSoup, page_url: str) -> str:
        tag = soup.find("base", href=True)
        return urljoin(page_url, tag["href"]) if tag else page_url

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

    # 페이지 내 모든 URL 수집 (a, link, script, iframe, img, meta refresh)
    def _parse_links(self, soup: BeautifulSoup, page_url: str) -> list[str]:
        urls = []

        for tag in soup.find_all("a", href=True):
            urls.append(urljoin(page_url, tag["href"]))

        for tag in soup.find_all("link", href=True):
            urls.append(urljoin(page_url, tag["href"]))

        for tag in soup.find_all("script", src=True):
            urls.append(urljoin(page_url, tag["src"]))

        for tag in soup.find_all("iframe", src=True):
            urls.append(urljoin(page_url, tag["src"]))

        for tag in soup.find_all("img", src=True):
            urls.append(urljoin(page_url, tag["src"]))

        # <meta http-equiv="refresh" content="5; url=...">
        for tag in soup.find_all("meta", attrs={"http-equiv": re.compile(r"^refresh$", re.I)}):
            url = self._parse_meta_refresh(tag.get("content", ""), page_url)
            if url:
                urls.append(url)

        # TODO: button[formaction], button[formmethod] - 나중에 주입할때 확장 추가 하면 어떨까 싶음

        return urls

    # meta refresh content 에서 URL 파싱
    def _parse_meta_refresh(self, content: str, page_url: str) -> str | None:
        match = re.search(r"url\s*=\s*['\"]?([^'\";\s]+)", content, re.IGNORECASE)
        return urljoin(page_url, match.group(1)) if match else None
