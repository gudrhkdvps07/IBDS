from dataclasses import dataclass, field


# 폼 입력 필드 데이터 구조
@dataclass
class FormField:
    name: str
    field_type: str
    value: str = ""
    options: list[str] = field(default_factory=list)


# HTML 폼 데이터 구조
@dataclass
class Form:
    action: str
    method: str
    fields: list[FormField] = field(default_factory=list)
    enctype: str = "application/x-www-form-urlencoded"


# 파싱된 페이지 데이터 구조
@dataclass
class ParsedPage:
    title: str
    forms: list[Form]
    links: list[str]


# 크롤링 결과 저장 데이터 구조
@dataclass
class PageResult:
    url: str
    status_code: int
    role: str = ""
    forms: list[dict] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    danger_links: list[dict] = field(default_factory=list)
    query_params: dict = field(default_factory=dict)
    page_title: str = ""
    is_error_page: bool = False
