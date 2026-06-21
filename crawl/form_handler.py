"""
발견된 Form을 제출할지 결정 및 요청 수행부

GET form일 경우 제출하고
POST form일 경우 제출하지 않고 수집만 진행함. 
"""

from urllib.parse import urlparse, urlunparse
import requests

from crawl.models import Form


# 폼 제출 방식을 제한적으로 처리하는 클래스
class FormHandler:
    def __init__(
        self,
        session: requests.Session,
        timeout: int,
        submit_post_forms: bool = False, # POST 요청은 날리지 않음
    ):
        self.session = session
        self.timeout = timeout
        self.submit_post_forms = submit_post_forms 

    # 폼 method와 설정에 따른 제출 처리
    def submit(self, form: Form) -> requests.Response | None:
        payload = {f.name: f.value for f in form.fields if f.name}
        if not payload:
            return None

        if form.method == "GET":
            return self._submit_get(form.action, payload)

        if form.method == "POST" and self.submit_post_forms:
            return self._submit_post(form, payload)

        return None

    # GET 폼 제출 요청부분
    def _submit_get(self, action: str, payload: dict) -> requests.Response | None:
        clean_action = urlunparse(urlparse(action)._replace(query="", fragment=""))
        try:
            return self.session.get(clean_action, params=payload, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException:
            return None

    # POST 폼 제출 요청부분
    def _submit_post(self, form: Form, payload: dict) -> requests.Response | None:
        if "multipart/form-data" in form.enctype:
            return None
        try:
            return self.session.post(form.action, data=payload, timeout=self.timeout)
        except requests.RequestException:
            return None
