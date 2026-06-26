from http_executor import HttpExecutor


# 엔진 타입에 따라 라우팅
class Router:
    def __init__(self, response_store=None):
        self._http = HttpExecutor(response_store=response_store)
        # browser executor는 구현 시 추가

    def execute(self, case: dict) -> dict:
        engine = case.get("engine")
        if engine == "http":
            return self._http.execute(case)
        # if engine == "browser":
        #     return self._browser.execute(case)
        return {
            "case_id": case.get("case_id"),
            "target_id": case.get("target_id"),
            "test_type": case.get("test_type"),
            "engine": engine,
            "role": case.get("role"),
            "request": None,
            "response": None,
            "error": None,
            "skipped": True,
            "skip_reason": f"지원하지 않는 엔진입니다.: {engine!r}",
        }

    def close(self):
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
