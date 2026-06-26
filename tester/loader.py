import json


# test case JSON 파일 로드 및 구조 검증
def load_cases(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):  # 최상위가 list인지 검증
        raise ValueError(f"Expected top-level list, got {type(data).__name__}")
    for i, case in enumerate(data):
        if not isinstance(case, dict):  # 각 케이스가 dict인지 검증
            raise ValueError(f"case[{i}] is not a dict (got {type(case).__name__})")
    return data
