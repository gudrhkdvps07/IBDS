import json


def load_cases(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError(f"Expected top-level list, got {type(data).__name__}")
    for i, case in enumerate(data):
        if not isinstance(case, dict):
            raise ValueError(f"case[{i}] is not a dict (got {type(case).__name__})")
    return data
