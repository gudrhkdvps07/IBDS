import json
import os


class ResultWriter:
    def __init__(self, path: str):
        parent = os.path.dirname(path) or "."
        os.makedirs(parent, exist_ok=True)
        self._f = open(path, "w", encoding="utf-8")

    def write(self, record: dict):
        self._f.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._f.flush()

    def close(self):
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
