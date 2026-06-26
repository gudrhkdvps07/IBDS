import json
import os


class ResultWriter:
    # 출력 디렉토리 생성 및 파일 오픈 (실행마다 덮어씀)
    def __init__(self, path: str):
        parent = os.path.dirname(path) or "."  # 경로 없을 때 현재 디렉토리 처리
        os.makedirs(parent, exist_ok=True)
        self._f = open(path, "w", encoding="utf-8")

    # 결과 한 줄 JSONL 기록 및 즉시 flush
    def write(self, record: dict):
        self._f.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._f.flush()

    def close(self):
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
