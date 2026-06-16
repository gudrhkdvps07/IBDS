"""
크롤링결과와 프록시 결과 합치는 모듈
예전코드라 지금 쓰면 안됨.
"""
import argparse
import json
import re
import sys
from pathlib import Path

from utilities.file_utils import load_json, save_json

STATIC_EXT = re.compile(
    r"\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|pdf|zip|map)(\?|#|$)",
    re.IGNORECASE,
)


def _is_static(url: str) -> bool:
    return bool(STATIC_EXT.search(url))


# results/ 하위의 가장 최근 run_* 디렉터리를 반환
def _latest_run_dir() -> Path:
    runs = sorted(Path("results").glob("run_*"))
    if not runs:
        raise FileNotFoundError("results/run_* 디렉터리가 없습니다.")
    return runs[-1]


# (base_url, method) 기준 중복 제거 — 마지막 항목 유지
def load_captured_requests(path: Path) -> list[dict]:
    seen: dict[tuple, dict] = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            req = json.loads(line)
            key = (req["base_url"], req["method"].upper())
            seen[key] = req
    return list(seen.values())



def _build_crawl_index(pages: list[dict]) -> tuple[dict, dict]:
    """
    반환값:
      url_index  — {page_url: page}            (크롤러가 방문한 URL 기준)
      form_index — {(form_action, METHOD): fields}  (폼 액션 URL 기준)
    """
    url_index: dict[str, dict] = {}
    form_index: dict[tuple, list] = {}

    for page in pages:
        url_index[page["url"]] = page
        for form in page.get("forms", []):
            key = (form["action"], form["method"].upper())
            # 같은 키가 여러 번 나오면 마지막 것 유지 (captured_requests와 동일 정책)
            form_index[key] = form.get("fields", [])

    return url_index, form_index


def find_form_fields(base_url: str, method: str, url_index: dict, form_index: dict) -> list:
    # 1. 크롤러가 그 URL을 직접 방문한 경우 ->  같은 URL의 폼에서 찾기
    page = url_index.get(base_url)
    if page:
        for form in page.get("forms", []):
            if form["method"].upper() == method:
                return form.get("fields", [])

    # 2. 다른 페이지의 폼 액션이 base_url과 일치하는 경우
    return form_index.get((base_url, method), [])


def build_scan_targets(crawl_path: Path, requests_path: Path) -> list[dict]:
    pages = load_json(str(crawl_path), default=[])
    url_index, form_index = _build_crawl_index(pages)

    requests = load_captured_requests(requests_path)

    targets = []
    for req in requests:
        base_url: str = req["base_url"]
        method: str = req["method"].upper()

        if _is_static(base_url):
            continue

        parameters: list = req.get("parameters", [])
        if not parameters:
            continue

        form_fields = find_form_fields(base_url, method, url_index, form_index)

        targets.append({
            "base_url": base_url,
            "method": method,
            "parameters": parameters,
            "cookies": req.get("cookies", {}),
            "headers": req.get("headers", {}),
            "form_fields": form_fields,
        })

    return targets


def main() -> None:
    parser = argparse.ArgumentParser(description="crawl_result + captured_requests → scan_targets")
    parser.add_argument("--crawl",    help="crawl_result.json 경로")
    parser.add_argument("--requests", help="captured_requests.jsonl 경로")
    parser.add_argument("--output",   help="출력 파일 경로 (기본: <run_dir>/scan_targets.json)")
    args = parser.parse_args()

    # 경로가 명시되지 않으면 가장 최근 run 디렉터리에서 자동 탐색
    if args.crawl or args.requests:
        crawl_path    = Path(args.crawl)    if args.crawl    else Path("crawl_result.json")
        requests_path = Path(args.requests) if args.requests else Path("captured_requests.jsonl")
        run_dir = crawl_path.parent
    else:
        run_dir       = _latest_run_dir()
        crawl_paths   = list(run_dir.glob("crawl_result*.json"))
        request_paths = list(run_dir.glob("captured_requests*.jsonl"))
        if not crawl_paths:
            print(f"[ERROR] {run_dir} 에 crawl_result*.json 없음", file=sys.stderr)
            sys.exit(1)
        if not request_paths:
            print(f"[ERROR] {run_dir} 에 captured_requests*.jsonl 없음", file=sys.stderr)
            sys.exit(1)
        crawl_path    = crawl_paths[-1]
        requests_path = request_paths[-1]

    output_path = Path(args.output) if args.output else run_dir / "scan_targets.json"

    if not crawl_path.exists():
        print(f"[ERROR] 파일 없음: {crawl_path}", file=sys.stderr)
        sys.exit(1)
    if not requests_path.exists():
        print(f"[ERROR] 파일 없음: {requests_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] crawl   : {crawl_path}")
    print(f"[INFO] requests: {requests_path}")

    targets = build_scan_targets(crawl_path, requests_path)
    save_json(str(output_path), targets)

    print(f"[INFO] {len(targets)}개 스캔 타겟 → {output_path}")


if __name__ == "__main__":
    main()
