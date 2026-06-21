import json
import re
from pathlib import Path
from urllib.parse import urlparse

from crawl.config import DANGER_LINK_PATTERNS
from utilities.file_utils import load_json, save_json

# 정적파일 정규식
_STATIC_EXT = re.compile(
    r"\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|pdf|zip|map)(\?|#|$)",
    re.IGNORECASE,
)


def _is_static(url: str) -> bool:
    return bool(_STATIC_EXT.search(url))


def _is_danger(url: str) -> bool:
    parsed = urlparse(url)
    target = f"{parsed.path}?{parsed.query}"
    return any(re.search(p, target, re.IGNORECASE) for p in DANGER_LINK_PATTERNS)


# 크롤링 결과 불러오기
# 크롤러가 방문한 URL에서 METHOD, action, form, danger_url들을 가져옴
def _load_crawl(crawl_path: Path) -> tuple[dict, set, set]:
    pages = load_json(str(crawl_path), default=[])
    form_index: dict[tuple, list] = {}
    danger_urls: set[str] = set()
    crawl_urls: set[str] = set()

    for page in pages:
        crawl_urls.add(page["url"])
        for dl in page.get("danger_links", []):
            danger_urls.add(dl["url"])
        for form in page.get("forms", []):
            key = (form["action"], form["method"].upper())
            form_index[key] = form.get("fields", [])

    return form_index, danger_urls, crawl_urls


# 프록시 결과 불러오기
def _load_proxy(proxy_path: Path) -> dict[tuple, list]:
    groups: dict[tuple, list] = {}

    if not proxy_path.exists():
        print(f"[WARN] proxy snapshot 없음: {proxy_path}")
        return groups

    with open(proxy_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not rec.get("parameters"): # 파라미터 없으면 제외
                continue
            if _is_static(rec.get("base_url", "")): # 정적 요청일 경우 제외
                continue

            key = (rec["method"].upper(), rec["base_url"])
            groups.setdefault(key, []).append(rec)

    return groups


# URL이 위험 패턴에 해당하는지 판단하고 결과 반환
def _make_danger_result(url: str, danger_urls: set) -> tuple[bool, list, str | None]:
    is_danger = url in danger_urls or _is_danger(url)
    return (
        not is_danger,
        ["danger_url"] if is_danger else [],
        "danger_url pattern matched" if is_danger else None,
    )


# 프록시, 크롤 결과를 합치기
def _build_targets(
    proxy_groups: dict[tuple, list],
    form_index: dict[tuple, list],
    danger_urls: set[str],
    crawl_urls: set[str],
) -> list[dict]:
    targets: list[dict] = []
    processed_keys: set[tuple] = set()

    # 프록시에서 잡힌 요청들
    for (method, base_url), records in proxy_groups.items():
        processed_keys.add((method, base_url))

        all_param_names: set[str] = set()
        seen_requests: list[dict] = []

        for rec in records:
            params = rec.get("parameters", [])
            names = [p["name"] for p in params if p.get("name")]
            values = {p["name"]: p.get("value", "") for p in params if p.get("name")}
            if not names:
                continue
            all_param_names.update(names)
            seen_requests.append({
                "full_url": rec.get("full_url", base_url),
                "param_names": names,
                "sample_values": values,
            })

        if not all_param_names:
            continue

        in_crawl = base_url in crawl_urls or (base_url, method) in form_index
        source = ["proxy", "crawl"] if in_crawl else ["proxy"]
        form_fields = form_index.get((base_url, method), [])

        # 파라미터가 가장 많은 요청을 대표 cookies/headers로 사용
        best = max(records, key=lambda r: len(r.get("parameters", [])))

        can_scan, risk_tags, skip_reason = _make_danger_result(base_url, danger_urls)

        targets.append({
            "base_url": base_url,
            "method": method,
            "parameters": sorted(all_param_names),
            "form_fields": form_fields,
            "cookies": best.get("cookies", {}),
            "headers": best.get("headers", {}),
            "source": source,
            "can_scan": can_scan,
            "risk_tags": risk_tags,
            "skip_reason": skip_reason,
            "seen_requests": seen_requests,
        })

    # 크롤 전용 폼 타겟 (프록시에 안 잡힌 폼, 주로 POST)
    for (action_url, method), fields in form_index.items():
        if (method, action_url) in processed_keys:
            continue

        input_fields = [f for f in fields if f.get("field_type") != "submit"]
        param_names = [f["name"] for f in input_fields if f.get("name")]
        if not param_names:
            continue

        can_scan, risk_tags, skip_reason = _make_danger_result(action_url, danger_urls)

        targets.append({
            "base_url": action_url,
            "method": method,
            "parameters": param_names,
            "form_fields": fields,
            "cookies": {},
            "headers": {},
            "source": ["crawl"],
            "can_scan": can_scan,
            "risk_tags": risk_tags,
            "skip_reason": skip_reason,
            "seen_requests": [],
        })

    return targets



def merge(session_dir: Path) -> list[dict]:
    crawl_path = session_dir / "crawl_result.json"
    proxy_path = session_dir / "proxy_history_snapshot.jsonl"

    form_index, danger_urls, crawl_urls = _load_crawl(crawl_path)
    proxy_groups = _load_proxy(proxy_path)
    return _build_targets(proxy_groups, form_index, danger_urls, crawl_urls)


def _latest_session_dir() -> Path:
    sessions = sorted(Path("results/sessions").glob("session_*"))
    if not sessions:
        raise FileNotFoundError("results/sessions/session_* 디렉터리가 없습니다.")
    return sessions[-1]


if __name__ == "__main__":
    session_dir = _latest_session_dir()
    output_path = session_dir / "scan_targets.json"

    print(f"[MERGE] session dir : {session_dir}")

    targets = merge(session_dir)
    save_json(str(output_path), targets)

    scannable = sum(1 for t in targets if t["can_scan"])
    skipped = len(targets) - scannable
    print(f"[MERGE] targets={len(targets)}  can_scan={scannable}  skipped={skipped}")
    print(f"[MERGE] → {output_path}")
