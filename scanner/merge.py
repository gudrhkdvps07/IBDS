import json
import re
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from utilities.file_utils import load_json, save_json
from core.session_context import latest_session_dir


_STATIC_EXT = re.compile(
    r"\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|pdf|zip|map)(\?|#|$)",
    re.IGNORECASE,
)


""" 
위험 키워드 -> risk tag 매핑
path, 파라미터 이름, 파라미터 값에서 키워드 탐지 후 태그 부여
여기는 계속 수정이 필요할듯.. 어떻게 해야 될까

태그 설명
    setup : DB 초기화 혹은 설치 페이지 가능성
    state_changing_action : 데이터 삭제 혹은 변조 가능성
    session_action: 세션 종료
    account_modification: 계정 정보 변경
    file_upload: 파일 업로드
    security_setting_change: 보안 설정 변경
    payment_action: 결제, 출금
"""
_DANGER_MAP: dict[str, list[str]] = {
    "setup": ["setup", "state_changing_action"], # 고민중
    "install": ["setup", "state_changing_action"],
    "reset": ["setup", "state_changing_action"],
    "clear": ["state_changing_action"],
    "delete": ["state_changing_action"],
    "remove": ["state_changing_action"],
    "drop": ["state_changing_action"],
    "truncate": ["state_changing_action"],
    "create_db": ["state_changing_action"],
    "logout": ["session_action"],   # 고민중
    "upload": ["file_upload"],      # 고민중
    "file_upload": ["file_upload"], # 고민중
    "upload_file": ["file_upload"], #  고민중
    # "security": ["security_setting_change"], # 고민중
    "phpids": ["security_setting_change"],
    "payment": ["payment_action"],
    "withdraw": ["payment_action"],
    "current_password": ["account_modification"],
    "change_password": ["account_modification"],
    "new_password": ["account_modification"],
    "password_new": ["account_modification"],
    "password_config": ["account_modification"],
    "password_conf": ["account_modification"],
}


# scan=false 처리 대상인 필드타입
_NOSCAN_FIELD_TYPES = {"submit", "hidden", "file"}

# scan=false 처리 대상 파라미터 이름 키워드
_NOSCAN_NAME_KEYWORDS = {"token", "csrf"}

# 프록시로 관찰된 요청 샘플 최대 보존 개수
_MAX_SEEN = 5


def _normalize_url(url: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))


# 정적 파일 URL 여부 판별
def _is_static(url: str) -> bool:
    return bool(_STATIC_EXT.search(url))


# field_type이 submit/hidden/file이거나 이름에 token/csrf 포함 시 스캔 대상에서 제외
def _param_scannable(name: str, field_type: str) -> bool:
    if field_type in _NOSCAN_FIELD_TYPES:
        return False
    name_lower = name.lower()
    return not any(kw in name_lower for kw in _NOSCAN_NAME_KEYWORDS)


# path + 파라미터 이름, 값 전체에서 위험 키워드 탐지 후 risk tag 목록 반환
def _collect_risk_tags(path: str, params: list[dict]) -> list[str]:
    tags: set[str] = set()
    texts = [path.lower()]
    for p in params:
        texts.append(p.get("name", "").lower())
        for v in p.get("sample_values", []):
            texts.append(str(v).lower())
        if p.get("field_type") == "file":
            tags.add("file_upload")
    combined = " ".join(texts)
    for keyword, risk_tags in _DANGER_MAP.items():
        if keyword in combined:
            tags.update(risk_tags)
    return sorted(tags)


# crawl form fields -> parameter 객체 배열 변환
def _form_to_params(fields: list[dict], method: str) -> list[dict]:
    location = "query" if method.upper() == "GET" else "body"
    params = []
    for f in fields:
        name = f.get("name", "")
        if not name:
            continue
        field_type = f.get("field_type", "text")
        value = f.get("value", "")
        params.append({
            "name": name,
            "request_location": location,
            "field_type": field_type,
            "sample_values": [value] if value is not None else [],
            "sources": ["crawl"],
            "scan": _param_scannable(name, field_type),
        })
    return params


# proxy 레코드 -> parameter 객체 배열 변환
def _proxy_rec_to_params(rec: dict) -> list[dict]:
    method = rec.get("method", "GET").upper()
    default_location = "query" if method == "GET" else "body"  # location 없을경우 fallback
    params = []
    for p in rec.get("parameters", []):
        name = p.get("name", "")
        if not name:
            continue
        value = p.get("value", "")
        location = p.get("request_location", default_location)  # capture.py가 기록한 location 우선
        params.append({
            "name": name,
            "request_location": location,
            "field_type": "text",  # 프록시만 캡쳐한 경우, field_type 정보가 없으므로 text로 고정
            "sample_values": [value] if value is not None else [],
            "sources": ["proxy"],
            "scan": _param_scannable(name, "text"),
        })
    return params


# name, location 기준 파라미터 병합
def _merge_params(base: list[dict], incoming: list[dict]) -> list[dict]:
    index: dict[tuple, dict] = {(p["name"], p["request_location"]): p for p in base}
    for p in incoming:
        key = (p["name"], p["request_location"])
        if key in index: # 중복 시 sources, sample_values 합산
            ex = index[key]
            for s in p.get("sources", []):
                if s not in ex["sources"]:
                    ex["sources"].append(s)
            for v in p.get("sample_values", []):
                if v not in ex["sample_values"]: 
                    ex["sample_values"].append(v)
            ex["scan"] = ex["scan"] and p.get("scan", True) # crawl이 hidden/submit으로 판별한 경우 scan=False 유지
        else:
            index[key] = dict(p)
    return list(index.values())


# 프록시 레코드에서 role 추론
def _infer_role(rec: dict, url_roles: dict, norm_url: str) -> str:
    roles = url_roles.get(norm_url)
    if roles and len(roles) == 1:
        return next(iter(roles)) # url_roles에 단일 role이면 그대로 사용
    return "member" if rec.get("cookies") else "guest" # 복수이거나 없으면 쿠키 유무로 판별



def _load_crawl(crawl_path: Path) -> tuple[dict, set, dict, dict]:
    pages = load_json(str(crawl_path), default=[])
    form_index: dict[tuple, list[dict]] = {}
    danger_urls: set[str] = set()
    url_roles: dict[str, set] = {}
    form_meta: dict[tuple, dict] = {}  # enctype 보존용

    for page in pages:
        page_url = page.get("url", "")
        role = page.get("role", "guest")
        norm_url = _normalize_url(page_url)
        url_roles.setdefault(norm_url, set()).add(role)

        for dl in page.get("danger_links", []):
            danger_urls.add(_normalize_url(dl.get("url", "")))

        for form in page.get("forms", []):
            action = form.get("action") or page_url
            method = form.get("method", "GET").upper()
            norm_action = _normalize_url(action)
            url_roles.setdefault(norm_action, set()).add(role)

            key = (role, method, norm_action)
            incoming = _form_to_params(form.get("fields", []), method)
            form_index[key] = _merge_params(form_index.get(key, []), incoming)
            form_meta[key] = {"enctype": form.get("enctype", "application/x-www-form-urlencoded")}

    return form_index, danger_urls, url_roles, form_meta



def _load_proxy(proxy_path: Path, url_roles: dict) -> dict[tuple, list]:
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

            if not rec.get("parameters"):
                continue
            base_url = rec.get("base_url", "")
            if _is_static(base_url):
                continue

            norm_url = _normalize_url(base_url)
            method = rec.get("method", "GET").upper()
            role = _infer_role(rec, url_roles, norm_url)

            key = (role, method, norm_url)
            groups.setdefault(key, []).append(rec)

    return groups



# crawl + proxy 결과 통합 후 스캔 타겟 목록 생성
def _build_targets(
    proxy_groups: dict[tuple, list],
    form_index: dict[tuple, list],
    danger_urls: set[str],
    form_meta: dict[tuple, dict],
) -> list[dict]:
    targets: list[dict] = []

    for key in set(proxy_groups) | set(form_index):
        role, method, norm_url = key
        params: list[dict] = []
        sources: list[str] = []
        seen_requests: list[dict] = []
        cookies: dict = {}
        headers: dict = {}

        if key in form_index:
            params = _merge_params(params, form_index[key])
            sources.append("crawl")

        if key in proxy_groups:
            seen_full_urls: set[str] = set()
            best_rec = None

            for rec in proxy_groups[key]:
                full_url = rec.get("full_url", norm_url)
                if full_url not in seen_full_urls and len(seen_requests) < _MAX_SEEN:
                    seen_full_urls.add(full_url)
                    seen_requests.append({"full_url": full_url, "method": rec.get("method", method)})

                params = _merge_params(params, _proxy_rec_to_params(rec))

                # 파라미터가 가장 많은 레코드를 대표 cookies/headers로 사용
                if best_rec is None or len(rec.get("parameters", [])) > len(best_rec.get("parameters", [])):
                    best_rec = rec

            if best_rec:
                cookies = best_rec.get("cookies", {})
                headers = best_rec.get("headers", {})
            sources.append("proxy")

        if not params:
            continue

        path = urlparse(norm_url).path
        risk_tags = _collect_risk_tags(path, params)
        is_danger_url = norm_url in danger_urls
        if is_danger_url and not risk_tags:
            risk_tags = ["danger_url"]
        is_danger = is_danger_url or bool(risk_tags)
        enctype = form_meta.get(key, {}).get("enctype", "application/x-www-form-urlencoded")

        targets.append({
            "role": role,
            "base_url": norm_url,
            "method": method,
            "enctype": enctype,
            "parameters": params,
            "cookies": cookies,
            "headers": headers,
            "sources": sorted(set(sources)),
            "can_scan": not is_danger,
            "risk_tags": risk_tags,
            "skip_reason": "risk_tags: " + ",".join(risk_tags) if is_danger else None,
            "seen_requests": seen_requests,
        })

    return targets


# 세션 디렉터리를 받아 crawl + proxy 결과를 합한 스캔 타겟 반환
def merge(session_dir: Path) -> list[dict]:
    crawl_path = session_dir / "crawl_result.json"
    proxy_path = session_dir / "proxy_history_snapshot.jsonl"

    form_index, danger_urls, url_roles, form_meta = _load_crawl(crawl_path)
    proxy_groups = _load_proxy(proxy_path, url_roles)
    return _build_targets(proxy_groups, form_index, danger_urls, form_meta)


if __name__ == "__main__":
    session_dir = latest_session_dir()
    output_path = session_dir / "scan_targets.json"

    print(f"[MERGE] session dir : {session_dir}")

    targets = merge(session_dir)
    save_json(str(output_path), targets)

    scannable = sum(1 for t in targets if t["can_scan"])
    skipped = len(targets) - scannable
    print(f"[MERGE] targets={len(targets)}  can_scan={scannable}  skipped={skipped}")
    print(f"[MERGE] → {output_path}")
