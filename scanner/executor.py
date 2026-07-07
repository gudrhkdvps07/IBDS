"""
task 목록 → HTTP 전송 → result 목록

injector.py가 만든 task를 받아 실제 HTTP 요청을 보내고 응답을 수집한다.

allow_redirects=False 이유
  취약점 탐지는 "서버가 에러를 담은 원본 응답"이 필요하다.
  리다이렉트를 따라가면 중간 응답의 에러/반사가 누락된다. (ZAP 동일)

병렬 실행 이유
  페이로드 수가 많아 순차 실행은 너무 느리다.
  requests.Session은 thread-safe하지 않으므로 스레드마다 독립 Session 생성.
"""

from __future__ import annotations

import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

_HIDDEN_TAG_RE = re.compile(r"<input[^>]+>", re.IGNORECASE | re.DOTALL)
_INPUT_TYPE_RE = re.compile(r'\btype=["\']([^"\']+)["\']', re.IGNORECASE)
_INPUT_NAME_RE = re.compile(r'\bname=["\']([^"\']+)["\']', re.IGNORECASE)
_INPUT_VALUE_RE = re.compile(r'\bvalue=["\']([^"\']*)["\']', re.IGNORECASE)
_CSRF_NAME_RE = re.compile(r"(csrf|token|nonce|_token|authenticity|captcha)", re.IGNORECASE)

_RESPONSE_BODY_LIMIT = 20_000


def _make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "*/*",
    })
    # status_forcelist 제거: 5xx는 SQLi 에러 응답일 수 있으므로 재시도 금지
    # connect 재시도만 최소한으로 허용 (네트워크 순단 대응)
    retry = Retry(total=1, connect=1, read=0, status=0, backoff_factor=0)
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    return s


def _fetch_fresh_csrf(session: requests.Session, source_url: str, timeout: int, cookies: dict | None = None) -> dict:
    """source_url에서 CSRF hidden input 값을 새로 가져온다."""
    try:
        r = session.get(source_url, timeout=timeout, allow_redirects=True, cookies=cookies or {})
        tokens: dict = {}
        for tag in _HIDDEN_TAG_RE.findall(r.text):
            m_type = _INPUT_TYPE_RE.search(tag)
            if not (m_type and m_type.group(1).lower() == "hidden"):
                continue
            m_name = _INPUT_NAME_RE.search(tag)
            if not m_name:
                continue
            field_name = m_name.group(1)
            if not _CSRF_NAME_RE.search(field_name):
                continue
            m_val = _INPUT_VALUE_RE.search(tag)
            tokens[field_name] = m_val.group(1) if m_val else ""
        return tokens
    except Exception:
        return {}


def _execute_one(task: dict, timeout: int) -> dict:
    """task 하나를 HTTP로 전송하고 result dict 반환. 스레드마다 독립 Session 사용."""
    session = _make_session()

    point = task.get("point")
    payload = task.get("payload")
    inject_mode = task.get("inject_mode", "replace")
    inject_location = task.get("inject_location", "query")
    inject_param = task.get("inject_param")

    base: dict[str, Any] = {
        "id": task.get("id"),
        "point": point,
        "payload": payload,
        "payload_type": task.get("payload_type"),
        "payload_family": task.get("payload_family"),
        "inject_mode": inject_mode,
        "inject_location": inject_location,
        "inject_param": inject_param,
        "meta": task.get("meta") or {},
        "error": None,
    }

    url = task.get("url")
    method = str(task.get("method", "GET")).upper()

    if not url or payload is None or not inject_param:
        return {**base, "url": url, "error": "invalid_task"}

    base_params = dict(task.get("base_params") or {})
    base_headers = dict(task.get("base_headers") or {})
    base_cookies = dict(task.get("base_cookies") or {})
    base_value = str(task.get("base_value") or "")

    if task.get("needs_csrf_refresh"):
        src = task.get("source_url", "")
        if src:
            base_params.update(_fetch_fresh_csrf(session, src, timeout, base_cookies))

    injected = f"{base_value}{payload}" if inject_mode == "append" else str(payload)

    params = None
    data = None
    headers = dict(base_headers)
    cookies = dict(base_cookies)

    loc = str(inject_location).lower()
    if loc == "header":
        headers[str(inject_param)] = injected
        data = dict(base_params) if method == "POST" else None
        params = None if method == "POST" else dict(base_params)
    elif loc == "cookie":
        cookies[str(inject_param)] = injected
        data = dict(base_params) if method == "POST" else None
        params = None if method == "POST" else dict(base_params)
    elif loc == "body":
        data = dict(base_params) if method == "POST" else None
        params = None if method == "POST" else dict(base_params)
        if method == "POST":
            data[str(inject_param)] = injected
        else:
            params[str(inject_param)] = injected
    else:  # query
        params = dict(base_params)
        params[str(inject_param)] = injected

    started = time.perf_counter()
    try:
        if method == "POST":
            enctype = str(task.get("enctype") or "").lower()
            if "multipart" in enctype and data:
                resp = session.post(
                    url,
                    params=params,
                    files={k: (None, str(v)) for k, v in data.items()},
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout,
                    allow_redirects=False,
                )
            else:
                resp = session.post(
                    url,
                    params=params,
                    data=data,
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout,
                    allow_redirects=False,
                )
        else:
            resp = session.get(
                url,
                params=params,
                headers=headers,
                cookies=cookies,
                timeout=timeout,
                allow_redirects=False,
            )

        elapsed = time.perf_counter() - started
        try:
            body_text = resp.text
        except Exception:
            body_text = None

        return {
            **base,
            "url": url,
            "method": method,
            "status": resp.status_code,
            "length": len(resp.content) if resp.content is not None else None,
            "elapsed": round(elapsed, 3),
            "response_body": body_text[:_RESPONSE_BODY_LIMIT] if body_text else None,
        }

    except requests.Timeout:
        elapsed = time.perf_counter() - started
        return {
            **base,
            "url": url,
            "method": method,
            "status": None,
            "length": 0,
            "elapsed": round(elapsed, 3),
            "response_body": None,
            "error": "timeout",
        }
    except Exception as e:
        elapsed = time.perf_counter() - started
        return {
            **base,
            "url": url,
            "method": method,
            "status": None,
            "length": 0,
            "elapsed": round(elapsed, 3),
            "response_body": None,
            "error": f"exception:{type(e).__name__}",
        }


def execute(
    tasks: List[dict],
    timeout: int = 10,
    delay: float = 0.0,
    max_workers: int = 5,
    output_file: Optional[str] = None,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> List[dict]:
    """task 목록을 병렬로 HTTP 전송하고 result 목록 반환.

    max_workers=1 이면 순차 실행 (디버그/time-based 정밀 측정용).
    delay는 순차 실행 시에만 적용된다.
    """
    total = len(tasks)
    results: List[dict] = [None] * total  # 순서 보존용

    if max_workers <= 1:
        # 순차 실행 — delay 적용, time-based 측정 정밀도 높음
        for i, task in enumerate(tasks):
            if delay:
                time.sleep(delay)
            results[i] = _execute_one(task, timeout)
            if progress_callback and total > 0:
                progress_callback(i + 1, total)
    else:
        # 병렬 실행 — 각 스레드가 독립 Session 생성
        future_to_idx = {}
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            for i, task in enumerate(tasks):
                future = pool.submit(_execute_one, task, timeout)
                future_to_idx[future] = i

            completed = 0
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    results[idx] = future.result()
                except Exception as e:
                    task = tasks[idx]
                    results[idx] = {
                        "id": task.get("id"),
                        "point": task.get("point"),
                        "payload": task.get("payload"),
                        "payload_type": task.get("payload_type"),
                        "payload_family": task.get("payload_family"),
                        "inject_mode": task.get("inject_mode"),
                        "inject_location": task.get("inject_location"),
                        "inject_param": task.get("inject_param"),
                        "meta": task.get("meta") or {},
                        "url": task.get("url"),
                        "method": task.get("method"),
                        "status": None,
                        "length": 0,
                        "elapsed": 0.0,
                        "response_body": None,
                        "error": f"future_exception:{type(e).__name__}",
                    }
                completed += 1
                if progress_callback and total > 0:
                    progress_callback(completed, total)

    results = [r for r in results if r is not None]

    if output_file:
        os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

    return results
