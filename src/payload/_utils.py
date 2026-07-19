from typing import Dict, List

Payload = Dict[str, str]

STRENGTH_LIMIT = {
    "LOW":    4,
    "MEDIUM": 10,
    "HIGH":   25,
    "INSANE": 9999,
}


def _limit(payloads: List[Payload], strength: str) -> List[Payload]:
    return payloads[: STRENGTH_LIMIT.get(strength.upper(), STRENGTH_LIMIT["MEDIUM"])]


def _dedupe(groups: List[List[Payload]]) -> List[Payload]:
    seen: set = set()
    result: List[Payload] = []
    for group in groups:
        for item in group:
            if item["payload"] not in seen:
                seen.add(item["payload"])
                result.append(item)
    return result
