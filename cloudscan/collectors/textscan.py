"""Shared text matching for job posts, trust pages, status pages and repositories."""
from __future__ import annotations

import html
import re

from .. import signatures as S

_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")
_COMPILED = {p: [re.compile(x) for x in pats] for p, pats in S.PROVIDER_TEXT.items()}
_SUBPROC = {p: [re.compile(x) for x in pats] for p, pats in S.SUBPROCESSOR_TEXT.items()}
_ROLES = {k: re.compile(v, re.I) for k, v in S.ROLE_PATTERNS.items()}
_COST = re.compile(S.COST_TEXT, re.I)
_CONTAINER = re.compile(S.CONTAINER_TEXT, re.I)
_ML_DATA = re.compile(S.ML_DATA_TEXT, re.I)


def plain(text: str) -> str:
    return _WS.sub(" ", html.unescape(_TAG.sub(" ", html.unescape(text or "")))).strip()


def providers_in(text: str, formal: bool = False) -> dict[str, list[str]]:
    """Which providers a text mentions, with the matched terms. `formal` uses subprocessor wording."""
    table = _SUBPROC if formal else _COMPILED
    found = {}
    for prov, pats in table.items():
        terms = sorted({m.group(0) for p in pats for m in p.finditer(text)})
        if terms:
            found[prov] = terms
    return found


def roles_in(title: str) -> list[str]:
    return [k for k, p in _ROLES.items() if p.search(title)]


def mentions_cost(text: str) -> bool:
    return bool(_COST.search(text))


def mentions_containers(text: str) -> bool:
    return bool(_CONTAINER.search(text))


def mentions_ml_data(text: str) -> bool:
    return bool(_ML_DATA.search(text))


def snippet(text: str, term: str, width: int = 90) -> str:
    i = text.find(term)
    if i < 0:
        return ""
    start = max(0, i - width // 2)
    return ("…" if start else "") + text[start:start + width].strip() + "…"
