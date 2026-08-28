from __future__ import annotations

import ipaddress
import re
from functools import lru_cache

# Strong, conservative hostname/remark signals. These are only used when the
# collector could not already determine a country from explicit node metadata.
COUNTRY_TOKENS = {
    "uk":"GB", "gb":"GB", "england":"GB", "greatbritain":"GB", "britain":"GB",
    "us":"US", "usa":"US", "america":"US", "unitedstates":"US",
    "ca":"CA", "canada":"CA", "de":"DE", "germany":"DE", "fr":"FR", "france":"FR",
    "nl":"NL", "netherlands":"NL", "sg":"SG", "singapore":"SG", "jp":"JP", "japan":"JP",
    "kr":"KR", "korea":"KR", "southkorea":"KR", "au":"AU", "australia":"AU",
    "at":"AT", "austria":"AT", "fi":"FI", "finland":"FI", "se":"SE", "sweden":"SE",
    "dk":"DK", "denmark":"DK", "pl":"PL", "poland":"PL", "cz":"CZ", "czechia":"CZ",
    "ch":"CH", "switzerland":"CH", "it":"IT", "italy":"IT", "es":"ES", "spain":"ES",
    "pt":"PT", "portugal":"PT", "no":"NO", "norway":"NO", "ru":"RU", "russia":"RU",
    "ua":"UA", "ukraine":"UA", "tr":"TR", "turkey":"TR", "turkiye":"TR",
    "ir":"IR", "iran":"IR", "ae":"AE", "uae":"AE", "sa":"SA", "saudiarabia":"SA",
    "in":"IN", "india":"IN", "id":"ID", "indonesia":"ID", "my":"MY", "malaysia":"MY",
    "th":"TH", "thailand":"TH", "vn":"VN", "vietnam":"VN", "br":"BR", "brazil":"BR",
    "za":"ZA", "southafrica":"ZA", "nz":"NZ", "newzealand":"NZ", "hk":"HK", "hongkong":"HK",
    "tw":"TW", "taiwan":"TW", "az":"AZ", "azerbaijan":"AZ", "bg":"BG", "bulgaria":"BG",
    "ee":"EE", "estonia":"EE", "lt":"LT", "lithuania":"LT", "lv":"LV", "latvia":"LV",
    "hu":"HU", "hungary":"HU", "kz":"KZ", "kazakhstan":"KZ", "si":"SI", "slovenia":"SI",
    "sc":"SC", "seychelles":"SC", "cn":"CN", "china":"CN", "tm":"TM", "turkmenistan":"TM",
}

@lru_cache(maxsize=8192)
def resolve_host(host: str) -> str | None:
    if not host:
        return None
    value = host.strip().lower().rstrip('.')
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass

    labels = [x for x in re.split(r"[.\-_]+", value) if x]
    # Prefer exact country-code labels and conservative full-name labels.
    for label in labels:
        code = COUNTRY_TOKENS.get(label)
        if code and len(label) in (2,):
            return code
    for label in labels:
        code = COUNTRY_TOKENS.get(label)
        if code and len(label) > 2:
            return code
    # Common provider patterns such as us1, de-01, sg2.
    for label in labels:
        m = re.fullmatch(r"([a-z]{2})(?:\d{1,4}|[-_](?:\d{1,4}))", label)
        if m and m.group(1) in COUNTRY_TOKENS:
            return COUNTRY_TOKENS[m.group(1)]
    return None


def resolve_rows(rows: list[dict]) -> int:
    changed = 0
    for row in rows:
        if row.get("country") != "UNKNOWN":
            continue
        code = resolve_host(str(row.get("host") or ""))
        if code:
            row["country"] = code
            row["country_resolution"] = "hostname"
            changed += 1
    return changed
