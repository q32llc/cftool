#!/usr/bin/env python3
"""
cftool  ─  Export legacy zones ➜ YAML  ➜ Apply to Cloudflare

Major capabilities
==================
• export <domains…>      → YAML with: DNS, mail_forwarding, url_redirects
• apply  <config.yml>    → Creates DNS, Email‑Routing, Bulk‑Redirects, flips NS
Dependencies: requests pydantic[dotenv] PyYAML rich
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import sys
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Sequence

import requests
import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field

# ──────────────────────────────────────────────────────────────────────────────
#  Environment & session
# ──────────────────────────────────────────────────────────────────────────────
load_dotenv()

CF_API_TOKEN = os.environ["CF_API_TOKEN"]
CF_API = "https://api.cloudflare.com/client/v4"

log = logging.getLogger("cftool")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
my_ip = requests.get("https://checkip.amazonaws.com").text.strip()


# ──────────────────────────────────────────────────────────────────────────────
#  Neutral dataclasses
# ──────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class DNSRecord:
    type: str
    name: str
    content: str
    ttl: int | None = None
    priority: int | None = None
    proxied: bool | None = None
    id: str | None = None

    def is_equal(self, other: object) -> bool:
        diff = {}
        if self.priority != other.priority:
            diff["priority"] = (self.priority, other.priority)
        if self.content.rstrip(".") != other.content.rstrip("."):
            diff["content"] = (self.content, other.content)
        if bool(self.proxied) != bool(other.proxied) and self.type in ("A", "AAAA", "CNAME"):
            diff["proxied"] = (self.proxied, other.proxied)
        if self.ttl != other.ttl and self.ttl != 1:
            diff["ttl"] = (self.ttl, other.ttl)
        if self.name != other.name:
            diff["name"] = (self.name, other.name)
        if self.type != other.type:
            diff["type"] = (self.type, other.type)
        if diff:
            log.info(f"MX record {self.name} has changed from {diff}")

        if self.type == "MX":
            assert self.priority
            assert other.priority

        is_equal = (
            self.type == other.type
            and self.name == other.name
            and self.content.rstrip(".") == other.content.rstrip(".")
            and (
                bool(self.proxied) == bool(other.proxied) or self.type not in ("A", "AAAA", "CNAME")
            )
            and (self.ttl == other.ttl or self.ttl == 1)
            and (  # 1 is auto
                self.priority == other.priority or self.type not in ("MX", "SRV", "URI")
            )
        )

        if not is_equal:
            log.error(self.__dict__)
            log.error(other.__dict__)
            assert diff

        return is_equal

    @classmethod
    def from_cf(cls, r: Dict, domain: str) -> "DNSRecord":
        if r["type"] == "MX":
            log.info(f"CF record {r}")
            assert r["priority"]

        if r["type"] == "TXT":
            if r["content"].startswith('"') and r["content"].endswith('"'):
                content = re.findall(r'"([^"]*)"', r["content"])
                if len(content) >= 1:
                    # merge into one quoted string
                    r["content"] = '"' + "".join(content) + '"'

        name = re.sub(rf"\b{domain}$", "", r["name"]).strip(".")
        if name == "":
            name = "@"
        ret = cls(
            r["type"].upper(),
            name,
            r["content"],
            r.get("ttl"),
            r.get("priority"),
            r.get("proxied"),
            r.get("id"),
        )
        if ret.type == "MX":
            assert ret.priority
        return ret

    def key(self) -> tuple:
        # records that can't be duplicated per type and name
        if self.type in ("A", "AAAA", "CNAME"):
            return (
                self.type.upper(),
                self.name.rstrip("."),
            )
        else:
            content = self.content.rstrip(".")
            return (
                self.type.upper(),
                self.name.rstrip("."),
                content,
                self.priority or 0,
            )

    def payload(self) -> Dict:
        d = {"type": self.type.upper(), "name": self.name, "content": self.content}
        if self.ttl is not None:
            d["ttl"] = self.ttl
        if self.priority is not None:
            d["priority"] = self.priority
        if self.proxied is not None:
            d["proxied"] = self.proxied
        return d


# ──────────────────────────────────────────────────────────────────────────────
#  YAML schema (pydantic)
# ──────────────────────────────────────────────────────────────────────────────
class Forward(BaseModel):
    from_: str = Field(..., alias="from")
    to: str

    model_config = dict(populate_by_name=True)


class Redirect(BaseModel):
    source: str
    destination: str
    code: int = 301  # 301 / 302


class Extra(BaseModel):
    type: str
    name: str
    content: str
    ttl: int | None = None
    priority: int | None = None
    proxied: bool | None = None


class Site(BaseModel):
    registrar: str
    cache_bypass: List[str] = []
    records: List[Extra] = []
    mail_forwarding: List[Forward] = []
    url_redirects: List[Redirect] = []
    extra_records: List[Extra] = []
    inject_csp: bool = False


class Config(BaseModel):
    domains: Dict[str, Site]


# ──────────────────────────────────────────────────────────────────────────────
#  Registrar providers  (Namecheap + Name.com)
# ──────────────────────────────────────────────────────────────────────────────
class BaseProvider(ABC):
    @abstractmethod
    def export_dns(self, domain: str) -> List[DNSRecord]: ...

    @abstractmethod
    def export_forward(self, domain: str) -> List[Forward]: ...

    @abstractmethod
    def export_redirects(self, domain: str) -> List[Redirect]: ...

    @abstractmethod
    def has_domain(self, domain: str) -> bool: ...

    @abstractmethod
    def set_ns(self, domain: str, ns: List[str]): ...


class Namecheap(BaseProvider):
    API = "https://api.namecheap.com/xml.response"

    def __init__(self):
        self.u = os.environ["NC_API_USER"]
        self.k = os.environ["NC_API_KEY"]
        self.headers = {
            "User-Agent": "cftool/1.0",
        }
        self.ns = {"nc": "http://api.namecheap.com/xml.response"}
        self._cache = {}

    def _call(self, cmd: str, params: Dict) -> str:
        p = {
            "ApiUser": self.u,
            "ApiKey": self.k,
            "UserName": self.u,
            "Command": cmd,
            "ClientIp": my_ip,
        } | params
        r = requests.get(self.API, params=p, headers=self.headers, timeout=60)
        r.raise_for_status()
        return r.text

    def _parse_xml(self, xml: str) -> ET.Element:
        root = ET.fromstring(xml)
        if error := root.find(".//nc:Errors/nc:Error", self.ns):
            raise RuntimeError(f"Namecheap API error: {error.text}")
        return root

    def _get_all_pages(self, cmd: str, params: Dict, pattern: str) -> List[ET.Element]:
        cache_key = (cmd, tuple(sorted(params.items())), pattern)
        if cached := self._cache.get(cache_key):
            return cached

        params["PageSize"] = 100
        params["Page"] = 1
        xml = self._call(cmd, params)
        root = self._parse_xml(xml)
        els = root.findall(f".//nc:{pattern}", self.ns)
        while len(els) == 100:
            params["Page"] += 1
            xml = self._call(cmd, params)
            root = self._parse_xml(xml)
            els += root.findall(f".//nc:{pattern}", self.ns)
        self._cache[cache_key] = els
        return els

    def has_domain(self, domain: str) -> bool:
        els = self._get_all_pages("namecheap.domains.getList", {}, "Domain")
        domains = {el.attrib["Name"].lower() for el in els}
        return domain.lower() in domains

    def export_dns(self, domain: str) -> List[DNSRecord]:
        sld, tld = domain.split(".", 1)

        els = self._get_all_pages(
            "namecheap.domains.dns.getHosts", {"SLD": sld, "TLD": tld}, "host"
        )

        records = []
        for host in els:
            record_type = host.attrib["Type"]
            name = host.attrib["Name"] or "@"
            content = host.attrib["Address"]
            ttl = int(host.attrib.get("TTL"))
            priority = int(host.attrib.get("MXPref", None))

            # Handle URL redirects
            if record_type in {"URL", "URL301"}:
                continue  # These are handled by export_redirects

            records.append(
                DNSRecord(
                    type=record_type, name=name.lower(), content=content, ttl=ttl, priority=priority
                )
            )
        return records

    def export_forward(self, domain: str) -> List[Forward]:
        sld, tld = domain.split(".", 1)
        els = self._get_all_pages(
            "namecheap.domains.dns.getEmailForwarding", {"DomainName": domain}, "Forward"
        )

        forwards = []
        for host in els:
            mailbox = host.attrib["mailbox"]
            forwards.append(Forward(from_=f"{mailbox}@{domain}", to=host.text))
        return forwards

    def export_redirects(self, domain: str) -> List[Redirect]:
        sld, tld = domain.split(".", 1)
        els = self._get_all_pages(
            "namecheap.domains.dns.getHosts", {"SLD": sld, "TLD": tld}, "host"
        )

        redirects = []
        for host in els:
            if host.attrib["Type"] in {"URL", "URL301"}:
                name = host.attrib["Name"] or "@"
                source = f"https://{name}.{domain}" if name != "@" else f"https://{domain}"
                redirects.append(
                    Redirect(
                        source=source,
                        destination=host.attrib["Address"],
                        code=301 if host.attrib["Type"] == "URL301" else 302,
                    )
                )
        return redirects

    def set_ns(self, domain: str, ns: List[str]):
        sld, tld = domain.split(".", 1)
        # check if already to ns
        ns_list = self._get_all_pages(
            "namecheap.domains.dns.getList", {"SLD": sld, "TLD": tld}, "Nameserver"
        )
        ns_list = [ns.text.lower().rstrip(" ").rstrip(".") for ns in ns_list]
        count = 0
        for n in ns:
            if n.lower().rstrip(" ").rstrip(".") in ns_list:
                count += 1

        log.info(f"COUNT {count} of {len(ns)}")

        if len(ns) == count:
            log.info(f"NS {ns} already set for {domain}")
            return

        self._call(
            "namecheap.domains.dns.setCustom",
            {"SLD": sld, "TLD": tld, "Nameservers": ",".join(ns)},
        )


class NameDotCom(BaseProvider):
    API = "https://api.name.com/v4"

    def __init__(self):
        self.auth = (os.environ["NAMEDOTCOM_USER"], os.environ["NAMEDOTCOM_TOKEN"])
        self.headers = {
            "User-Agent": "cftool/1.0",
        }

    def has_domain(self, domain: str) -> bool:
        r = requests.get(
            f"{self.API}/domains/{domain}", auth=self.auth, headers=self.headers, timeout=60
        )
        r.raise_for_status()
        return r.status_code == 200

    def export_dns(self, domain: str) -> list[DNSRecord]:
        r = requests.get(
            f"{self.API}/domains/{domain}/records", auth=self.auth, headers=self.headers, timeout=60
        )
        if r.status_code == 400:
            log.warning(f"Domain {domain} uses other DNS provider")
            return []
        r.raise_for_status()
        return [
            DNSRecord(
                type=rec["type"],
                name=(rec.get("host") or "@").lower(),
                content=rec["answer"],
                ttl=rec.get("ttl") if rec.get("ttl", 300) != 300 else None,
                priority=rec.get("priority"),
            )
            for rec in r.json().get("records", [])
        ]

    def export_forward(self, domain: str) -> list[Forward]:
        mx_required = f"mx.{domain}.cust.a.hostedemail.com"
        active_mx = any(
            r
            for r in self.export_dns(domain)
            if r.type == "MX" and r.content.lower() == mx_required
        )
        r = requests.get(
            f"{self.API}/domains/{domain}/email/forwarding",
            auth=self.auth,
            headers=self.headers,
            timeout=60,
        )
        if r.status_code != 200:
            return []
        data = r.json().get("emailForwarding", [])
        if not active_mx:
            if len(data):
                log.warning(f"Domain {domain} has email forwarding but no active MX record")
            return []
        return [Forward(from_=f["emailBox"] + f"@{domain}", to=f["emailTo"]) for f in data]

    def export_redirects(self, domain: str) -> list[Redirect]:
        r = requests.get(
            f"{self.API}/domains/{domain}/url/forwarding",
            auth=self.auth,
            headers=self.headers,
            timeout=60,
        )
        r.raise_for_status()
        data = r.json().get("urlForwarding", [])
        redirects = []
        for rd in data:
            source = rd.get("host", "@")
            destination = rd["forwardsTo"]
            code = 301
            redirects.append(Redirect(source=source, destination=destination, code=code))
        return redirects

    def set_ns(self, domain: str, ns: List[str]):
        r = requests.post(
            f"{self.API}/domains/{domain}:setNameservers",
            auth=self.auth,
            headers=self.headers,
            json={"nameservers": ns},
            timeout=60,
        )
        if r.status_code >= 400:
            raise RuntimeError(r.text)


PROVIDERS: dict[str, BaseProvider] = {"namecheap": Namecheap(), "name.com": NameDotCom()}


def detect_provider(domain: str) -> str:
    name: str
    prov: BaseProvider
    for name, prov in PROVIDERS.items():
        if prov.has_domain(domain):
            return name
    raise RuntimeError(f"No provider matched {domain}")


# ──────────────────────────────────────────────────────────────────────────────
#  Cloudflare helpers
# ──────────────────────────────────────────────────────────────────────────────
def cf_req(m: str, p: str, **kw):
    headers = {
        "User-Agent": "cftool/1.0",
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json",
    }
    r = requests.request(m, f"{CF_API}{p}", timeout=60, headers=headers, **kw)
    if r.status_code >= 400:
        raise RuntimeError(r.text[:200])
    data = r.json()
    if not data.get("success"):
        raise RuntimeError(data)
    return data["result"]


def cf_zone(domain: str) -> Dict:
    z = cf_req("GET", f"/zones?name={domain}")
    return (
        z[0]
        if z
        else cf_req("POST", "/zones", json={"name": domain, "account": {"id": cf_account()}})
    )


def cf_records(zone_id: str, domain: str) -> Dict[tuple, DNSRecord]:
    return {
        DNSRecord.from_cf(r, domain).key(): DNSRecord.from_cf(r, domain)
        for r in cf_req("GET", f"/zones/{zone_id}/dns_records?per_page=5000")
    }


def cf_upsert(zone_id: str, rec: DNSRecord, already: DNSRecord | None):
    if already is None:
        cf_req("POST", f"/zones/{zone_id}/dns_records", json=rec.payload())
    else:
        cf_req("PATCH", f"/zones/{zone_id}/dns_records/{already.id}", json=rec.payload())


def cf_cache(zone_id: str, paths: Sequence[str]):
    if not paths:
        return
    expr = " or ".join([f'http.request.uri.path matches "{p}"' for p in paths])
    cf_req(
        "POST",
        f"/zones/{zone_id}/rulesets",
        json={
            "name": "bypass",
            "kind": "zone",
            "phase": "http_request_cache_settings",
            "rules": [
                {
                    "action": "set_cache_settings",
                    "action_parameters": {"cache": False},
                    "expression": expr,
                    "enabled": True,
                }
            ],
        },
    )


# example of enabled-state for cf email routing
# MX	drawme.io	91	route1.mx.cloudflare.net.
# MX	drawme.io	4	route2.mx.cloudflare.net.
# MX	drawme.io	68	route3.mx.cloudflare.net.
# TXT	cf2024-1._domainkey.drawme.io		"v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiweykoi+o48IOGuP7GR3X0MOExCUDY/BCRHoWBnh3rChl7WhdyCxW3jgq1daEjPPqoi7sJvdg5hEQVsgVRQP4DcnQDVjGMbASQtrY4WmB1VebF+RPJB2ECPsEDTpeiI5ZyUAwJaVX7r6bznU67g7LvFq35yIo4sdlmtZGV+i0H4cpYH9+3JJ78km4KXwaf9xUJCWF6nxeD+qG6Fyruw1Qlbds2r85U9dkNDVAS3gioCvELryh1TxKGiVTkg4wqHTyHfWsp7KD3WQHYJn0RyfJJu6YEmL77zonn7p2SRMvTMP3ZEXibnC9gz3nnhR6wcYL8Q7zXypKTMD58bTixDSJwIDAQAB"
# TXT	drawme.io		"v=spf1 include:_spf.mx.cloudflare.net ~all"


def cf_email_rules(
    zone_id: str, fwds: Sequence[Forward], existing: dict[tuple, DNSRecord], domain: str
):
    if not fwds:
        return

    ok_ids = set()
    records = cf_req("GET", f"/zones/{zone_id}/email/routing/dns", json={})
    for r in records:
        d = DNSRecord.from_cf(r, domain)
        log.debug(f"Processing {d.key()}")
        already = existing.get(d.key())
        if already is not None:
            if already.is_equal(d):
                log.debug(f"Skipping {d.payload()} because {d.key()} already exists, {already.id}")
                ok_ids.add(already.id)
                continue
            else:
                log.debug(f"Updating {d.payload()}")
                ok_ids.add(already.id)
        else:
            log.info(f"Creating {d.payload()} because {d.key()} not in ({list(existing.keys())})")
        cf_upsert(zone_id, d, already)

    # cleanup any records that are no longer needed
    log.info("OK IDs: " + str(ok_ids))
    for r in existing.values():
        needs_delete = r.id not in ok_ids and (
            r.type == "MX"
            or (r.type == "TXT" and r.content.lower().find("v=spf1") != -1)
            or (r.type == "TXT" and r.content.lower().find("v=dkim1") != -1)
        )
        if needs_delete:
            log.debug(f"Deleting {r.id} -> {r.payload()}")
            cf_req("DELETE", f"/zones/{zone_id}/email/routing/dns_records/{r.id}")

    cf_catch_all = cf_req("GET", f"/zones/{zone_id}/email/routing/rules/catch_all")
    if cf_catch_all and cf_catch_all["enabled"]:
        catch_all = cf_catch_all["actions"][0]["value"][0]
    else:
        catch_all = None
    rules = cf_req("GET", f"/zones/{zone_id}/email/routing/rules")
    log.info(f"Existing rules: {rules}")
    existing = {}
    for r in rules:
        if not r["enabled"]:
            continue
        for match in r["matchers"]:
            if match["type"] == "literal" and match["field"] == "to":
                existing[match["value"].lower()] = {
                    "id": r["id"],
                    "to": r["actions"][0]["value"][0],
                }
    # create new
    for f in fwds:
        if f.from_ in existing:
            already = existing[f.from_]
            if already["to"] == f.to:
                log.info(f"Skipping {f.from_} -> {f.to} because it already exists")
                continue
            log.info(f"Deleting existing rule {f.from_} -> {existing[f.from_]}")
            cf_req("DELETE", f"/zones/{zone_id}/email/routing/rules/{existing[f.from_]['id']}")

        if f.from_ == "*@" + domain:
            if catch_all:
                if catch_all == f.to:
                    log.info(f"Skipping {f.from_} -> {f.to} because it already exists")
                    continue
                log.info(f"Deleting existing catch all rule {catch_all['id']}")
            else:
                log.info(f"Creating catch all rule {f.from_} -> {f.to}")
            cf_req(
                "PUT",
                f"/zones/{zone_id}/email/routing/rules/catch_all",
                json={"enabled": True, "actions": [{"type": "forward", "value": [f.to]}]},
            )
            continue

        log.info(f"Creating rule {f.from_} -> {f.to}")
        cf_req(
            "POST",
            f"/zones/{zone_id}/email/routing/rules",
            json={
                "name": f.from_,
                "enabled": True,
                "matchers": [{"type": "literal", "field": "to", "value": f.from_}],
                "actions": [{"type": "forward", "value": [f.to]}],
            },
        )


def redirect_to_cf_rule(r: Redirect):
    if not r.source.startswith("https://"):
        log.warning(f"Redirect source must start with https://: {r.source}")
        return
    parsed = r.source.removeprefix("https://").split("/", 1)
    host = parsed[0]
    path = "/" + parsed[1] if len(parsed) > 1 else "/"

    # Create the wildcard pattern for the source
    source_pattern = f"https://{host}{path}"
    if path == "/":
        source_pattern += "*"

    # Create the wildcard pattern for the target
    target_pattern = r.destination
    if not target_pattern.endswith("/"):
        target_pattern += "/"
    target_pattern += "${1}"

    rule = {
        "action": "redirect",
        "action_parameters": {
            "from_value": {
                "preserve_query_string": True,
                "status_code": r.code,
                "target_url": {
                    "expression": f'wildcard_replace(http.request.full_uri, r"{source_pattern}", r"{target_pattern}")'
                },
            }
        },
        "description": f"Redirect from {host}{path} to {r.destination}",
        "enabled": True,
        "expression": f'(http.request.full_uri wildcard r"{source_pattern}")',
    }
    return rule


def cf_bulk_redirect(zone_id: str, redirects: Sequence[Redirect]):
    if not redirects:
        return

    existing = cf_req("GET", f"/zones/{zone_id}/rulesets?phase=http_request_dynamic_redirect")
    existing_rules = []
    patch_id = None
    for rset in existing:
        if rset["kind"] == "zone" and rset["phase"] == "http_request_dynamic_redirect":
            patch_id = rset["id"]
            try:
                existing_rules.extend(
                    cf_req("GET", f"/zones/{zone_id}/rulesets/{rset['id']}")["rules"]
                )
            except KeyError:
                pass
    rules = [redirect_to_cf_rule(r) for r in redirects]
    have = 0
    for r in redirects:
        for rule in existing_rules:
            log.info(f"Checking {r.source} against {rule['expression']}")
            if rule["action"] == "redirect":
                if r.source in rule["expression"]:
                    log.info(f"Found existing rule for {r.source}: {rule}")
                    target = rule["action_parameters"]["from_value"]["target_url"]["expression"]
                    log.info(f"Target: {target}, Destibnation: {r.destination}")
                    if r.destination.lower() not in target.lower():
                        log.info(f"Need to update destination from {target} to {r.destination}")
                    if r.destination.lower() in target.lower():
                        have += 1
                        log.info(f"Already have rule for {r.source}")
                        break

    if len(rules) == have:
        log.info("Already have all rules")
        return

    if patch_id:
        log.info(f"PATCHING IN {rules}")
        cf_req(
            "PUT",
            f"/zones/{zone_id}/rulesets/{patch_id}",
            json={"rules": rules},
        )
        return
    else:
        cf_req(
            "POST",
            f"/zones/{zone_id}/rulesets",
            json={
                "name": "cftool-redirects",
                "kind": "zone",
                "phase": "http_request_dynamic_redirect",
                "rules": rules,
            },
        )


@lru_cache(maxsize=1)
def cf_account() -> str:
    zs = cf_req("GET", "/zones")
    for z in zs:
        return z["account"]["id"]
    return cf_req("GET", "/user")["account"]["id"]


# ──────────────────────────────────────────────────────────────────────────────
#  EXPORT
# ──────────────────────────────────────────────────────────────────────────────
def get_mailgun_dns_records(domain: str) -> List[DNSRecord]:
    """Fetch DNS records from Mailgun for a domain.

    If Mailgun has a subdomain of the target domain (e.g. mg.q32.com for q32.com),
    those records will be included in the export with proper subdomain paths.
    """
    api_key = os.environ.get("MAILGUN_API_KEY")
    if not api_key:
        return []

    # First get all domains from Mailgun
    r = requests.get(
        "https://api.mailgun.net/v3/domains",
        auth=("api", api_key),
        timeout=60,
    )
    r.raise_for_status()
    domains = r.json().get("items", [])

    # Find all Mailgun domains that are either the target domain or a subdomain of it
    mailgun_domains = [
        d["name"] for d in domains if d["name"] == domain or d["name"].endswith(f".{domain}")
    ]

    if not mailgun_domains:
        return []

    records = []
    for mg_domain in mailgun_domains:
        # Get the domain's DNS records
        r = requests.get(
            f"https://api.mailgun.net/v3/domains/{mg_domain}",
            auth=("api", api_key),
            timeout=60,
        )
        r.raise_for_status()
        data = r.json()

        # Calculate the subdomain prefix if this is a subdomain
        subdomain_prefix = ""
        if mg_domain != domain:
            # Remove the target domain from the end to get the subdomain prefix
            subdomain_prefix = mg_domain[: -len(domain) - 1]  # -1 for the dot

        for record in data.get("sending_dns_records", []) + data.get("receiving_dns_records", []):
            if record["record_type"] == "TXT":
                # Handle SPF and DKIM records
                # For subdomains, we need to preserve the full record name
                base_name = record["name"].rstrip(f".{mg_domain}.") or "@"
                if base_name == "@" and subdomain_prefix:
                    name = subdomain_prefix
                else:
                    name = f"{base_name}.{subdomain_prefix}" if subdomain_prefix else base_name
                records.append(
                    DNSRecord(
                        type="TXT",
                        name=name,
                        content=record["value"],
                    )
                )
            elif record["record_type"] == "MX":
                # Handle MX records
                name = subdomain_prefix if subdomain_prefix else "@"
                records.append(
                    DNSRecord(
                        type="MX",
                        name=name,
                        content=record["value"],
                        priority=record.get("priority", 10),
                    )
                )
            elif record["record_type"] == "CNAME":
                # Handle CNAME records
                # For subdomains, we need to preserve the full record name
                base_name = record["name"].rstrip(f".{mg_domain}.")
                name = f"{base_name}.{subdomain_prefix}" if subdomain_prefix else base_name
                records.append(
                    DNSRecord(type="CNAME", name=name, content=record["value"], proxied=False)
                )

    return records


def cmd_export(domains: List[str]) -> None:
    yaml_out = {}
    for dom in domains:
        prov_name = detect_provider(dom)
        prov = PROVIDERS[prov_name]
        log.info(f"Export {dom} via {prov_name}")
        recs = [r.payload() for r in prov.export_dns(dom)]  # type: ignore[attr-defined]
        fwds = [f.model_dump(by_alias=True, exclude_none=True) for f in prov.export_forward(dom)]  # type: ignore[attr-defined]
        reds = [r.model_dump(by_alias=True, exclude_none=True) for r in prov.export_redirects(dom)]  # type: ignore[attr-defined]

        # Add Mailgun DNS records if available
        mailgun_recs = get_mailgun_dns_records(dom)
        if mailgun_recs:
            log.info(f"Found {len(mailgun_recs)} Mailgun DNS records for {dom}")
            recs.extend([r.payload() for r in mailgun_recs])

        for rec in recs:
            if rec["type"] == "ANAME":
                # cloudflare will magcally do the right thing
                rec["type"] = "CNAME"
            if rec["type"] == "CNAME":
                rec["proxied"] = True
            if rec["type"] == "A" and rec["name"] == "@":
                rec["proxied"] = True
            if rec["type"] == "AAAA" and rec["name"] == "@":
                rec["proxied"] = True
            if rec["type"] not in ("MX", "SRV", "URI"):
                rec.pop("priority", None)
        yaml_out[dom] = {
            "registrar": prov_name,
            "records": recs,
        }
        if fwds:
            yaml_out[dom]["mail_forwarding"] = fwds
        if reds:
            yaml_out[dom]["url_redirects"] = reds
    yaml.dump({"domains": yaml_out}, sys.stdout, sort_keys=False)


# ──────────────────────────────────────────────────────────────────────────────
#  APPLY
# ──────────────────────────────────────────────────────────────────────────────
def cf_csp_ruleset(zone_id: str, domain: str, inject: bool):
    """Manage CSP ruleset for a domain.

    This function carefully manages CSP rules while preserving other rules in the ruleset.
    It will:
    1. Only delete CSP rules when explicitly disabled
    2. Preserve all other rules in the ruleset
    3. Merge CSP rules with existing rules when needed
    """
    # Get existing rulesets
    rulesets = cf_req(
        "GET", f"/zones/{zone_id}/rulesets?phase=http_response_headers_transform", json={}
    )

    log.info(f"Rulesets: {rulesets}")

    # Find existing CSP ruleset
    csp_ruleset = None
    for rs in rulesets:
        if rs["name"] == "Add CSP header":
            csp_ruleset = rs
            break

    csp_rule = {
        "expression": "true",
        "action": "rewrite",
        "action_parameters": {
            "headers": {
                "Content-Security-Policy": {"operation": "set", "value": "frame-ancestors 'self'"}
            }
        },
        "enabled": True,
        "description": "Set CSP to disallow iframing by other domains",
    }

    if not inject:
        if csp_ruleset:
            # Fetch the rules for this ruleset
            ruleset_details = cf_req(
                "GET", f"/zones/{zone_id}/rulesets/{csp_ruleset['id']}", json={}
            )
            rules = ruleset_details.get("rules", [])

            # Remove just the CSP rule while preserving others
            log.info(f"Removing CSP rule from ruleset for {domain} while preserving other rules")
            other_rules = [
                r
                for r in rules
                if not (
                    r.get("action") == "rewrite"
                    and "Content-Security-Policy"
                    in r.get("action_parameters", {}).get("headers", {})
                )
            ]
            if not other_rules:
                log.info(f"No other rules in ruleset for {domain}, deleting ruleset")
                cf_req("DELETE", f"/zones/{zone_id}/rulesets/{csp_ruleset['id']}")
                return
            cf_req(
                "PUT",
                f"/zones/{zone_id}/rulesets/{csp_ruleset['id']}",
                json={
                    "name": csp_ruleset["name"],
                    "kind": "zone",
                    "phase": "http_response_headers_transform",
                    "rules": other_rules,
                },
            )
        return

    if csp_ruleset:
        # Fetch the rules for this ruleset
        ruleset_details = cf_req("GET", f"/zones/{zone_id}/rulesets/{csp_ruleset['id']}", json={})
        rules = ruleset_details.get("rules", [])

        # Check if CSP rule already exists
        has_csp = any(
            r.get("action") == "rewrite"
            and "Content-Security-Policy" in r.get("action_parameters", {}).get("headers", {})
            for r in rules
        )

        if not has_csp:
            # Add CSP rule to existing ruleset
            log.info(f"Adding CSP rule to existing ruleset for {domain}")
            cf_req(
                "PUT",
                f"/zones/{zone_id}/rulesets/{csp_ruleset['id']}",
                json={
                    "name": csp_ruleset["name"],
                    "kind": "zone",
                    "phase": "http_response_headers_transform",
                    "rules": rules + [csp_rule],
                },
            )
        else:
            log.info(f"CSP rule already exists in ruleset for {domain}")
    else:
        # Create new ruleset with CSP rule
        log.info(f"Creating new CSP ruleset for {domain}")
        cf_req(
            "POST",
            f"/zones/{zone_id}/rulesets",
            json={
                "name": "Add CSP header",
                "kind": "zone",
                "phase": "http_response_headers_transform",
                "rules": [csp_rule],
            },
        )


def cmd_apply(cfg_path: Path, dry: bool = False):
    cfg = Config.model_validate(yaml.safe_load(cfg_path.read_text()))

    for dom, site in cfg.domains.items():
        zone = cf_zone(dom)
        zid = zone["id"]
        log.info(f"Zone: {zid}, ns: {zone['name_servers']}")
        ns_s = zone["name_servers"][:2]
        existing = cf_records(zid, dom)

        log.debug(f"Existing records: {existing}")

        desired = [DNSRecord(**r.dict()) for r in site.records] + [
            DNSRecord(**e.dict()) for e in site.extra_records
        ]

        log.debug(f"Desired records: {desired}")

        created = 0
        for rec in {d.key(): d for d in desired}.values():
            already = existing.get(rec.key())
            if already is not None:
                if already.is_equal(rec):
                    log.debug(f"Skipping {rec.payload()} because {rec.key()} already exists")
                    continue
                else:
                    log.debug(f"Updating {rec.payload()}")
            else:
                log.info(f"Creating {rec.payload()}")
            if not dry:
                cf_upsert(zid, rec, already)
            created += 1
        if site.cache_bypass:
            log.info(f"Bypassing cache for {site.cache_bypass}")
            if not dry:
                cf_cache(zid, site.cache_bypass)
        if site.mail_forwarding:
            log.info(f"Creating email forwarding rules for {site.mail_forwarding}")
            if not dry:
                cf_email_rules(zid, site.mail_forwarding, existing, dom)
        log.info(f"Managing CSP ruleset for {dom}")
        if not dry:
            cf_csp_ruleset(zid, dom, site.inject_csp)
        if site.url_redirects:
            log.info(f"Creating bulk redirect for {site.url_redirects}")
            if not dry:
                cf_bulk_redirect(zid, site.url_redirects)
        if not dry:
            log.info(f"Setting NS for {dom}")
            PROVIDERS[site.registrar].set_ns(dom, ns_s)  # type: ignore[attr-defined]

        log.info(
            f"Apply {dom} ({len(desired)} rows, {created} created, {len(site.mail_forwarding)} fwds, {len(site.url_redirects)} redirects)"
        )


# ──────────────────────────────────────────────────────────────────────────────
#  CLI
# ──────────────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Cloudflare export/apply tool")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ex = sub.add_parser("export")
    ex.add_argument("domains", nargs="+")
    ex.add_argument("--debug", "-D", action="store_true")
    aply = sub.add_parser("apply")
    aply.add_argument("config", type=Path)
    aply.add_argument("--dry", action="store_true")
    aply.add_argument("--debug", "-D", action="store_true")
    args = ap.parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        log.debug(args)
    if args.cmd == "export":
        cmd_export(args.domains)
    else:
        cmd_apply(args.config, args.dry)


if __name__ == "__main__":
    main()
