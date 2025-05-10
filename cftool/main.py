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
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence

import requests
import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from rich.console import Console
from rich.table import Table

# ──────────────────────────────────────────────────────────────────────────────
#  Environment & session
# ──────────────────────────────────────────────────────────────────────────────
load_dotenv()


class CFToolError(Exception):
    """Custom error for cftool to short-circuit on expected errors."""

    pass


CF_API_TOKEN = os.getenv("CF_API_TOKEN")
if not CF_API_TOKEN:
    raise CFToolError("CF_API_TOKEN missing")
SESSION = requests.Session()
SESSION.headers.update(
    {
        "User-Agent": "cftool/1.0",
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json",
    }
)
CF_API = "https://api.cloudflare.com/client/v4"

console = Console()
log = logging.getLogger("cftool")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


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

    @classmethod
    def from_cf(cls, r: Dict) -> "DNSRecord":
        return cls(
            r["type"], r["name"], r["content"], r.get("ttl"), r.get("priority"), r.get("proxied")
        )

    def key(self) -> tuple:
        return (
            self.type.upper(),
            self.name.rstrip("."),
            self.content.rstrip("."),
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
    dns_provider: str
    origin: str | None = None
    cache_bypass: List[str] = []
    records: List[Extra] = []
    mail_forwarding: List[Forward] = []
    url_redirects: List[Redirect] = []
    extra_records: List[Extra] = []


class Config(BaseModel):
    domains: Dict[str, Site]


# ──────────────────────────────────────────────────────────────────────────────
#  Registrar providers  (Namecheap + Name.com)
# ──────────────────────────────────────────────────────────────────────────────
class Namecheap:
    API = "https://api.namecheap.com/xml.response"

    def __init__(self):
        req = ("NC_API_USER", "NC_API_KEY", "NC_USERNAME", "NC_API_IP")
        missing = [v for v in req if not os.getenv(v)]
        if missing:
            raise CFToolError(f"Namecheap missing: {', '.join(missing)}")
        self.u, self.k, self.un, self.ip = map(os.getenv, req)

    def _call(self, cmd: str, params: Dict) -> str:
        p = {
            "ApiUser": self.u,
            "ApiKey": self.k,
            "UserName": self.un,
            "Command": cmd,
            "ClientIp": self.ip,
        } | params
        r = SESSION.get(self.API, params=p, timeout=60)
        r.raise_for_status()
        return r.text

    def _parse_xml(self, xml: str) -> ET.Element:
        root = ET.fromstring(xml)
        if error := root.find(".//Errors/Error"):
            raise RuntimeError(f"Namecheap API error: {error.text}")
        return root

    def export_dns(self, domain: str) -> List[DNSRecord]:
        sld, tld = domain.split(".", 1)
        xml = self._call("namecheap.domains.dns.getHosts", {"SLD": sld, "TLD": tld})
        root = self._parse_xml(xml)

        records = []
        for host in root.findall(".//host"):
            record_type = host.attrib["Type"]
            name = host.attrib["Name"] or "@"
            content = host.attrib["Address"]
            ttl = int(host.attrib.get("TTL", "1800"))
            priority = int(host.attrib.get("MXPref", "0")) or None

            # Handle URL redirects
            if record_type in {"URL", "URL301"}:
                continue  # These are handled by export_redirects

            records.append(
                DNSRecord(type=record_type, name=name, content=content, ttl=ttl, priority=priority)
            )
        return records

    def export_forward(self, domain: str) -> List[Forward]:
        sld, tld = domain.split(".", 1)
        xml = self._call(
            "namecheap.domains.dns.getHosts", {"SLD": sld, "TLD": tld, "EmailType": "MXE"}
        )
        root = self._parse_xml(xml)

        forwards = []
        for host in root.findall(".//host"):
            if host.attrib["Type"] == "MXE":
                forwards.append(
                    Forward(from_=f"{host.attrib['Name']}@{domain}", to=host.attrib["Address"])
                )
        return forwards

    def export_redirects(self, domain: str) -> List[Redirect]:
        sld, tld = domain.split(".", 1)
        xml = self._call("namecheap.domains.dns.getHosts", {"SLD": sld, "TLD": tld})
        root = self._parse_xml(xml)

        redirects = []
        for host in root.findall(".//host"):
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

    def set_ns(self, domain: str, ns1: str, ns2: str):
        sld, tld = domain.split(".", 1)
        self._call(
            "namecheap.domains.dns.setCustom",
            {"SLD": sld, "TLD": tld, "Nameservers": f"{ns1},{ns2}"},
        )


class NameDotCom:
    API = "https://api.name.com/v4"

    def __init__(self):
        if not (os.getenv("NAMEDOTCOM_USER") and os.getenv("NAMEDOTCOM_TOKEN")):
            raise CFToolError("Name.com creds missing")
        self.auth = (os.getenv("NAMEDOTCOM_USER"), os.getenv("NAMEDOTCOM_TOKEN"))

    def export_dns(self, domain: str) -> list[DNSRecord]:
        r = SESSION.get(f"{self.API}/domains/{domain}/records", auth=self.auth, timeout=60)
        if r.status_code != 200:
            raise RuntimeError(r.text)
        return [
            DNSRecord(
                type=rec["type"],
                name=rec["host"] or "@",
                content=rec["answer"],
                ttl=rec.get("ttl"),
                priority=rec.get("priority"),
            )
            for rec in r.json().get("records", [])
        ]

    def export_forward(self, domain: str) -> list[Forward]:
        r = SESSION.get(
            f"{self.API}/domains/{domain}/email/forwardings", auth=self.auth, timeout=60
        )
        if r.status_code != 200:
            return []
        data = r.json().get("emailForwarding", [])
        return [
            Forward(from_=f["email"] or f["alias"] + f"@{domain}", to=f["forwardTo"]) for f in data
        ]

    def export_redirects(self, domain: str) -> list[Redirect]:
        r = SESSION.get(f"{self.API}/domains/{domain}/url/forwardings", auth=self.auth, timeout=60)
        if r.status_code != 200:
            return []
        data = r.json().get("urlForwarding", [])
        redirects = []
        for rd in data:
            source = rd.get("source") or rd.get("subdomain", "@")
            destination = rd.get("forwardTo") or rd.get("destination")
            code = 301 if rd.get("type", "redirect").lower() == "redirect" else 302
            redirects.append(Redirect(source=source, destination=destination, code=code))
        return redirects

    def set_ns(self, domain: str, ns1: str, ns2: str):
        r = SESSION.post(
            f"{self.API}/domains/{domain}:setNameservers",
            auth=self.auth,
            json={"nameservers": [ns1, ns2]},
            timeout=60,
        )
        if r.status_code >= 400:
            raise RuntimeError(r.text)


PROVIDERS = {"namecheap": Namecheap(), "name.com": NameDotCom()}


def detect_provider(domain: str) -> str:
    for name, prov in PROVIDERS.items():
        try:
            prov.export_dns(domain)  # type: ignore[attr-defined]
            return name
        except Exception:
            continue
    raise RuntimeError(f"No provider matched {domain}")


# ──────────────────────────────────────────────────────────────────────────────
#  Cloudflare helpers
# ──────────────────────────────────────────────────────────────────────────────
def cf_req(m: str, p: str, **kw):
    r = SESSION.request(m, f"{CF_API}{p}", timeout=60, **kw)
    if r.status_code >= 400:
        raise RuntimeError(r.text[:200])
    data = r.json()
    if not data.get("success"):
        raise RuntimeError(data)
    return data["result"]


def cf_zone(domain: str) -> Dict:
    z = cf_req("GET", f"/zones?name={domain}")
    return z[0] if z else cf_req("POST", "/zones", json={"name": domain})


def cf_records(zone_id: str) -> Dict[tuple, DNSRecord]:
    return {
        DNSRecord.from_cf(r).key(): DNSRecord.from_cf(r)
        for r in cf_req("GET", f"/zones/{zone_id}/dns_records?per_page=5000")
    }


def cf_upsert(zone_id: str, rec: DNSRecord):
    cf_req("POST", f"/zones/{zone_id}/dns_records", json=rec.payload())


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


def cf_email_rules(zone_id: str, fwds: Sequence[Forward]):
    # ensure Email Routing is ON
    cf_req("PUT", f"/zones/{zone_id}/email/routing/settings", json={"enabled": True})
    # remove existing rules
    for r in cf_req("GET", f"/zones/{zone_id}/email/routing/rules"):
        cf_req("DELETE", f"/zones/{zone_id}/email/routing/rules/{r['id']}")
    # create new
    for f in fwds:
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


def cf_bulk_redirect(zone_id: str, redirects: Sequence[Redirect]):
    if not redirects:
        return
    # create or update a Bulk Redirect list
    lsts = cf_req(
        "GET", f"/accounts/{cf_account()}/rules/lists?page=1&per_page=50&match=name&name=url‑tool"
    )
    lst = (
        lsts[0]
        if lsts
        else cf_req(
            "POST",
            f"/accounts/{cf_account()}/rules/lists",
            json={"name": "url‑tool", "kind": "redirect"},
        )
    )
    items = [
        {"source_url": r.source, "target_url": r.destination, "status_code": r.code}
        for r in redirects
    ]
    cf_req("PUT", f"/accounts/{cf_account()}/rules/lists/{lst['id']}", json={"items": items})
    # attach list as ruleset (once)
    sets = cf_req("GET", f"/zones/{zone_id}/rulesets?phase=http_request_redirect")
    if not sets:
        cf_req(
            "POST",
            f"/zones/{zone_id}/rulesets",
            json={
                "name": "bulk‑redirect",
                "kind": "zone",
                "phase": "http_request_redirect",
                "rules": [
                    {
                        "action": "redirect",
                        "expression": "true",
                        "action_parameters": {"redirect_list_id": lst["id"]},
                    }
                ],
            },
        )


def cf_account() -> str:
    return cf_req("GET", "/user")["account"]["id"]


FORWARD_MX = [
    DNSRecord("MX", "@", "mx1.mail.cloudflare.net", priority=10, ttl=300),
    DNSRecord("MX", "@", "mx2.mail.cloudflare.net", priority=20, ttl=300),
]


# ──────────────────────────────────────────────────────────────────────────────
#  EXPORT
# ──────────────────────────────────────────────────────────────────────────────
def cmd_export(domains: List[str]) -> None:
    yaml_out = {}
    for dom in domains:
        prov_name = detect_provider(dom)
        prov = PROVIDERS[prov_name]
        console.print(f"[cyan]export {dom} via {prov_name}[/]")
        recs = [r.__dict__ for r in prov.export_dns(dom)]  # type: ignore[attr-defined]
        fwds = [f.dict(by_alias=True) for f in prov.export_forward(dom)]  # type: ignore[attr-defined]
        reds = [r.dict() for r in prov.export_redirects(dom)]  # type: ignore[attr-defined]
        yaml_out[dom] = {
            "dns_provider": prov_name,
            "origin": None,
            "cache_bypass": [],
            "records": recs,
            "mail_forwarding": fwds,
            "url_redirects": reds,
            "extra_records": [],
        }
    yaml.dump({"domains": yaml_out}, sys.stdout, sort_keys=False)


# ──────────────────────────────────────────────────────────────────────────────
#  APPLY
# ──────────────────────────────────────────────────────────────────────────────
def cmd_apply(cfg_path: Path, dry: bool = False):
    cfg = Config.parse_obj(yaml.safe_load(cfg_path.read_text()))

    tbl = Table("Domain", "dns rows", "new dns", "fwds", "redirects")
    for dom, site in cfg.domains.items():
        zone = cf_zone(dom)
        zid = zone["id"]
        ns1, ns2 = zone["name_servers"][:2]
        existing = cf_records(zid)

        desired = [DNSRecord(**r.dict()) for r in site.records] + [
            DNSRecord(**e.dict()) for e in site.extra_records
        ]
        if site.origin:
            desired.append(DNSRecord("CNAME", "@", site.origin, ttl=300, proxied=True))
        if site.mail_forwarding:
            # replace provider MX with CF MX
            desired = [r for r in desired if r.type != "MX"]
            desired.extend(FORWARD_MX)

        created = 0
        for rec in {d.key(): d for d in desired}.values():
            if rec.key() not in existing and not dry:
                cf_upsert(zid, rec)
                created += 1
        if site.cache_bypass and not dry:
            cf_cache(zid, site.cache_bypass)
        if site.mail_forwarding and not dry:
            cf_email_rules(zid, site.mail_forwarding)
        if site.url_redirects and not dry:
            cf_bulk_redirect(zid, site.url_redirects)

        if not dry:
            PROVIDERS[site.dns_provider].set_ns(dom, ns1, ns2)  # type: ignore[attr-defined]

        tbl.add_row(
            dom,
            str(len(desired)),
            str(created),
            str(len(site.mail_forwarding)),
            str(len(site.url_redirects)),
        )
    console.print(tbl)
    console.print("[green]dry-run[/]" if dry else "[green]apply complete[/]")


# ──────────────────────────────────────────────────────────────────────────────
#  CLI
# ──────────────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Cloudflare export/apply tool")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ex = sub.add_parser("export")
    ex.add_argument("domains", nargs="+")
    aply = sub.add_parser("apply")
    aply.add_argument("config", type=Path)
    aply.add_argument("--dry", action="store_true")
    args = ap.parse_args()
    if args.cmd == "export":
        cmd_export(args.domains)
    else:
        cmd_apply(args.config, args.dry)


if __name__ == "__main__":
    main()
