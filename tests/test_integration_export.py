import importlib

import requests
import yaml


class _Resp:
    def __init__(self, *, status_code: int = 200, text: str = "", json_data=None):
        self.status_code = status_code
        self.text = text
        self._json_data = json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(self.text)

    def json(self):
        return self._json_data


def test_cmd_export_cloudflare_dns_fallback(monkeypatch, capsys):
    monkeypatch.setenv("CF_API_TOKEN", "test-token")
    monkeypatch.setenv("MAILGUN_API_KEY", "")

    def fake_get(url, *args, **kwargs):
        if url == "https://checkip.amazonaws.com":
            return _Resp(text="203.0.113.10\n")
        raise AssertionError(f"unexpected GET {url}")

    monkeypatch.setattr(requests, "get", fake_get)

    m = importlib.import_module("cftool.main")

    class RegistrarWithNoDns(m.BaseProvider):
        def export_dns(self, domain: str):
            return []

        def export_forward(self, domain: str):
            return []

        def export_redirects(self, domain: str):
            return []

        def has_domain(self, domain: str) -> bool:
            return True

        def set_ns(self, domain: str, ns):
            return None

    monkeypatch.setattr(m, "PROVIDERS", {"name.com": RegistrarWithNoDns()})

    monkeypatch.setattr(m, "cf_zone_lookup", lambda domain: {"id": "zone-1"})

    a = m.DNSRecord(type="A", name="@", content="1.2.3.4", proxied=False)
    monkeypatch.setattr(m, "cf_records", lambda zone_id, domain: {a.key(): a})
    monkeypatch.setattr(m, "cf_export_email_forwarding", lambda zone_id, domain: [])

    m.cmd_export(["example.com"])
    out, _ = capsys.readouterr()

    data = yaml.safe_load(out)
    site = data["domains"]["example.com"]
    assert site["registrar"] == "name.com"
    assert site["dns_provider"] == "cloudflare"
    assert {"type": "A", "name": "@", "content": "1.2.3.4", "proxied": False} in site["records"]


def test_cmd_export_cloudflare_mail_forwarding_collapse(monkeypatch, capsys):
    monkeypatch.setenv("CF_API_TOKEN", "test-token")
    monkeypatch.setenv("MAILGUN_API_KEY", "")

    def fake_get(url, *args, **kwargs):
        if url == "https://checkip.amazonaws.com":
            return _Resp(text="203.0.113.10\n")
        raise AssertionError(f"unexpected GET {url}")

    monkeypatch.setattr(requests, "get", fake_get)

    m = importlib.import_module("cftool.main")

    class RegistrarWithNoDns(m.BaseProvider):
        def export_dns(self, domain: str):
            return []

        def export_forward(self, domain: str):
            return []

        def export_redirects(self, domain: str):
            return []

        def has_domain(self, domain: str) -> bool:
            return True

        def set_ns(self, domain: str, ns):
            return None

    monkeypatch.setattr(m, "PROVIDERS", {"name.com": RegistrarWithNoDns()})
    monkeypatch.setattr(m, "cf_zone_lookup", lambda domain: {"id": "zone-1"})

    mx1 = m.DNSRecord(type="MX", name="@", content="route1.mx.cloudflare.net.", ttl=1, priority=91)
    mx2 = m.DNSRecord(type="MX", name="@", content="route2.mx.cloudflare.net.", ttl=1, priority=4)
    mx3 = m.DNSRecord(type="MX", name="@", content="route3.mx.cloudflare.net.", ttl=1, priority=68)
    spf = m.DNSRecord(
        type="TXT", name="@", content='"v=spf1 include:_spf.mx.cloudflare.net ~all"', ttl=1
    )
    dkim = m.DNSRecord(
        type="TXT", name="cf2024-1._domainkey", content='"v=DKIM1; h=sha256; k=rsa; p=abc"', ttl=1
    )
    a = m.DNSRecord(type="A", name="@", content="1.2.3.4", proxied=False)
    monkeypatch.setattr(
        m,
        "cf_records",
        lambda zone_id, domain: {r.key(): r for r in [mx1, mx2, mx3, spf, dkim, a]},
    )

    monkeypatch.setattr(
        m,
        "cf_export_email_forwarding",
        lambda zone_id, domain: [m.Forward(from_=f"*@{domain}", to="earonesty@gmail.com")],
    )

    m.cmd_export(["bobchart.com"])
    out, _ = capsys.readouterr()

    data = yaml.safe_load(out)
    site = data["domains"]["bobchart.com"]
    assert {"from": "*@bobchart.com", "to": "earonesty@gmail.com"} in site["mail_forwarding"]
    assert all(r["type"] != "MX" for r in site["records"])
    assert all("_spf.mx.cloudflare.net" not in r.get("content", "") for r in site["records"])
    assert all("DKIM1" not in r.get("content", "") for r in site["records"])


def test_cmd_transfer_namecom_dry_run_writes_plan_without_mutation(monkeypatch, tmp_path):
    monkeypatch.setenv("CF_API_TOKEN", "test-token")
    monkeypatch.setenv("NAMEDOTCOM_USER", "user")
    monkeypatch.setenv("NAMEDOTCOM_TOKEN", "token")

    def fake_get(url, *args, **kwargs):
        if url == "https://checkip.amazonaws.com":
            return _Resp(text="203.0.113.10\n")
        raise AssertionError(f"unexpected GET {url}")

    monkeypatch.setattr(requests, "get", fake_get)

    m = importlib.import_module("cftool.main")
    provider = m.NameDotCom()
    monkeypatch.setattr(provider, "list_domains", lambda: [{"domainName": "example.com"}])
    monkeypatch.setattr(
        provider,
        "get_domain",
        lambda domain: {
            "domainName": domain,
            "locked": True,
            "nameservers": ["ns1.name.com", "ns2.name.com"],
        },
    )

    def unexpected_mutation(*args, **kwargs):
        raise AssertionError("dry run should not mutate")

    monkeypatch.setattr(provider, "set_ns", unexpected_mutation)
    monkeypatch.setattr(provider, "unlock", unexpected_mutation)
    monkeypatch.setattr(provider, "get_auth_code", unexpected_mutation)
    monkeypatch.setattr(m, "PROVIDERS", {"name.com": provider})
    monkeypatch.setattr(
        m,
        "cf_zone_lookup",
        lambda domain: {
            "id": "zone-1",
            "status": "pending",
            "name_servers": ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"],
        },
    )

    report = tmp_path / "plan.csv"
    m.cmd_transfer_namecom(report_path=report)

    rows = report.read_text().splitlines()
    assert rows[0].startswith("domain,action,cf_zone_id")
    assert "example.com,wait_for_cloudflare_active,zone-1,pending" in rows[1]


def test_cmd_transfer_namecom_execute_writes_auth_codes_private(monkeypatch, tmp_path):
    monkeypatch.setenv("CF_API_TOKEN", "test-token")
    monkeypatch.setenv("NAMEDOTCOM_USER", "user")
    monkeypatch.setenv("NAMEDOTCOM_TOKEN", "token")

    def fake_get(url, *args, **kwargs):
        if url == "https://checkip.amazonaws.com":
            return _Resp(text="203.0.113.10\n")
        raise AssertionError(f"unexpected GET {url}")

    monkeypatch.setattr(requests, "get", fake_get)

    m = importlib.import_module("cftool.main")
    provider = m.NameDotCom()
    calls = []
    monkeypatch.setattr(provider, "list_domains", lambda: [{"domainName": "example.com"}])
    monkeypatch.setattr(
        provider,
        "get_domain",
        lambda domain: {
            "domainName": domain,
            "locked": True,
            "nameservers": ["ns1.name.com", "ns2.name.com"],
        },
    )
    monkeypatch.setattr(provider, "set_ns", lambda domain, ns: calls.append(("set_ns", domain, ns)))
    monkeypatch.setattr(provider, "unlock", lambda domain: calls.append(("unlock", domain)))
    monkeypatch.setattr(provider, "get_auth_code", lambda domain: "secret-epp")
    monkeypatch.setattr(m, "PROVIDERS", {"name.com": provider})
    monkeypatch.setattr(
        m,
        "cf_zone",
        lambda domain: {
            "id": "zone-1",
            "status": "active",
            "name_servers": ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"],
        },
    )

    report = tmp_path / "plan.csv"
    auth_codes = tmp_path / "auth.csv"
    m.cmd_transfer_namecom(execute=True, auth_codes_path=auth_codes, report_path=report)

    assert calls == [
        ("set_ns", "example.com", ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"]),
        ("unlock", "example.com"),
    ]
    assert auth_codes.read_text() == "domain,auth_code\nexample.com,secret-epp\n"
    assert oct(auth_codes.stat().st_mode & 0o777) == "0o600"
