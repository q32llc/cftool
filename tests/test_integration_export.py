from cftool.main import cmd_export


class DummyProvider:
    def __init__(self, name):
        self.name = name

    def export_dns(self, domain):
        return []

    def export_forward(self, domain):
        return []

    def export_redirects(self, domain):
        return []

    def set_ns(self, domain, ns1, ns2):
        pass


def test_cmd_export_detection(tmp_path, capsys):
    cmd_export(["q32.com", "drawme.io"])
    out, err = capsys.readouterr()
    print(out)
    assert "q32.com" in out
    assert "drawme.io" in out
    assert "name.com" in out
    assert "namecheap" in out
    assert "cloudflare" in out
