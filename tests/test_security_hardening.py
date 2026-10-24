"""Regression tests for the HS-1..HS-5 security hardening.

Run with: python3 -m pytest tests/test_security_hardening.py
(or: python3 -m unittest discover -s tests)

Heavy optional dependencies (selenium, mitmproxy, ...) are stubbed when not
installed so the server module can be imported in CI without them.
"""

import sys
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _stub_module(name, **attrs):
    if name in sys.modules:
        return
    try:
        __import__(name)
        return
    except ImportError:
        pass
    module = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    sys.modules[name] = module


class _Dummy:
    def __init__(self, *args, **kwargs):
        pass

    def __call__(self, *args, **kwargs):
        return _Dummy()


def _install_stubs():
    _stub_module("psutil")
    _stub_module("bs4", BeautifulSoup=_Dummy)
    _stub_module("aiohttp")
    _stub_module("selenium", webdriver=_Dummy())
    for name in (
        "selenium.webdriver",
        "selenium.webdriver.chrome",
        "selenium.webdriver.chrome.options",
        "selenium.webdriver.common",
        "selenium.webdriver.common.by",
        "selenium.webdriver.support",
        "selenium.webdriver.support.ui",
        "selenium.webdriver.support.expected_conditions",
        "selenium.common",
        "selenium.common.exceptions",
    ):
        _stub_module(name)
    sys.modules["selenium.webdriver.chrome.options"].Options = _Dummy
    sys.modules["selenium.webdriver.common.by"].By = _Dummy
    sys.modules["selenium.webdriver.support.ui"].WebDriverWait = _Dummy
    sys.modules["selenium.common.exceptions"].TimeoutException = type("TimeoutException", (Exception,), {})
    sys.modules["selenium.common.exceptions"].WebDriverException = type("WebDriverException", (Exception,), {})
    _stub_module("mitmproxy", http=types.SimpleNamespace())
    _stub_module("mitmproxy.http", HTTPFlow=_Dummy)
    _stub_module("mitmproxy.tools")
    _stub_module("mitmproxy.tools.dump", DumpMaster=_Dummy)
    _stub_module("mitmproxy.options", Options=_Dummy)


_install_stubs()

import hexstrike_server as hs  # noqa: E402


class TestAuthAndBind(unittest.TestCase):
    def test_loopback_detection(self):
        self.assertTrue(hs._is_loopback_host("127.0.0.1"))
        self.assertTrue(hs._is_loopback_host("localhost"))
        self.assertFalse(hs._is_loopback_host("0.0.0.0"))
        self.assertFalse(hs._is_loopback_host("192.168.1.10"))

    def test_command_rejected_without_token(self):
        with mock.patch.object(hs, "API_TOKEN", "test-secret"):
            client = hs.app.test_client()
            response = client.post("/api/command", json={"command": "echo should-not-run"})
            self.assertEqual(response.status_code, 401)

    def test_command_allowed_with_token(self):
        with mock.patch.object(hs, "API_TOKEN", "test-secret"):
            client = hs.app.test_client()
            response = client.post(
                "/api/command",
                json={"command": "echo hexstrike-auth-ok"},
                headers={"Authorization": "Bearer test-secret"},
            )
            self.assertEqual(response.status_code, 200)
            self.assertIn("hexstrike-auth-ok", response.get_json().get("stdout", ""))


class TestFileContainment(unittest.TestCase):
    def setUp(self):
        import tempfile

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name) / "base"
        self.manager = hs.FileOperationsManager(base_dir=str(base))

    def test_normal_file_roundtrip(self):
        self.assertTrue(self.manager.create_file("ok.txt", "hello")["success"])
        self.assertTrue(self.manager.list_files(".")["success"])

    def test_dotdot_escape_blocked(self):
        result = self.manager.create_file("../escape.txt", "pwned")
        self.assertFalse(result["success"])
        self.assertFalse((Path(self.tmp.name) / "escape.txt").exists())

    def test_absolute_path_blocked(self):
        target = str(Path(self.tmp.name) / "absolute.txt")
        result = self.manager.create_file(target, "pwned")
        self.assertFalse(result["success"])
        self.assertFalse(Path(target).exists())

    def test_delete_outside_base_blocked(self):
        outside = Path(self.tmp.name) / "outside.txt"
        outside.write_text("keep me")
        result = self.manager.delete_file("../outside.txt")
        self.assertFalse(result["success"])
        self.assertTrue(outside.exists())


class TestScopeAndBrowser(unittest.TestCase):
    def test_out_of_scope_request_not_sent(self):
        framework = hs.HTTPTestingFramework()
        framework.set_scope("example.com")
        with mock.patch.object(framework.session, "get") as mock_get:
            result = framework.intercept_request("http://169.254.169.254/latest/meta-data/", "GET")
        self.assertFalse(result["success"])
        mock_get.assert_not_called()

    def test_file_scheme_blocked_in_browser_agent(self):
        agent = hs.BrowserAgent()
        result = agent.navigate_and_inspect("file:///etc/passwd")
        self.assertFalse(result["success"])
        self.assertIn("scheme", result["error"])


if __name__ == "__main__":
    unittest.main()
