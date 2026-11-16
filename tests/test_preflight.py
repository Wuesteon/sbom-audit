import unittest

from sbomaudit import preflight


class PreflightTests(unittest.TestCase):
    def test_reports_missing_tools(self):
        missing = preflight.check(which=lambda t: None if t == "syft" else "/usr/bin/" + t)
        self.assertEqual(missing, ["syft"])

    def test_all_present(self):
        self.assertEqual(preflight.check(which=lambda t: "/x/" + t), [])

    def test_brew_line(self):
        self.assertEqual(preflight.BREW_LINE, "brew install syft osv-scanner gh")


if __name__ == "__main__":
    unittest.main()
