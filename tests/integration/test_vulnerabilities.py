import tests.client as client
import unittest


class VulnerabilityTestCases(unittest.TestCase):
    api = client.get_client()

    @classmethod
    def setUpClass(cls):
        try:
            next(cls.api.iter_vulnerabilities())
        except StopIteration:
            raise unittest.SkipTest("No vulnerabilities found")

    def test_get_vulnerabilities(self):
        rows = self.api.iter_vulnerabilities()
        self.assertTrue(all(isinstance(row, dict) for row in rows))

    def test_count_vulnerabilities(self):
        total = self.api.count_vulnerabilities()
        self.assertGreater(total, 0)
