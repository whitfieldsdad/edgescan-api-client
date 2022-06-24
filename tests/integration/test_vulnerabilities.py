from edgescan.data.types.vulnerability import Vulnerability

import tests.client as client
import unittest


class VulnerabilityTestCases(unittest.TestCase):
    edgescan_api = client.get_client()

    @classmethod
    def setUpClass(cls):
        try:
            next(cls.edgescan_api.iter_vulnerabilities())
        except StopIteration:
            raise unittest.SkipTest("No vulnerabilities found")

    def test_get_vulnerabilities(self):
        rows = self.edgescan_api.iter_vulnerabilities()
        self.assertTrue(all(isinstance(row, Vulnerability) for row in rows))

    def test_count_vulnerabilities(self):
        total = self.edgescan_api.count_vulnerabilities()
        self.assertGreater(total, 0)
