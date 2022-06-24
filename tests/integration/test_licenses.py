from edgescan.data.types.license import License

import tests.client as client
import unittest


class LicenseTestCases(unittest.TestCase):
    edgescan_api = client.get_client()

    @classmethod
    def setUpClass(cls):
        try:
            next(cls.edgescan_api.iter_licenses())
        except StopIteration:
            raise unittest.SkipTest("No licenses found")

    def test_get_licenses(self):
        rows = self.edgescan_api.iter_licenses()
        self.assertTrue(all(isinstance(row, License) for row in rows))

    def test_count_licenses(self):
        total = self.edgescan_api.count_licenses()
        self.assertGreater(total, 0)
