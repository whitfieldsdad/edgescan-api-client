import tests.client as client
import unittest


class LicenseTestCases(unittest.TestCase):
    api = client.get_client()

    @classmethod
    def setUpClass(cls):
        try:
            next(cls.api.iter_licenses())
        except StopIteration:
            raise unittest.SkipTest("No licenses found")

    def test_get_licenses(self):
        rows = self.api.iter_licenses()
        self.assertTrue(all(isinstance(row, dict) for row in rows))

    def test_count_licenses(self):
        total = self.api.count_licenses()
        self.assertGreater(total, 0)
