import tests.client as client
import unittest


class HostTestCases(unittest.TestCase):
    api = client.get_client()

    @classmethod
    def setUpClass(cls):
        try:
            next(cls.api.iter_hosts())
        except StopIteration:
            raise unittest.SkipTest("No hosts found")

    def test_get_hosts(self):
        rows = self.api.iter_hosts()
        self.assertTrue(all(isinstance(row, dict) for row in rows))

    def test_count_hosts(self):
        total = self.api.count_hosts()
        self.assertGreater(total, 0)
