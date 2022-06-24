from edgescan.data.types.host import Host

import tests.client as client
import unittest


class HostTestCases(unittest.TestCase):
    edgescan_api = client.get_client()

    @classmethod
    def setUpClass(cls):
        try:
            next(cls.edgescan_api.iter_hosts())
        except StopIteration:
            raise unittest.SkipTest("No hosts found")

    def test_get_hosts(self):
        rows = self.edgescan_api.iter_hosts()
        self.assertTrue(all(isinstance(row, Host) for row in rows))

    def test_count_hosts(self):
        total = self.edgescan_api.count_hosts()
        self.assertGreater(total, 0)
