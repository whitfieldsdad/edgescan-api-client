from unittest import TestCase
from tests.client import get_client

import unittest


class AssetIntegrationTestCases(TestCase):
    api = get_client()

    @classmethod
    def setUpClass(cls):
        try:
            next(cls.api.iter_assets())
        except StopIteration:
            raise unittest.SkipTest("No assets found")

    def test_get_assets(self):
        rows = self.api.iter_assets()
        self.assertTrue(all(isinstance(row, dict) for row in rows))

    def test_count_assets(self):
        total = self.api.count_assets()
        self.assertGreater(total, 0)
