from unittest import TestCase
from edgescan.data.types.asset import Asset
from tests.client import get_client

import unittest


class AssetIntegrationTestCases(TestCase):
    edgescan_api = get_client()

    @classmethod
    def setUpClass(cls):
        try:
            next(cls.edgescan_api.iter_assets())
        except StopIteration:
            raise unittest.SkipTest("No assets found")

    def test_get_assets(self):
        rows = self.edgescan_api.iter_assets()
        self.assertTrue(all(isinstance(row, Asset) for row in rows))

    def test_count_assets(self):
        total = self.edgescan_api.count_assets()
        self.assertGreater(total, 0)
