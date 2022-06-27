import tests.client as client
import tests.cli.runner as runner
import unittest


class AssetTestCases(unittest.TestCase):
    edgescan_api = None

    @classmethod
    def setUpClass(cls):
        cls.edgescan_api = client.get_client()
        try:
            next(cls.edgescan_api.iter_assets())
        except StopIteration:
            raise unittest.SkipTest("No assets found")

    def test_command_group(self):
        asset = next(self.edgescan_api.iter_assets())
        commands = [
            ['assets', 'get-asset', '--asset-id', asset['id']],
            ['assets', 'get-assets'],
            ['assets', 'get-assets', '--asset-ids', asset['id']],
            ['assets', 'count-assets'],
            ['assets', 'count-assets', '--asset-ids', asset['id']],
        ]
        for args in commands:
            result = runner.invoke(*args)
            command = ' '.join(map(str, args))
            with self.subTest(command=command):
                self.assertEqual(0, result.exit_code)
