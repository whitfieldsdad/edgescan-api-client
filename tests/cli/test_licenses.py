import tests.client as client
import tests.cli.runner as runner
import unittest


class LicenseTestCases(unittest.TestCase):
    edgescan_api = None

    @classmethod
    def setUpClass(cls):
        cls.edgescan_api = client.get_client()
        try:
            next(cls.edgescan_api.iter_licenses())
        except StopIteration:
            raise unittest.SkipTest("No licenses found")

    def test_command_group(self):
        example = next(self.edgescan_api.iter_licenses())
        license_id = example.id

        commands = [
            ['licenses', 'get-license', '--license-id', license_id],
            ['licenses', 'get-licenses'],
            ['licenses', 'get-licenses', '--license-ids', license_id],
            ['licenses', 'count-licenses'],
            ['licenses', 'count-licenses', '--license-ids', license_id],
        ]
        for args in commands:
            result = runner.invoke(*args)
            command = ' '.join(map(str, args))
            with self.subTest(command=command):
                self.assertEqual(0, result.exit_code)
