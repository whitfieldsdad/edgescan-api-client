import tests.client as client
import tests.cli.runner as runner
import unittest


class HostTestCases(unittest.TestCase):
    edgescan_api = None

    @classmethod
    def setUpClass(cls):
        cls.edgescan_api = client.get_client()
        try:
            next(cls.edgescan_api.iter_hosts())
        except StopIteration:
            raise unittest.SkipTest("No hosts found")

    def test_command_group(self):
        host = next(self.edgescan_api.iter_hosts())
        commands = [
            ['hosts', 'get-host', '--host-id', host['id']],
            ['hosts', 'get-hosts'],
            ['hosts', 'get-hosts', '--host-ids', host['id']],
            ['hosts', 'count-hosts'],
            ['hosts', 'count-hosts', '--host-ids', host['id']],
        ]
        for args in commands:
            result = runner.invoke(*args)
            command = ' '.join(map(str, args))
            with self.subTest(command=command):
                self.assertEqual(0, result.exit_code)
