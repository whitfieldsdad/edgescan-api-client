import tests.client as client
import tests.cli.runner as runner
import unittest


class VulnerabilityTestCases(unittest.TestCase):
    edgescan_api = None

    @classmethod
    def setUpClass(cls):
        cls.edgescan_api = client.get_client()
        try:
            next(cls.edgescan_api.iter_vulnerabilities())
        except StopIteration:
            raise unittest.SkipTest("No vulnerabilities found")

    def test_command_group(self):
        vulnerability = next(self.edgescan_api.iter_vulnerabilities())

        commands = [
            ['vulnerabilities', 'get-vulnerability', '--vulnerability-id', vulnerability.id],
            ['vulnerabilities', 'get-vulnerabilities'],
            ['vulnerabilities', 'get-vulnerabilities', '--vulnerability-ids', vulnerability.id],
            ['vulnerabilities', 'count-vulnerabilities'],
            ['vulnerabilities', 'count-vulnerabilities', '--vulnerability-ids', vulnerability.id],
        ]
        for args in commands:
            result = runner.invoke(*args)
            command = ' '.join(map(str, args))
            with self.subTest(command=command):
                self.assertEqual(0, result.exit_code)
