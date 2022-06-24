from click.testing import CliRunner, Result
from edgescan.cli import cli


def invoke(*args) -> Result:
    runner = CliRunner()
    args = list(map(str, args))
    result = runner.invoke(cli, args)
    if result.exception:
        raise result.exception
    return result
