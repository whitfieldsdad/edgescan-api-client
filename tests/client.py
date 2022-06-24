from edgescan.api.client import Client
from edgescan.errors import MissingCredentialsError

import unittest


def get_client():
    try:
        return Client()
    except MissingCredentialsError:
        raise unittest.SkipTest("No API key provided")
