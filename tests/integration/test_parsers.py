from typing import Iterator, Iterable, Callable, Any

import itertools
from unittest import TestCase

import random

import edgescan.data.parser
from edgescan import Client, Asset, Host, License, Vulnerability

MAX_SAMPLE_SIZE = 1000


class ParserTestCases(TestCase):
    api = Client()
    maxDiff = None

    def get_random_sample(self, rows: Iterator[dict]) -> Iterable[dict]:
        rows = list(rows)
        random.shuffle(rows)
        return list(itertools.islice(rows, MAX_SAMPLE_SIZE))

    def _test_parser(self, rows: Iterator[dict], parser: Callable[[dict], Any], expected_return_type: Any):
        for row in self.get_random_sample(rows):
            with self.subTest(id=row['id']):
                obj = parser(row)
                self.assertIsInstance(obj, expected_return_type)

    def test_parse_assets(self):
        self._test_parser(self.api.iter_assets(), edgescan.data.parser.parse_asset, Asset)

    def test_parse_hosts(self):
        self._test_parser(self.api.iter_hosts(), edgescan.data.parser.parse_host, Host)

    def test_parse_licenses(self):
        self._test_parser(self.api.iter_licenses(), edgescan.data.parser.parse_license, License)

    def test_parse_vulnerabilities(self):
        self._test_parser(self.api.iter_vulnerabilities(), edgescan.data.parser.parse_vulnerability, Vulnerability)
