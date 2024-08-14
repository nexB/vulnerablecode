#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
from pathlib import Path

from commoncode import testcase
from packageurl import PackageURL

from vulnerabilities.tests import util_tests
from vulntotal.datasources import vulnerablecode


class TestVulnerableCode(testcase.FileBasedTesting):
    test_data_dir = str(Path(__file__).resolve().parent /
                        "test_data" / "vulnerablecode")

    def test_parse_advisory(self):
        advisory_file = self.get_test_loc("advisory.json")
        with open(advisory_file) as f:
            advisory = json.load(f)
        input_purl = PackageURL.from_string(
            "pkg:maven/org.apache.tomcat/tomcat@10.1.0-M5")
        results = [vulnerablecode.parse_advisory(
            adv, input_purl).to_dict() for adv in advisory]
        expected_file = self.get_test_loc(
            "parse_advisory-expected.json", must_exist=False)
        util_tests.check_results_against_json(results, expected_file)
