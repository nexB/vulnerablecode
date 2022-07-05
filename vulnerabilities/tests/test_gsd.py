#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import datetime
from unittest import TestCase

from vulnerabilities.importers.gsd import get_published_date_nvd_nist_gov, get_cvss_str_v_cve_org, get_summary, \
    get_aliases, get_description, get_references


class TestGSDImporter(TestCase):
    def test_get_references(self):
        assert get_references({"references": {
            "reference_data": [
                {
                    "name": "https://kc.mcafee.com/corporate/index?page=content&id=SB10198",
                    "refsource": "CONFIRM",
                    "tags": ["Vendor Advisory"],
                    "url": "https://kc.mcafee.com/corporate/index?page=content&id=SB10198"
                }]
        }}) == ["https://kc.mcafee.com/corporate/index?page=content&id=SB10198"]
        assert get_references({"references": {
            "reference_data": [
                {
                    "name": "https://kc.mcafee.com/corporate/index?page=content&id=SB10198",
                    "refsource": "CONFIRM",
                    "tags": ["Vendor Advisory"],
                    "url": "https://kc.mcafee.com/corporate/index?page=content&id=SB10198"
                }]
        }}) == ["https://kc.mcafee.com/corporate/index?page=content&id=SB10198"]

    def test_get_description(self):
        assert get_description({"description": {
            "description_data": [
                {
                    "lang": "eng",
                    "value": "User Name Disclosure in the server in McAfee Network Data Loss Prevention (NDLP) 9.3.x allows remote attackers to view user information via the appliance web interface."
                }
            ]
        }}) == [
                   "User Name Disclosure in the server in McAfee Network Data Loss Prevention (NDLP) 9.3.x allows remote attackers to view user information via the appliance web interface."]

    def test_get_aliases_cve_org(self):
        assert get_aliases({"CVE_data_meta": {
            "ASSIGNER": "secure@intel.com",
            "ID": "CVE-2017-4017",
            "STATE": "PUBLIC"
        }}) == ["CVE-2017-4017"]
        assert get_aliases({
            "CVE_data_meta": {
                "ASSIGNER": "secure@intel.com",
                "ID": "CVE-2017-4017",
                "STATE": "PUBLIC"
            }, "source": {
                "advisory": "GHSA-v8x6-59g4-5g3w",
                "discovery": "UNKNOWN"
            }
        }) == ["CVE-2017-4017", "GHSA-v8x6-59g4-5g3w"]
        assert get_aliases({"source": {
            "advisory": "GHSA-v8x6-59g4-5g3w",
            "discovery": "UNKNOWN"
        }}) == ["GHSA-v8x6-59g4-5g3w"]

    def test_get_summary(self):
        assert get_summary({"CVE_data_meta": {"TITLE": "DoS vulnerability: Invalid Accent Colors"
                                              }}) == "DoS vulnerability: Invalid Accent Colors"

    def test_get_cvss_str_v_cve_org(self):
        assert get_cvss_str_v_cve_org({"impact": {
            "cvss": {
                "attackComplexity": "LOW",
                "attackVector": "NETWORK",
                "availabilityImpact": "HIGH",
                "baseScore": 5.7,
                "baseSeverity": "MEDIUM",
                "confidentialityImpact": "NONE",
                "integrityImpact": "NONE",
                "privilegesRequired": "LOW",
                "scope": "UNCHANGED",
                "userInteraction": "REQUIRED",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H",
                "version": "3.1"
            }
        }}) == "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H"
        assert get_cvss_str_v_cve_org({"impact": {}}) is None

    def test_get_published_date_nvd_nist_gov(self):
        assert get_published_date_nvd_nist_gov({"publishedDate": "2022-06-23T07:15Z"}) == \
               datetime.datetime(2022, 6, 23, 7, 15, 0, 0).replace(tzinfo=datetime.timezone.utc)
        assert get_published_date_nvd_nist_gov({}) is None
