#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import json
import logging
import os

import dateparser
from typing import Iterable
from fetchcode.vcs.git import fetch_via_git
from vulnerabilities.importer import AdvisoryData, Reference
from vulnerabilities.importer import Importer


logger = logging.getLogger(__name__)


class GSDImporter(Importer):
    spdx_license_expression = "CC0-1.0"
    license_url = "https://github.com/cloudsecurityalliance/gsd-database/blob/main/LICENSE"
    gsd_url = "git+https://github.com/cloudsecurityalliance/gsd-database"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        # for file in fork_and_get_files(self.gsd_url):
        #     print(file)
        x = '''{
    "GSD": {
        "alias": "CVE-2017-4017",
        "description": "User Name Disclosure in the server in McAfee Network Data Loss Prevention (NDLP) 9.3.x allows remote attackers to view user information via the appliance web interface.",
        "id": "GSD-2017-4017"
    },
    "namespaces": {
        "cve.org": {
            "CVE_data_meta": {
                "ASSIGNER": "secure@intel.com",
                "ID": "CVE-2017-4017",
                "STATE": "PUBLIC"
            },
            "affects": {
                "vendor": {
                    "vendor_data": [
                        {
                            "product": {
                                "product_data": [
                                    {
                                        "product_name": "Network Data Loss Prevention (NDLP)",
                                        "version": {
                                            "version_data": [
                                                {
                                                    "version_value": "9.3.x"
                                                }
                                            ]
                                        }
                                    }
                                ]
                            },
                            "vendor_name": "McAfee"
                        }
                    ]
                }
            },
            "data_format": "MITRE",
            "data_type": "CVE",
            "data_version": "4.0",
            "description": {
                "description_data": [
                    {
                        "lang": "eng",
                        "value": "User Name Disclosure in the server in McAfee Network Data Loss Prevention (NDLP) 9.3.x allows remote attackers to view user information via the appliance web interface."
                    }
                ]
            },
            "problemtype": {
                "problemtype_data": [
                    {
                        "description": [
                            {
                                "lang": "eng",
                                "value": "User Name Disclosure"
                            }
                        ]
                    }
                ]
            },
            "references": {
                "reference_data": [
                    {
                        "name": "https://kc.mcafee.com/corporate/index?page=content&id=SB10198",
                        "refsource": "CONFIRM",
                        "url": "https://kc.mcafee.com/corporate/index?page=content&id=SB10198"
                    },
                    {
                        "name": "1038523",
                        "refsource": "SECTRACK",
                        "url": "http://www.securitytracker.com/id/1038523"
                    }
                ]
            }
        },
        "nvd.nist.gov": {
            "configurations": {
                "CVE_data_version": "4.0",
                "nodes": [
                    {
                        "children": [],
                        "cpe_match": [
                            {
                                "cpe23Uri": "cpe:2.3:a:mcafee:network_data_loss_prevention:*:*:*:*:*:*:*:*",
                                "cpe_name": [],
                                "versionEndIncluding": "9.3.0",
                                "vulnerable": true
                            }
                        ],
                        "operator": "OR"
                    }
                ]
            },
            "cve": {
                "CVE_data_meta": {
                    "ASSIGNER": "secure@intel.com",
                    "ID": "CVE-2017-4017"
                },
                "data_format": "MITRE",
                "data_type": "CVE",
                "data_version": "4.0",
                "description": {
                    "description_data": [
                        {
                            "lang": "en",
                            "value": "User Name Disclosure in the server in McAfee Network Data Loss Prevention (NDLP) 9.3.x allows remote attackers to view user information via the appliance web interface."
                        }
                    ]
                },
                "problemtype": {
                    "problemtype_data": [
                        {
                            "description": [
                                {
                                    "lang": "en",
                                    "value": "CWE-200"
                                }
                            ]
                        }
                    ]
                },
                "references": {
                    "reference_data": [
                        {
                            "name": "https://kc.mcafee.com/corporate/index?page=content&id=SB10198",
                            "refsource": "CONFIRM",
                            "tags": [
                                "Vendor Advisory"
                            ],
                            "url": "https://kc.mcafee.com/corporate/index?page=content&id=SB10198"
                        },
                        {
                            "name": "1038523",
                            "refsource": "SECTRACK",
                            "tags": [],
                            "url": "http://www.securitytracker.com/id/1038523"
                        }
                    ]
                }
            },
            "impact": {
                "baseMetricV2": {
                    "cvssV2": {
                        "accessComplexity": "LOW",
                        "accessVector": "NETWORK",
                        "authentication": "NONE",
                        "availabilityImpact": "NONE",
                        "baseScore": 5.0,
                        "confidentialityImpact": "PARTIAL",
                        "integrityImpact": "NONE",
                        "vectorString": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
                        "version": "2.0"
                    },
                    "exploitabilityScore": 10.0,
                    "impactScore": 2.9,
                    "obtainAllPrivilege": false,
                    "obtainOtherPrivilege": false,
                    "obtainUserPrivilege": false,
                    "severity": "MEDIUM",
                    "userInteractionRequired": false
                },
                "baseMetricV3": {
                    "cvssV3": {
                        "attackComplexity": "LOW",
                        "attackVector": "NETWORK",
                        "availabilityImpact": "NONE",
                        "baseScore": 5.3,
                        "baseSeverity": "MEDIUM",
                        "confidentialityImpact": "LOW",
                        "integrityImpact": "NONE",
                        "privilegesRequired": "NONE",
                        "scope": "UNCHANGED",
                        "userInteraction": "NONE",
                        "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        "version": "3.0"
                    },
                    "exploitabilityScore": 3.9,
                    "impactScore": 1.4
                }
            },
            "lastModifiedDate": "2017-07-08T01:29Z",
            "publishedDate": "2017-05-17T21:29Z"
        }
    }
}'''
        raw_data = json.loads(x)

        # GSD json
        GSD = raw_data.get("GSD") or {}
        alias = GSD.get("alias") or ""
        description = GSD.get("description") or ""
        idx = GSD.get("id") or ""

        namespaces = raw_data.get("namespaces") or {}
        cve_org = namespaces.get("cve.org") or {}
        nvd_nist_gov = namespaces.get("nvd.nist.gov") or {}

        yield AdvisoryData( aliases=aliases,
                            summary=summary,
                            references=references,
                            date_published=get_published_date_nvd_nist_gov(nvd_nist_gov))


def get_summary(cve) -> str:
    CVE_data_meta = cve.get("CVE_data_meta") or {}
    return CVE_data_meta.get("TITLE") or ""


def get_cvss_str_v_cve_org(cve) -> str:
    impact = cve.get("impact") or {}
    cvss = impact.get("cvss") or {}
    return cvss.get("vectorString")


def get_description(cve) -> [str]:
    description = cve.get("description") or {}
    description_data = description.get("description_data") or []
    return [desc['value'] for desc in description_data if desc['value']]


def get_references(cve,severities) -> [str]:
    references = cve.get("references") or {}
    reference_data = references.get("reference_data") or []
    return [Reference(url=ref["url"]) for ref in reference_data if ref['url']]


def get_aliases(cve) -> [str]:
    CVE_data_meta = cve.get("CVE_data_meta") or {}
    alias = CVE_data_meta.get("ID")

    source = cve.get("source") or {}
    advisory = source.get("advisory")

    aliases = []
    if alias:
        aliases.append(alias)
    if advisory:
        aliases.append(advisory)
    return aliases


def get_published_date_nvd_nist_gov(nvd_nist_gov):
    publishedDate = nvd_nist_gov.get("publishedDate")
    return publishedDate and dateparser.parse(publishedDate)


def get_nvd_nist_gov_details(nvd_nist_gov):
    configurations = nvd_nist_gov.get("configurations") or {}
    lastModifiedDate = nvd_nist_gov.get("lastModifiedDate")


def get_severities_nvd_nist_gov(nvd_nist_gov):
    impact = nvd_nist_gov.get("impact") or {}
    baseMetricV2 = impact.get("baseMetricV2") or {}
    cvssV2 =
    severity = baseMetricV2.get("severity")

    baseMetricV3 = impact.get("baseMetricV2") or {}
    cvssV3 =



def get_severities_cve_org(cve_org):
    impact = cve_org.get("impact") or {}



def ForkError():
    pass



def fork_and_get_files(url) -> dict:
    try:
        fork_directory = fetch_via_git(url=url)
    except Exception as e:
        logger.error(f"Can't clone url {url}")
        raise ForkError() from e

    advisory_dirs = os.path.join(fork_directory.dest_dir, "1999")
    for root, _, files in os.walk(advisory_dirs):
        for file in files:
            if not file.endswith(".json"):
                logger.warning(f"unsupported file {file}")
            else:
                with open(os.path.join(root, file), "r") as f:
                    yield f.read()
