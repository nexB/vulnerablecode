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
from fetchcode.vcs.git import fetch_via_git
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importers.gitlab import ForkError

logger = logging.getLogger(__name__)


class GSDImporter(Importer):
    spdx_license_expression = "CC0-1.0"
    license_url = "https://github.com/cloudsecurityalliance/gsd-database/blob/main/LICENSE"
    gsd_url = "git+https://github.com/cloudsecurityalliance/gsd-database"

    def advisory_data(self):
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

        return AdvisoryData(aliases=aliases,
                            summary=summary,
                            affected_packages=affected_packages,
                            references=references,
                            date_published=date_published, )


def get_cve_org_details(cve_org):
    CVE_data_meta = cve_org.get("CVE_data_meta") or {}
    if CVE_data_meta:
        ASSIGNER = CVE_data_meta.get("ASSIGNER") or ""
        ID = CVE_data_meta.get("ID") or ""
        STATE = CVE_data_meta.get("STATE") or ""

    affects = cve_org.get("affects") or {}  # TODO

    data_format = cve_org.get("data_format") or ""
    data_type = cve_org.get("data_type") or ""
    data_version = cve_org.get("data_version") or ""

    description = cve_org.get("description") or {}
    if description:
        description_data = description.get("description_data") or {}
        description_value = description_data.get("value") or ""

    problem_type = cve_org.get("problemtype") or {}
    if problem_type:
        problemtype_data = problem_type.get("problemtype") or {}
        description = problemtype_data.get("description") or {}
        summary = description.get("value") or ""  # problemtype

    references = cve_org.get("references") or {}


def get_cve_references(references):
    pass


def get_nvd_nist_gov_details(nvd_nist_gov):
    configurations = nvd_nist_gov.get("configurations") or {}
    cve = nvd_nist_gov.get("cve") or {}
    impact = nvd_nist_gov.get("impact") or {}

    lastModifiedDate = nvd_nist_gov.get("lastModifiedDate")  # not used
    publishedDate = nvd_nist_gov.get("publishedDate")


def get_serverity():
    pass


def get_cwe():
    pass


def get_aliases_nvd():
    """
    >>> get_aliases()
    Returns:

    """

    pass


def get_description():
    """
    >>> get_description()
    Returns:

    """
    pass


def get_references(nvd_nist_gov_cve) -> [str]:
    """
    >>> get_description({"references": {
          "reference_data": [
            {
              "name": "https://kc.mcafee.com/corporate/index?page=content&id=SB10198",
              "refsource": "CONFIRM",
              "tags": ["Vendor Advisory"],
              "url": "https://kc.mcafee.com/corporate/index?page=content&id=SB10198"
            }]
        }})
    >>> ["https://kc.mcafee.com/corporate/index?page=content&id=SB10198"]
    """
    references = nvd_nist_gov_cve.get("references") or {}
    reference_data = references.get("reference_data") or []
    return [ref['url'] for ref in reference_data if ref['url']]


def fork_and_get_files(url) -> dict:
    try:
        fork_directory = fetch_via_git(url=url)
    except Exception as e:
        logger.error(f"Can't clone url {url}")
        raise ForkError(url) from e

    advisory_dirs = os.path.join(fork_directory.dest_dir, "1999")
    for root, _, files in os.walk(advisory_dirs):
        for file in files:
            if not file.endswith(".json"):
                logger.warning(f"unsupported file {file}")
            else:
                with open(os.path.join(root, file), "r") as f:
                    yield f.read()
