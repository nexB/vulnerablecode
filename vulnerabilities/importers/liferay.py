#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
import re
from typing import Dict
from typing import Iterable
from typing import List

import requests
from packageurl import PackageURL
from univers.version_range import RpmVersionRange

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.rpm_utils import rpm_to_purl
from vulnerabilities.utils import get_cwe_id
from vulnerabilities.utils import get_item
from vulnerabilities.utils import requests_with_5xx_retry

logger = logging.getLogger(__name__)

# FIXME: we should use a centralized retry
requests_session = requests_with_5xx_retry(max_retries=5, backoff_factor=1)

import requests
from bs4 import BeautifulSoup
# def fetch_cves() -> Iterable[List[Dict]]:
#     page_no = 1
#     cve_data = None
#     while True:
#         current_url = f"https://access.redhat.com/hydra/rest/securitydata/cve.json?per_page=1000&page={page_no}"  # nopep8
#         try:
#             response = requests_session.get(current_url)
#             if response.status_code != requests.codes.ok:
#                 logger.error(f"Failed to fetch RedHat CVE results from {current_url}")
#                 break
#             cve_data = response.json()
#         except Exception as e:
#             logger.error(f"Failed to fetch RedHat CVE results from {current_url} {e}")
#             break
#         if not cve_data:
#             break
#         page_no += 1
#         yield cve_data



class LifeRayImporter(Importer):
    spdx_license_expression = "CC-BY-4.0"
    
    importer_name = "Liferay Importer"
    url = "https://liferay.dev/portal/security/known-vulnerabilities"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        response = requests.get(self.url)
        soup = BeautifulSoup(response.text, 'html.parser')
        table = soup.find_all(class_='h4 list-group-title text-truncate')
        for i in table:
            page = i.find('a')
            # print(page['href'])
            soup2 = BeautifulSoup(requests.get(page['href']),
                                  'html.parser')
            """
                Find the aliases and rest attributes and save the data
                Pending DO NOT MERGE BROKEN PR
            
            """
        # pages = table.find_all('a')
        # print(pages)
        # return AdvisoryData(
        #     aliases=aliases,
        #     summary=advisory_data.get("bugzilla_description") or "",
        #     affected_packages=affected_packages,
        #     references=references,
        #     weaknesses=cwe_list,
        #     url=resource_url
        #     if resource_url
        #     else "https://access.redhat.com/hydra/rest/securitydata/cve.json",
        # )
        return []

def main():
    importer = LifeRayImporter()
    for advisory_data in importer.advisory_data():
        print(advisory_data)  # Or do something else with the data
main()