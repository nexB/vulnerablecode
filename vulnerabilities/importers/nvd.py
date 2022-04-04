# Copyright (c)  nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an 'AS IS' BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import gzip
import json
from datetime import date
from typing import Iterable

import requests
from dateutil import parser as dateparser
from django.db.models.query import QuerySet

from vulnerabilities.helpers import get_item
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.improver import Improver
from vulnerabilities.improver import Inference
from vulnerabilities.models import Advisory
from vulnerabilities.severity_systems import SCORING_SYSTEMS


class NVDImporter(Importer):
    spdx_license_expression = "TBD"

    def advisory_data(self):
        advisory_data = []
        current_year = date.today().year
        # NVD json feeds start from 2002.
        for year in range(2002, current_year + 1):
            download_url = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
            data = fetch(download_url)
            advisory_data.extend(to_advisories(data))
        return advisory_data


# Isolating network calls for simplicity of testing
def fetch(url):
    gz_file = requests.get(url)
    data = gzip.decompress(gz_file.content)
    return json.loads(data)


def extract_summary(cve_item):
    """
    Return a summary for a given CVE item.
    """
    # In 99% of cases len(cve_item['cve']['description']['description_data']) == 1 , so
    # this usually returns  cve_item['cve']['description']['description_data'][0]['value']
    # In the remaining 1% cases this returns the longest summary.
    summaries = []
    for desc in get_item(cve_item, "cve", "description", "description_data") or []:
        if desc.get("value"):
            summaries.append(desc["value"])
    return max(summaries, key=len) if summaries else None


def to_advisories(nvd_data):
    """
    Yield AdvisoryData objects from a NVD json feed.
    """
    for cve_item in nvd_data.get("CVE_Items") or []:
        cpes = extract_cpes(cve_item)
        if related_to_hardware(cpes):
            continue

        aliases = []
        cve_id = get_item(cve_item, "cve", "CVE_data_meta", "ID")
        ref_urls = extract_reference_urls(cve_item)
        references = []
        severity_scores = list(extract_severity_scores(cve_item))
        for cpe in cpes:
            references.append(
                Reference(
                    reference_id=cpe,
                )
            )
        references.append(
            Reference(
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                reference_id=cve_id,
                severities=severity_scores,
            )
        )
        if "https://nvd.nist.gov/vuln/detail/{cve_id}" in ref_urls:
            ref_urls.remove(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
        references.extend([Reference(url=url) for url in ref_urls])
        if cve_id:
            aliases.append(cve_id)
        summary = extract_summary(cve_item)
        yield AdvisoryData(
            aliases=aliases,
            summary=summary,
            references=references,
            date_published=dateparser.parse(cve_item.get("publishedDate")),
        )


def extract_reference_urls(cve_item):
    """
    Return a list of reference URLs for a given CVE item.
    """
    urls = set()
    for reference in get_item(cve_item, "cve", "references", "reference_data") or []:
        ref_url = reference.get("url")

        if not ref_url:
            continue

        if ref_url.startswith("http") or ref_url.startswith("ftp"):
            urls.add(ref_url)

    return urls


def related_to_hardware(cpes):
    """
    Return True if the CVE item is related to hardware.
    """
    for cpe in cpes:
        cpe_comps = cpe.split(":")
        # CPE follow the format cpe:cpe_version:product_type:vendor:product
        if len(cpe_comps) > 2 and cpe_comps[2] == "h":
            return True

    return False


def extract_cpes(cve_item):
    """
    Return a list of CPEs for a given CVE item.
    """
    cpes = set()
    for node in get_item(cve_item, "configurations", "nodes") or []:
        for cpe_data in node.get("cpe_match") or []:
            if cpe_data.get("cpe23Uri"):
                cpes.add(cpe_data["cpe23Uri"])
    return cpes


def extract_severity_scores(cve_item):
    """
    Yield a vulnerability severity for each `cve_item`.
    """
    if get_item(cve_item, "impact", "baseMetricV3"):
        yield VulnerabilitySeverity(
            system=SCORING_SYSTEMS["cvssv3"],
            value=str(get_item(cve_item, "impact", "baseMetricV3", "cvssV3", "baseScore")),
        )
        yield VulnerabilitySeverity(
            system=SCORING_SYSTEMS["cvssv3_vector"],
            value=str(get_item(cve_item, "impact", "baseMetricV3", "cvssV3", "vectorString")),
        )

    if get_item(cve_item, "impact", "baseMetricV2"):
        yield VulnerabilitySeverity(
            system=SCORING_SYSTEMS["cvssv2"],
            value=str(get_item(cve_item, "impact", "baseMetricV2", "cvssV2", "baseScore")),
        )
        yield VulnerabilitySeverity(
            system=SCORING_SYSTEMS["cvssv2_vector"],
            value=str(get_item(cve_item, "impact", "baseMetricV2", "cvssV2", "vectorString")),
        )


class NVDBasicImprover(Improver):
    @property
    def interesting_advisories(self) -> QuerySet:
        return Advisory.objects.filter(created_by=NVDImporter.qualified_name)

    def get_inferences(self, advisory_data: AdvisoryData) -> Iterable[Inference]:
        yield Inference.from_advisory_data(
            advisory_data=advisory_data, confidence=100, fixed_purl=None
        )
