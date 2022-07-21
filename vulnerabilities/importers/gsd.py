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
from typing import Iterable

import dateparser
from fetchcode.vcs.git import fetch_via_git

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.utils import build_description
from vulnerabilities.utils import dedupe

logger = logging.getLogger(__name__)


class GSDImporter(Importer):
    spdx_license_expression = "CC0-1.0"
    license_url = "https://github.com/cloudsecurityalliance/gsd-database/blob/main/LICENSE"
    gsd_url = "git+https://github.com/cloudsecurityalliance/gsd-database"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        forked_dir = fork_and_get_dir(self.gsd_url)
        for file in get_files(forked_dir):
            yield parse_advisory_data(file)


def parse_advisory_data(file):
    """
    Parse a GSD advisory file and return an AdvisoryData.
    Each advisory file contains the advisory information in JSON format.
    """
    raw_data = json.loads(file)

    namespaces = raw_data.get("namespaces") or {}
    cve_org = namespaces.get("cve.org") or {}
    nvd_nist_gov = namespaces.get("nvd.nist.gov") or {}

    GSD = raw_data.get("GSD") or {}
    GSD_alias = [].append(GSD.get("alias")) or []
    details = GSD.get("description") or get_description(cve_org)
    GSD_id = [].append(GSD.get("id")) or []

    aliases_cve_org = get_aliases(cve_org)
    aliases_nvd_nist_gov = get_aliases(nvd_nist_gov)
    aliases = GSD_alias + GSD_id + aliases_cve_org + aliases_nvd_nist_gov

    summary = build_description(summary=get_summary(cve_org), description=details)
    references = get_references(cve_org)

    date_published = get_published_date_nvd_nist_gov(nvd_nist_gov)

    return AdvisoryData(
        aliases=dedupe(aliases),
        summary=summary,
        references=references,
        date_published=date_published,
    )


def get_summary(cve) -> str:
    """
    Args:
        cve: json object have a CVE_data_meta key
        {"CVE_data_meta": {"TITLE": "DoS vulnerability: Invalid Accent Colors"}
    Returns:
        a TITLE value as summary
    """
    CVE_data_meta = cve.get("CVE_data_meta") or {}
    return CVE_data_meta.get("TITLE") or ""


def get_cvss_str_v_cve_org(cve) -> str:
    """
    Args:
        cve: a json object have impact key , CVSS key and vectorString
        {"impact": {"cvss": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H"}}}
    Returns:
        vectorString of cvss "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H"
    """
    impact = cve.get("impact") or {}
    cvss = impact.get("cvss") or {}
    return cvss.get("vectorString")


def get_description(cve) -> [str]:
    """
    Get a list description value from description object
    >>> get_description({"description": {"description_data": [{"lang": "eng","value": "the description"}]}})
    ['the description']

    """
    description = cve.get("description") or {}
    description_data = description.get("description_data") or []
    return [desc["value"] for desc in description_data if desc["value"]]


def get_references(cve):
    """
    Args:
        cve: json object with a references key
    Returns:
        list of Reference assigned with url
    >>> get_references({"references": {
    ...      "reference_data": [{
    ...            "name": "https://kc.mcafee.com/corporate/index?page=content&id=SB10198",
    ...             "refsource": "CONFIRM",
    ...             "tags": ["Vendor Advisory"],
    ...             "url": "https://kc.mcafee.com/corporate/index?page=content&id=SB10198"}]}})
    [Reference(reference_id='', url='https://kc.mcafee.com/corporate/index?page=content&id=SB10198', severities=[])]

    """
    references = cve.get("references") or {}
    reference_data = references.get("reference_data") or []
    return [Reference(url=ref["url"]) for ref in reference_data if ref["url"]]


def get_aliases(cve) -> [str]:
    """
    Args:
        cve:
    Returns:
        list of aliases

    >>> get_aliases({"CVE_data_meta": {"ID": "CVE-2017-4017"},"source": {"advisory": "GHSA-v8x6-59g4-5g3w"}})
    ['CVE-2017-4017', 'GHSA-v8x6-59g4-5g3w']
    """
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
    """
    Args:
        nvd_nist_gov: json object have a publishedDate as a key
    Returns:
        a published date
    >>> get_published_date_nvd_nist_gov({"publishedDate": "2022-06-23T07:15Z"})
    datetime.datetime(2022, 6, 23, 7, 15, tzinfo=<StaticTzInfo 'Z'>)

    """
    publishedDate = nvd_nist_gov.get("publishedDate")
    return publishedDate and dateparser.parse(publishedDate)


def ForkError():
    pass


def fork_and_get_dir(url) -> dict:
    try:
        fork_directory = fetch_via_git(url=url)
        return fork_directory.dest_dir
    except Exception as e:
        logger.error(f"Can't clone url {url}")
        raise ForkError() from e


def get_files(fork_directory):
    for root_dir in os.listdir(fork_directory):
        if root_dir in [
            "nvd_updated_time.txt",
            "CODE_OF_CONDUCT.md",
            "LICENSE",
            "allowlist.json",
            "README.md",
            ".github",
        ]:
            continue
        for root, _, files in os.walk(os.path.join(fork_directory, root_dir)):
            for file in files:
                with open(os.path.join(root, file), "r") as f:
                    yield f.read()
