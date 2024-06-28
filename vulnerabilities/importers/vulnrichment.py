import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Iterable
from typing import List
from typing import Optional

import dateparser
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import RANGE_CLASS_BY_SCHEMES
from univers.version_range import VersionRange
from univers.versions import AlpineLinuxVersion
from univers.versions import ArchLinuxVersion
from univers.versions import ComposerVersion
from univers.versions import DebianVersion
from univers.versions import GenericVersion
from univers.versions import GentooVersion
from univers.versions import GolangVersion
from univers.versions import InvalidVersion
from univers.versions import LegacyOpensslVersion
from univers.versions import MavenVersion
from univers.versions import NginxVersion
from univers.versions import NugetVersion
from univers.versions import OpensslVersion
from univers.versions import PypiVersion
from univers.versions import RpmVersion
from univers.versions import SemverVersion
from univers.versions import Version

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.utils import build_description
from vulnerabilities.utils import dedupe
from vulnerabilities.utils import get_advisory_url
from vulnerabilities.utils import get_cwe_id

logger = logging.getLogger(__name__)

VULNRICH_VERSION_CLASS_SCHEMES = {
    "semver": SemverVersion,
    "python": PypiVersion,
    "custom": GenericVersion,
    "rpm": RpmVersion,
    "maven": MavenVersion,
}


class VulnrichImporter(Importer):
    spdx_license_expression = "CC0-1.0"
    license_url = "https://github.com/cisagov/vulnrichment/blob/develop/LICENSE"
    repo_url = "git+https://github.com/cisagov/vulnrichment.git"
    importer_name = "Vulnrichment"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        try:
            vcs_response = self.clone(repo_url=self.repo_url)
            base_path = Path(vcs_response.dest_dir)
            for file_path in base_path.glob(f"**/**/*.json"):
                if not file_path.name.startswith("CVE-"):
                    continue

                with open(file_path) as f:
                    raw_data = json.load(f)

                advisory_url = get_advisory_url(
                    file=file_path,
                    base_path=base_path,
                    url="https://github.com/cisagov/vulnrichment/blob/develop/",
                )
                yield parse_cve_advisory(raw_data, advisory_url)
        finally:
            if self.vcs_response:
                self.vcs_response.delete()


def parse_cve_advisory(raw_data, advisory_url):
    """ """
    # Extract CVE Metadata
    cve_metadata = raw_data.get("cveMetadata", {})
    cve_id = cve_metadata.get("cveId")
    state = cve_metadata.get("state")

    date_published = cve_metadata.get("datePublished")
    date_published = dateparser.parse(date_published)

    # Extract containers
    containers = raw_data.get("containers", {})
    cna_data = containers.get("cna", {})
    adp_data = containers.get("adp", {})

    # Extract affected products
    affected_packages = []
    for affected_product in cna_data.get("affected", []):
        if type(affected_product) != dict:
            continue
        cpes = affected_product.get("cpes")  # TODO Add references cpes

        vendor = affected_product.get("vendor") or ""
        collection_url = affected_product.get("collectionURL") or ""
        product = affected_product.get("product") or ""
        package_name = affected_product.get("packageName") or ""

        platforms = affected_product.get("platforms", [])
        default_status = affected_product.get("defaultStatus")

        affected_packages = []
        # purl (vendor, collection_url, product, package_name, platforms)
        purl = PackageURL(
            type=vendor,
            name=product,
            namespace=package_name,
        )

        versions = affected_product.get("versions", [])
        for version_data in versions:
            # version ≤ V ≤ (lessThanOrEqual/lessThan)
            # right_version ≤ V ≤ left_version
            version_constraints = []
            r_version = version_data.get("version")
            version_type = version_data.get("versionType")
            version_class = VULNRICH_VERSION_CLASS_SCHEMES.get(version_type)
            if not version_class:
                logger.error(f"Invalid version_class type: {version_type}")
                continue

            l_version, l_comparator = None, ""
            if "lessThan" in version_data:
                l_version = version_data.get("lessThan")
                l_comparator = "<"
            elif "lessThanOrEqual" in version_data:
                l_version = version_data.get("lessThanOrEqual")
                l_comparator = "<="
            try:
                if l_version and l_comparator:
                    version_constraints.append(
                        VersionConstraint(comparator=l_comparator, version=version_class(l_version))
                    )
                if r_version:
                    version_constraints.append(
                        VersionConstraint(comparator=">", version=version_class(r_version))
                    )
            except InvalidVersion:
                logger.error(f"InvalidVersion: {l_version}-{r_version}")
                continue

            affected_packages.append(
                AffectedPackage(
                    purl,
                    affected_version_range=VersionRange(constraints=version_constraints),
                )
            )
            status = version_data.get("status")

    # Extract descriptions
    summary = ""
    description_list = cna_data.get("descriptions", [])
    for description_dict in description_list:
        if not description_dict.get("lang") in ["en", "en-US"]:
            continue
        summary = description_dict.get("value")

    # Extract metrics
    severities = []
    metrics = cna_data.get("metrics", []) + [data.get("metrics", [])[0] for data in adp_data]
    vulnrichment_scoring_system = {
        "cvssV4_0": SCORING_SYSTEMS["cvssv4"],
        "cvssV3_1": SCORING_SYSTEMS["cvssv3.1"],
        "cvssV3_0": SCORING_SYSTEMS["cvssv3"],
        "cvssV2_0": SCORING_SYSTEMS["cvssv2"],
        "other": {
            "ssvc": SCORING_SYSTEMS["ssvc"],
        },  # ignore kev
    }

    for metric in metrics:
        for metric_type, metric_value in metric.items():
            if metric_type not in vulnrichment_scoring_system:
                continue

            if metric_type == "other":
                other_types = metric_value.get("type")
                if other_types == "ssvc":
                    content = metric_value.get("content", {})
                    vector_string, decision = ssvc_calculator(content)
                    scoring_system = vulnrichment_scoring_system[metric_type][other_types]
                    severity = VulnerabilitySeverity(
                        system=scoring_system, scoring_elements=vector_string, value=decision
                    )
                    severities.append(severity)
                # ignore kev
            else:
                vector_string = metric_value.get("vectorString")
                base_score = metric_value.get("baseScore")
                scoring_system = vulnrichment_scoring_system[metric_type]
                severity = VulnerabilitySeverity(
                    system=scoring_system, value=base_score, scoring_elements=vector_string
                )
                severities.append(severity)

    # Extract references
    # TODO ADD reference type
    references = [
        Reference(url=ref.get("url"), severities=severities)
        for ref in cna_data.get("references", [])
    ]

    weaknesses = []
    for problem_type in cna_data.get("problemTypes", []):
        descriptions = problem_type.get("descriptions", [])
        for description in descriptions:
            cwe_id = description.get("cweId")
            if cwe_id:
                weaknesses.append(get_cwe_id(cwe_id))

            description_text = description.get("description")
            if description_text:
                pattern = r"CWE-(\d{3})"
                match = re.search(pattern, description_text)
                if match:
                    weaknesses.append(match.group(1))

    return AdvisoryData(
        aliases=[cve_id],
        summary=summary,
        affected_packages=affected_packages,
        references=references,
        # date_published=dateparser.parse(self.cve_item.get("publishedDate")),
        weaknesses=weaknesses,
        url=advisory_url,
    )


def ssvc_calculator(ssvc_data):
    """
    Return the ssvc vector and the decision value
    """
    options = ssvc_data.get("options", [])
    timestamp = ssvc_data.get("timestamp")

    # Extract the options into a dictionary
    options_dict = {list(option.keys())[0]: list(option.values())[0].lower() for option in options}

    # Determining Mission and Well-Being Impact Value
    mission_well_being_table = {
        # (Mission Prevalence, Public Well-being Impact) : "Mission & Well-being"
        ("minimal", "minimal"): "low",
        ("minimal", "material"): "medium",
        ("minimal", "irreversible"): "high",
        ("support", "minimal"): "medium",
        ("support", "material"): "medium",
        ("support", "material"): "high",
        ("essential", "minimal"): "high",
        ("essential", "material"): "high",
        ("essential", "irreversible"): "high",
    }
    if "Mission Prevalence" not in options_dict:
        options_dict["Mission Prevalence"] = "minimal"

    if "Public Well-being Impact" not in options_dict:
        options_dict["Public Well-being Impact"] = "material"

    options_dict["Mission & Well-being"] = mission_well_being_table[
        (options_dict["Mission Prevalence"], options_dict["Public Well-being Impact"])
    ]

    decision_key = (
        options_dict.get("Exploitation"),
        options_dict.get("Automatable"),
        options_dict.get("Technical Impact"),
        options_dict.get("Mission & Well-being"),
    )

    decision_points = {
        "Exploitation": {"E": {"none": "N", "poc": "P", "active": "A"}},
        "Automatable": {"A": {"no": "N", "yes": "Y"}},
        "Technical Impact": {"T": {"partial": "P", "total": "T"}},
        "Public Well-being Impact": {"B": {"minimal": "M", "material": "A", "irreversible": "I"}},
        "Mission Prevalence": {"P": {"minimal": "M", "support": "S", "essential": "E"}},
        "Mission & Well-being": {"M": {"low": "L", "medium": "M", "high": "H"}},
    }

    # Create the SSVC vector
    ssvc_vector = "SSVCv2/"
    for key, value_map in options_dict.items():
        options_key = decision_points.get(key)
        for lhs, rhs_map in options_key.items():
            ssvc_vector += f"{lhs}:{rhs_map.get(value_map)}/"

    # "Decision": {"D": {"Track": "T", "Track*": "R", "Attend": "A", "Act": "C"}},
    decision_values = {"Track": "T", "Track*": "R", "Attend": "A", "Act": "C"}

    decision_lookup = {
        ("none", "no", "partial", "low"): "Track",
        ("none", "no", "partial", "medium"): "Track",
        ("none", "no", "partial", "high"): "Track",
        ("none", "no", "total", "low"): "Track",
        ("none", "no", "total", "medium"): "Track",
        ("none", "no", "total", "high"): "Track*",
        ("none", "yes", "partial", "low"): "Track",
        ("none", "yes", "partial", "medium"): "Track",
        ("none", "yes", "partial", "high"): "Attend",
        ("none", "yes", "total", "low"): "Track",
        ("none", "yes", "total", "medium"): "Track",
        ("none", "yes", "total", "high"): "Attend",
        ("poc", "no", "partial", "low"): "Track",
        ("poc", "no", "partial", "medium"): "Track",
        ("poc", "no", "partial", "high"): "Track*",
        ("poc", "no", "total", "low"): "Track",
        ("poc", "no", "total", "medium"): "Track*",
        ("poc", "no", "total", "high"): "Attend",
        ("poc", "yes", "partial", "low"): "Track",
        ("poc", "yes", "partial", "medium"): "Track",
        ("poc", "yes", "partial", "high"): "Attend",
        ("poc", "yes", "total", "low"): "Track",
        ("poc", "yes", "total", "medium"): "Track*",
        ("poc", "yes", "total", "high"): "Attend",
        ("active", "no", "partial", "low"): "Track",
        ("active", "no", "partial", "medium"): "Track",
        ("active", "no", "partial", "high"): "Attend",
        ("active", "no", "total", "low"): "Track",
        ("active", "no", "total", "medium"): "Attend",
        ("active", "no", "total", "high"): "Act",
        ("active", "yes", "partial", "low"): "Attend",
        ("active", "yes", "partial", "medium"): "Attend",
        ("active", "yes", "partial", "high"): "Act",
        ("active", "yes", "total", "low"): "Attend",
        ("active", "yes", "total", "medium"): "Act",
        ("active", "yes", "total", "high"): "Act",
    }

    decision = decision_lookup.get(decision_key, "")

    if decision:
        ssvc_vector += f"D:{decision_values.get(decision)}/"

    if timestamp:
        timestamp_formatted = dateparser.parse(timestamp).strftime("%Y-%m-%dT%H:%M:%SZ")

        ssvc_vector += f"{timestamp_formatted}/"
    return ssvc_vector, decision
