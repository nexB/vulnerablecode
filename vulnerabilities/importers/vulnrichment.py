import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Iterable
from typing import List
from typing import Optional

import dateparser
from packageurl import PackageURL
from univers.versions import InvalidVersion
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
                    url="https://github.com/rubysec/ruby-advisory-db/blob/master/",
                )
                yield parse_cve_advisory(raw_data, advisory_url)
        finally:
            if self.vcs_response:
                self.vcs_response.delete()


def parse_cve_advisory(raw_data, advisory_url):
    """"""

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
    # affected_products = cna_data.get("affected", [])
    # products = []
    # for product in affected_products:
    #     product_info = {
    #         "default_status": product.get("defaultStatus"),
    #         "platforms": product.get("platforms", []),
    #         "product": product.get("product"),
    #         "vendor": product.get("vendor"),
    #         "versions": product.get("versions", [])
    #     }
    #     products.append(product_info)

    # Extract descriptions
    description = ""
    description_list = cna_data.get("descriptions", [])
    for description_dict in description_list:
        if description_dict.get("lang") != "en":
            continue
        description = description_dict.get("value")

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
        },
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
    references = [
        Reference(url=ref.get("url"), severities=severities)
        for ref in cna_data.get("references", [])
    ]

    # Extract problem types
    weaknesses = []
    # problem_types = cna_data.get("problemTypes", [])
    # for problem in problem_types:
    #     descriptions = problem.get("descriptions", [])
    #     for description in descriptions:
    #         weaknesses.append(
    #             description.get("cweId")
    # "description": description.get("description"),
    # "lang": description.get("lang"),
    # "type": description.get("type")
    #         )
    #
    # #         cwe_id = description.get("cweId")
    # #         cwe_id = get_cwe_id(cwe_id)
    # #         weaknesses.append(cwe_id)

    return AdvisoryData(
        aliases=[cve_id],
        summary=description,
        # affected_packages=affected_products,
        references=references,
        date_published=date_published,
        # weaknesses=weaknesses,
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

    timestamp_formatted = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ").strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    ssvc_vector += f"{timestamp_formatted}/"
    return ssvc_vector, decision
