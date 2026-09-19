from pathlib import Path
from typing import Any
from mitreattack.stix20 import MitreAttackData
import logging

logger = logging.getLogger(__name__)

Threat = dict[str, Any]

class ATTCK:
    def __init__(self, path: Path = Path("artifacts/enterprise-attack.json")) -> None:
        self.data = MitreAttackData(str(path))
        self.tactics = {
            tactic.x_mitre_shortname: tactic
            for tactic in self.data.get_tactics()
        }

    def get_ref(self, attack_object: Any) -> Any:
        # return attck ext reference from attck stix object
        for reference in attack_object.external_references:
            if reference.source_name == "mitre-attack":
                return reference

        raise ValueError(f"No MITRE ATT&CK reference for [{attack_object.name}]")

    def technique(self, technique_object: Any) -> Threat:
        # convert attck stix obj into kibana technique structure
        reference = self.get_ref(technique_object)

        return {
            "id": reference.external_id,
            "name": technique_object.name,
            "reference": reference.url,
            "subtechnique": [],
        }

    def tactic(self, tactic_object: Any) -> Threat:
        # convert attck stix obj into kibana tactic structure
        reference = self.get_ref(tactic_object)

        return {
            "id": reference.external_id,
            "name": tactic_object.name,
            "reference": reference.url,
        }

    def build_threat(self, attack_ids: list[str]) -> list[Threat]:
        # convert attck (sub)ids from metadata.yml info kibana threat structure
        threats: dict[str, Threat] = {}
        for attack_id in attack_ids:
            attack_id = attack_id.upper()
            parent_id = attack_id.split(".")[0]
            parent_technique = (self.data.get_object_by_attack_id(parent_id,"attack-pattern"))

            if parent_technique is None:
                raise ValueError(f"Unknown ATT&CK technique [{attack_id}]")

            # a technique can belong to multiple tactics
            for kill_chain_phase in (parent_technique.kill_chain_phases):
                if (kill_chain_phase.kill_chain_name != "mitre-attack"):
                    continue
                tactic_name = kill_chain_phase.phase_name
                tactic_object = self.tactics[tactic_name]

                # create kibana tactic entry
                if tactic_name not in threats:
                    threats[tactic_name] = {
                        "framework": "MITRE ATT&CK",
                        "tactic": self.tactic(
                            tactic_object
                        ),
                        "technique": [],
                    }

                threat = threats[tactic_name]

                # find parent technique
                kibana_technique = None
                for technique in threat["technique"]:
                    if technique["id"] == parent_id:
                        kibana_technique = technique
                        break

                if kibana_technique is None:
                    kibana_technique = (
                        self.technique(
                            parent_technique
                        )
                    )
                    threat["technique"].append(kibana_technique)

                # handle sub-techniques such as (T1059.001)
                if "." in attack_id:
                    subtechnique_object = (self.data.get_object_by_attack_id(attack_id,"attack-pattern"))
                    if subtechnique_object is None:
                        raise ValueError(f"Unknown ATT&CK sub-technique [{attack_id}]")

                    subtechnique = self.technique(subtechnique_object)
                    subtechnique.pop("subtechnique")

                    if (subtechnique not in kibana_technique["subtechnique"]):
                        kibana_technique["subtechnique"].append(subtechnique)

        return list(threats.values())
