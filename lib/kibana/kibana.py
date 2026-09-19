from __future__ import annotations
from pathlib import Path
from typing import Any
import logging
import requests

from mitre import ATTCK

logger = logging.getLogger(__name__)

class Kibana:
    RULES_ENDPOINT = "/api/detection_engine/rules"
    OWNER_TAG = "managed-by:ares-dac"

    RISK_SCORE = {
        "low": 21,
        "medium": 47,
        "high": 73,
        "critical": 90,
    }

    def __init__(self, endpoint: str, api_key: str, ca_certs: Path, attack_path: Path | None = None, timeout: int | None = None):
        self.endpoint = endpoint.rstrip("/")
        self.timeout = 10
        self.attack_path = Path("artifacts/enterprise-attack.json")
        self.session = requests.Session()
        auth_header = f"ApiKey {api_key}"
        self.session.headers.update(
            {
                "Authorization": auth_header,
                "Content-Type": "application/json",
                "kbn-xsrf": "true",
            }
        )

        if ca_certs is not None:
            self.session.verify = str(ca_certs)

        logger.debug(f"Initialized kibana client: [endpoint: {self.endpoint}, timeout: {self.timeout}, attack_path: {self.attack_path}")

        self.attck = ATTCK(attack_path)

    def _request(self, method: str, path: str, **kwargs) -> Any:
        url = f"{self.endpoint}{path}"
        logger.debug(f"Making {method} request to {url}")

        try:
            response = self.session.request(
                method,
                url,
                timeout=self.timeout,
                **kwargs,
            )
            response.raise_for_status()

        except requests.RequestException as exc:
            response = getattr(exc, "response", None)
            if response is not None:
                logger.error(f"Kibana request failed: {method} {url} [{response.status_code}]\n{response.text}")
            else:
                logger.error(f"Kibana request failed: {method} {url} [{response.status_code}]")
            raise

        if not response.content:
            return None

        return response.json()

    def get_rule(self, rule_id: str) -> dict | None:
        # get single rule by rule_id
        try:
            return self._request(
                "GET",
                self.RULES_ENDPOINT,
                params={"rule_id": rule_id},
            )
        except requests.HTTPError as e:
            if (e.response is not None and exc.response.status_code == 404):
                return None
            raise

    def get_rules(self) -> list[dict]:
        # get all rules
        rules: list[dict] = []
        page = 1
        per_page = 100

        while True:
            data = self._request(
                "GET",
                f"{self.RULES_ENDPOINT}/_find",
                params={
                    "page": page,
                    "per_page": per_page,
                },
            )

            page_rules = data.get("data", [])
            rules.extend(page_rules)

            total = data.get("total", 0)

            if len(rules) >= total or not page_rules:
                break

            page += 1

        logger.info(f"Found {len(rules)} total detection rules in kibana")

        return rules

    def get_managed_rules(self) -> list[dict]:
        # get all rules managed by ares-dac (using self.get_rules())
        rules = [
            rule for rule in self.get_rules()
            if self.OWNER_TAG in rule.get("tags", [])
        ]

        logger.info(f"Found [{len(rules)}] detection rules in kibana managed by ares-dac")

        return rules

    def create_rule(self, payload: dict) -> dict:
        # create a single rule
        logger.info(f"Creating Kibana rule [name: {payload['name']}, uuid: {payload['rule_id']}")

        return self._request(
            "POST",
            self.RULES_ENDPOINT,
            json=payload,
        )

    def update_rule(self, payload: dict) -> dict:
        # update a single rule
        logger.info(f"Updating Kibana rule [name: {payload['name']}, uuid: {payload['rule_id']}")

        return self._request(
            "PUT",
            self.RULES_ENDPOINT,
            json=payload,
        )

    def delete_rule(self, rule_name: str, rule_id: str) -> dict:
        # delete a single rule
        logger.info(f"Deleting Kibana rule [name: {rule_name}, uuid: {rule_id}")

        return self._request(
            "DELETE",
            self.RULES_ENDPOINT,
            params={"rule_id": rule_id},
        )

    def format_rule(self, metadata: dict, query: str, rule_type: str) -> dict:
        # build detection payload for kibana from metadata.yml. meta.uuid -> kibana.rule_id
        logger.info(f"Building kibana detection object of type {rule_type} for [name: {metadata.get('name')}, uuid: {metadata.get('uuid')}]")

        rule_type = rule_type.lower()
        payload = metadata.get("kibana", {}).copy()
        severity = metadata.get("severity", "medium").lower()

        if severity not in self.RISK_SCORE:
            raise ValueError(
                f"Unsupported severity [{severity}]"
            )
       
        payload.setdefault("enabled", True)
        payload.setdefault("interval", "5m")
        payload.setdefault("from", "now-6m")
        payload.setdefault("to", "now")
        payload.setdefault("severity", severity)
        payload.setdefault("risk_score", self.RISK_SCORE[severity])
        tags = set(payload.get("tags", []))
        tags.add(self.OWNER_TAG)

        payload.update({
            "rule_id": metadata["uuid"],
            "name": metadata["name"],
            "description": metadata["description"],
            "references": metadata.get("references", []),
            "tags": sorted(tags),
            "threat": self.attck.build_threat(
                metadata.get("mitre", {}).get("attack", [])
            )
        })

        if rule_type == "esql":
            payload.update(
                {
                    "type": "esql",
                    "language": "esql",
                    "query": query.strip(),
                }
            )
            return payload

        indices = metadata.get("indices", [])

        if not indices:
            raise ValueError(f"Rule [name: {metadata.get('name')}, uuid: {metadata.get('uuid')}] with type [{rule_type}] requires indices in metadata.yml")

        if rule_type == "kql":
            payload.update(
                {
                    "type": "query",
                    "language": "kuery",
                    "query": query.strip(),
                    "index": indices,
                }
            )

        elif rule_type == "lucene":
            payload.update(
                {
                    "type": "query",
                    "language": "lucene",
                    "query": query.strip(),
                    "index": indices,
                }
            )

        elif rule_type == "eql":
            payload.update(
                {
                    "type": "eql",
                    "language": "eql",
                    "query": query.strip(),
                    "index": indices,
                }
            )

        else:
            raise ValueError(f"Unsupported rule type [{rule_type}] for rule [name: {metadata.get('name')}, uuid: {metadata.get('uuid')}]")

        return payload

