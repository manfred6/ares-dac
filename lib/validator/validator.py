from elasticsearch import BadRequestError
import logging

logger = logging.getLogger(__name__)

class Validator:
    def validate(self, client, rule, rule_type, rule_indices):
        match rule_type:
            case "esql":
                return self._validate_esql(client, rule)
            case "kql":
                return self._validate_kql(client, rule, rule_indices)
            case _:
                logger.error("Unsupported rule passed to validate function")
                return False

    def _validate_esql(self, client, query):
        logger.debug("Validating ES|QL query")
    
        try:
            client.esql.query(
                query=f"{query.rstrip()}\n| LIMIT 0"
            )
        except BadRequestError as exc:
            logger.warning(f"ES|QL validation failed: {exc}")
            return False
    
        return True
    
    def _validate_kql(self, client, query, indices):
        logger.debug("Validating KQL query")
    
        result = client.indices.validate_query(
            index=indices,
            explain=True,
            query={
                "kql": {
                    "query": query,
                }
            },
        )
    
        return result["valid"]
