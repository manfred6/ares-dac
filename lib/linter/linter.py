#!/use/bin/env python3

from __future__ import annotations
from pathlib import Path
from schema import Schema, SchemaError, Regex # https://www.andrewvillazon.com/validate-yaml-python-schema/
import os, sys
import logging

logger = logging.getLogger(__name__)

class Linter:
    def __init__(self):
        self.schema = Schema({
            "name": str,
            "description": str,
            "date": {
                "created": str,
                "modified": str
            },
            "types": [str],
            "indices": [str],
            "author": str,
            "references": [str],
            "mitre": {
                "attack": [Regex(r"^T[0-9]+(\.[0-9]+)?$")]
            }
        })

    def validate(self, data):
        try:
            self.schema.validate(data)    
            return True
        except SchemaError as se:
            logger.error(se)

if __name__ == "__main__":
    print("[!] -> This module is to be imported")
    sys.exit(1)
