#!/use/bin/env python3

from __future__ import annotations
from pathlib import Path
import os
import yaml
from schema import Schema, SchemaError, Regex # https://www.andrewvillazon.com/validate-yaml-python-schema/

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

    def load(self, path):
        with open(path, "r") as f:
            return yaml.load(f, Loader=yaml.SafeLoader)

    def validate(self, data):
        try:
            self.schema.validate(data)    
            return True
        except SchemaError as se:
            raise se

if __name__ == "__main__":
    raise Error("This module is to be imported")
