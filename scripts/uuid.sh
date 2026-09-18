#!/bin/bash

if [[ $# -ne 1 ]]; then
    echo "Usage: bash scripts/uuid.sh <path>"
    exit 0
fi

DIR=$1
METADATA="$DIR/metadata.yml"

if ! [[ -d $DIR ]]; then
    echo "[!] -> Directory $DIR does not exist"
    exit 1
fi

if ! [[ -f $METADATA ]]; then
    echo "[!] -> Could not find metadata.yml in $DIR"
    exit 1
fi

UUID="$(cat /proc/sys/kernel/random/uuid)"
echo "[i] -> Generated UUID: $UUID"

if grep -qi "$UUID" "./artifacts/meta.json"; then
    echo "[!] -> Somehow, and i dont know how, there has been a collision with $UUID in ./artifacts/meta.json"
    exit 1
fi

if grep -qE '^uuid:[[:space:]]*"[a-zA-Z0-9\-]+"[[:space:]]*$' "$METADATA"; then
    echo "[!] -> UUID already present in $METADATA"
    exit 1
fi

sed -i "2i uuid: \"$UUID\"" "$METADATA"

if grep -qi "$UUID" "$METADATA"; then
    echo "[+] -> Added UUID [$UUID] to $METADATA" 
    exit 0
else
    echo "[!] -> Something went wrong adding $UUID to $METADATA"
    exit 1
fi
