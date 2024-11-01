#!/bin/bash

set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

script=$(./addr2script.py $1)
prefix=$(echo $script | cut -c1-6)

zstdcat output/$prefix.zst | grep ^$script | awk 'BEGIN {s=0} {s=s+$2} END {print s}'
