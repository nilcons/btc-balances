#!/bin/bash

set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

rm -rf output
mkdir output

# cron mode
if ! tty >/dev/null; then
    exec 2>output/log
fi

make

rm -f txoutset txoutset.incomplete
mkfifo txoutset.incomplete
./parse <txoutset.incomplete | awk '{print $0 > "output/" substr($0,0,6)}' &
./cli.sh dumptxoutset $PWD/txoutset >output/metadata.json
wait %1
rm txoutset
zstd output/??????
rm output/??????
