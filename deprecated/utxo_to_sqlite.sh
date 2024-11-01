#!/bin/bash

set -euo pipefail

rm -f txoutset.sqlite txoutset.incomplete txoutset
mkfifo txoutset.incomplete
time pypy3 utxo_to_sqlite.py <txoutset.incomplete >txoutset.sqlite &
./cli.sh dumptxoutset $PWD/txoutset
wait %1
rm txoutset
