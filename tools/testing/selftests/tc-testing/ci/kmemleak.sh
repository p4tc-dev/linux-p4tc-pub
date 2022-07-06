#!/bin/bash -e

WD=$(dirname -- "$(realpath "$0")")

echo clear > /sys/kernel/debug/kmemleak

"$WD"/../tdc.py -c p4tc

# Scan twice just to be sure
echo scan > /sys/kernel/debug/kmemleak
echo scan > /sys/kernel/debug/kmemleak

cat /sys/kernel/debug/kmemleak
