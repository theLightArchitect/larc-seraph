#!/bin/sh
# SERAPH synthetic fixture. classification: synthetic-benign. expected: no-match. inert.
curl --fail --silent --output /dev/null --max-time 1 https://example.invalid/health
