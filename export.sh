#!/usr/bin/env bash

FILE="$(date "+%Y%m%d")"
BRANCH="master"

git archive --format zip --output "${FILE}.zip" "${BRANCH}"
git archive --format tar.gz --output "${FILE}.tar.gz" "${BRANCH}"
