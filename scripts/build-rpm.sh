#!/bin/sh
set -eu
case "${1:-altp10}" in
    altp10|altp11) exec "$(dirname "$0")/build-package.sh" "${1:-altp10}" ;;
    *) echo 'Use altp10 or altp11' >&2; exit 1 ;;
esac
