#!/bin/sh
# Fixture mimicking nfqws2 for subprocess primitive tests.
# Behavior: accept --help (prints version, exits 0), accept --qnum=N
# (prints "started on queue N" to stdout, sleeps for $FAKE_NFQWS_SLEEP
# seconds or default 30, exits 0 on natural completion or SIGTERM).

if [ "$1" = "--help" ]; then
    echo "fake-nfqws v0.0 (test fixture)"
    exit 0
fi

# Find --qnum=N arg
QNUM="?"
for arg in "$@"; do
    case "$arg" in
        --qnum=*) QNUM="${arg#--qnum=}" ;;
    esac
done

echo "started on queue $QNUM"
sleep "${FAKE_NFQWS_SLEEP:-30}"
