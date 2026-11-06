# shellcheck shell=bash
# Sourced by demo.tape: each command the tape types prints the next file that
# capture.sh saved from a real run, in order.
DEMO_CAPTURED="examples/demo/captured"
DEMO_STEP=0
demo_next() {
    DEMO_STEP=$((DEMO_STEP + 1))
    command cat "${DEMO_CAPTURED}/$(printf '%02d' "${DEMO_STEP}")"-*
}
kubectl() { demo_next; }
PS1='$ '
clear
