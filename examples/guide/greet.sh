#!/usr/bin/env bash
# greet.sh — the guide's smallest possible tool. One flag, --mood, picks the message.
#
# Deliberately trivial: the point of this script is the ARGUMENT it takes, not what it does.
# --mood is the value a recipe will later gate.
set -euo pipefail

mood="calm"
while [ $# -gt 0 ]; do
  case "$1" in
    --mood) mood="$2"; shift 2 ;;
    *) echo "unknown flag: $1" >&2; exit 1 ;;
  esac
done

case "$mood" in
  calm)   echo "Everything is fine. Carry on." ;;
  urgent) echo "STOP. This needs attention right now." ;;
  *)      echo "unrecognized mood: $mood" >&2; exit 1 ;;
esac
