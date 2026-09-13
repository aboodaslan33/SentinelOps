#!/usr/bin/env bash
# =============================================================================
# SentinelOps - run-logtest.sh
# =============================================================================
# Proves (or disproves) each custom rule 100100-100153 by piping a sample event
# through wazuh-logtest and checking that the EXPECTED rule id fires.
#
# THIS IS THE ONLY THING THAT PROVES A RULE WORKS. It must run ON THE WAZUH
# MANAGER, after detection-rules/local_rules.xml has been deployed to
# /var/ossec/etc/rules/ and the manager restarted. Nothing here is validated
# until this script prints PASS for a rule on a live install.
#
# Usage (on the manager):
#     sudo bash tests/run-logtest.sh
#     sudo bash tests/run-logtest.sh 100111        # single rule
#
# Exit code: 0 if every tested rule PASSes, 1 otherwise.
# =============================================================================
set -u

LOGTEST="/var/ossec/bin/wazuh-logtest"
DIR="$(cd "$(dirname "$0")/logtest" && pwd)"

# Expected level per rule (kept in sync with local_rules.xml / expected_results.md).
declare -A EXPECTED_LEVEL=(
  [100100]=3  [100101]=10 [100102]=12 [100103]=8  [100104]=12
  [100110]=3  [100111]=10 [100112]=12 [100113]=12 [100114]=10 [100115]=13
  [100120]=8  [100121]=13 [100122]=5  [100123]=8
  [100130]=3  [100131]=12 [100132]=13 [100133]=10 [100134]=12
  [100140]=12 [100141]=5  [100142]=13 [100143]=10 [100144]=12 [100145]=10
  [100150]=14 [100151]=12 [100152]=12 [100153]=14
)

if [[ ! -x "$LOGTEST" ]]; then
  echo "ERROR: $LOGTEST not found."
  echo "This script must run on an installed Wazuh manager. Nothing has been proven."
  exit 1
fi

# Optional single-rule filter
FILTER="${1:-}"

pass=0; fail=0; total=0
printf "%-9s %-6s %-6s %-8s %s\n" "RULE" "EXP" "GOT" "RESULT" "ALL-MATCHED-IDS"
printf "%s\n" "-------------------------------------------------------------------"

for f in "$DIR"/*.txt; do
  rid="$(basename "$f" .txt)"
  [[ -n "$FILTER" && "$rid" != "$FILTER" ]] && continue
  exp="${EXPECTED_LEVEL[$rid]:-?}"
  total=$((total+1))

  # Feed every JSON line in the file into ONE logtest session (preserves
  # correlation state for frequency-based rules).
  out="$($LOGTEST < "$f" 2>&1)"

  # All rule ids that fired anywhere in the session, and the target's level.
  all_ids="$(printf '%s\n' "$out" | grep -oE "id: '[0-9]+'" | grep -oE '[0-9]+' | sort -u | paste -sd, -)"
  got_level="$(printf '%s\n' "$out" \
      | grep -A2 "id: '$rid'" | grep -oE "level: '[0-9]+'" | grep -oE '[0-9]+' | head -1)"
  got_level="${got_level:--}"

  if printf '%s\n' "$out" | grep -q "id: '$rid'"; then
    if [[ "$got_level" == "$exp" ]]; then
      result="PASS"; pass=$((pass+1))
    else
      result="LVL?"; fail=$((fail+1))   # fired but at an unexpected level
    fi
  else
    result="FAIL"; fail=$((fail+1))
  fi

  printf "%-9s %-6s %-6s %-8s %s\n" "$rid" "$exp" "$got_level" "$result" "${all_ids:-none}"
done

printf "%s\n" "-------------------------------------------------------------------"
echo "Tested: $total   PASS: $pass   FAIL/LVL?: $fail"
echo
echo "Legend: PASS=target rule fired at expected level | LVL?=fired at a different"
echo "level | FAIL=target rule did not fire. Investigate every non-PASS on the"
echo "manager (regex engine/backslash, decoder field names, correlation window,"
echo "sibling rule winning). See tests/logtest/expected_results.md."

[[ "$fail" -eq 0 ]] && exit 0 || exit 1
