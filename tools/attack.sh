#!/usr/bin/env bash
# Smoke / probe suite against a running otss instance.
# Usage: ./tools/attack.sh http://TARGET:8080

set -uo pipefail

BASE="${1:-http://localhost:8080}"
PASS=0
FAIL=0
SKIP=0

ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
skip() { printf '  \033[33mSKIP\033[0m %s\n' "$1"; SKIP=$((SKIP+1)); }
head() { printf '\n\033[1m%s\033[0m\n' "$1"; }

mk_secret() {
  local body="$1"
  curl -sS -X POST "$BASE/secrets" -H 'Content-Type: application/json' -d "$body"
}

jget() {
  # Parse a JSON field without assuming python3 exists: CI runs this in Linux
  # containers, but it also has to be runnable from a laptop. Try python3, then
  # python, then fall back to a grep-based extraction that is good enough for
  # the flat objects this API returns.
  if command -v python3 >/dev/null 2>&1; then
    python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('$1',''))" 2>/dev/null
  elif command -v python >/dev/null 2>&1; then
    python -c "import sys,json; d=json.load(sys.stdin); print(d.get('$1',''))" 2>/dev/null
  else
    sed -n 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1
  fi
}

head "0. reachability"
if curl -sS -m 5 "$BASE/healthz" >/dev/null 2>&1; then
  ok "service responds on /healthz"
else
  bad "service unreachable at $BASE"
  exit 1
fi

head "1. weak / enumerable ids"
RESP=$(mk_secret '{"content":"probe","ttl_seconds":300,"max_views":1}')
ID=$(printf '%s' "$RESP" | jget id)
if [ -z "$ID" ]; then
  bad "could not create a secret (rate limited or schema mismatch?): $RESP"
else
  LEN=${#ID}
  if [ "$LEN" -ge 22 ]; then ok "id length $LEN (>=22, no short-id enumeration)"; else bad "id length $LEN is short and likely enumerable"; fi
  if printf '%s' "$ID" | grep -qE '^[0-9]+$'; then bad "id is numeric/sequential: $ID"; else ok "id is not numeric"; fi

  head "2. sequential probes around the real id"
  HITS=0
  for off in 1 2 3 -1 -2 -3; do
    code=$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/s/$ID$off" 2>/dev/null || true)
    [ "$code" = "200" ] && HITS=$((HITS+1))
  done
  if [ "$HITS" -eq 0 ]; then ok "no neighbouring id returned content"; else bad "$HITS neighbouring ids were readable"; fi
fi

head "3. view-once under a race (20 parallel reads)"
R=$(mk_secret '{"content":"RACE-CANARY-777","ttl_seconds":300,"max_views":1}')
RID=$(printf '%s' "$R" | jget id)
if [ -z "$RID" ]; then
  skip "could not create the race secret"
else
  TMP=$(mktemp -d)
  for i in $(seq 1 20); do
    curl -sS -o "$TMP/$i.out" -w '%{http_code}' "$BASE/s/$RID" > "$TMP/$i.code" 2>/dev/null &
  done
  wait
  WINS=$(grep -lx '200' "$TMP"/*.code 2>/dev/null | wc -l | tr -d ' ')
  if [ "$WINS" -eq 1 ]; then ok "exactly one of 20 parallel reads succeeded"; else bad "$WINS of 20 parallel reads succeeded (want exactly 1)"; fi
  rm -rf "$TMP"
fi

head "4. revocation"
V=$(mk_secret '{"content":"revoke-probe","ttl_seconds":300,"max_views":1}')
VID=$(printf '%s' "$V" | jget id)
VTOK=$(printf '%s' "$V" | jget deletion_token)
if [ -z "$VID" ] || [ -z "$VTOK" ]; then
  skip "could not create the revoke secret"
else
  code=$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE "$BASE/s/$VID" -H "X-Deletion-Token: wrong-token")
  if [ "$code" = "204" ] || [ "$code" = "200" ]; then bad "arbitrary token revoked the secret"; else ok "wrong deletion token rejected ($code)"; fi

  code=$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/s/$VID")
  if [ "$code" = "200" ]; then ok "secret survived a failed revocation"; else bad "failed revocation destroyed the secret ($code)"; fi

  code=$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE "$BASE/s/$VID" -H "X-Deletion-Token: $VTOK")
  if [ "$code" = "204" ] || [ "$code" = "200" ]; then ok "valid token revoked the secret"; else bad "valid token did not revoke ($code)"; fi

  code=$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/s/$VID")
  if [ "$code" = "404" ]; then ok "revoked secret is unreadable"; else bad "revoked secret still readable ($code)"; fi
fi

head "5. response uniformity"
A=$(mk_secret '{"content":"probe","ttl_seconds":300,"max_views":1,"passphrase":"right-one"}')
AID=$(printf '%s' "$A" | jget id)
if [ -z "$AID" ]; then
  skip "could not create the passphrase secret"
else
  b1=$(curl -sS "$BASE/s/$AID?p=wrong-one")
  c1=$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/s/$AID?p=wrong-one")
  b2=$(curl -sS "$BASE/s/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA?p=wrong-one")
  c2=$(curl -sS -o /dev/null -w '%{http_code}' "$BASE/s/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA?p=wrong-one")
  if [ "$c1" = "$c2" ] && [ "$b1" = "$b2" ]; then
    ok "wrong passphrase and missing id match ($c1)"
  else
    bad "wrong passphrase ($c1) and missing id ($c2) differ"
  fi

  head "6. timing sample"
  T1=$( { /usr/bin/time -f '%e' bash -c "for i in \$(seq 1 30); do curl -sS -o /dev/null '$BASE/s/$AID?p=wrong'; done" ; } 2>&1 | tail -1 )
  T2=$( { /usr/bin/time -f '%e' bash -c "for i in \$(seq 1 30); do curl -sS -o /dev/null '$BASE/s/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA?p=wrong'; done" ; } 2>&1 | tail -1 )
  echo "     wrong-passphrase: ${T1}s   not-found: ${T2}s"
  ok "recorded (compare by eye)"
fi

head "7. rate limiting and X-Forwarded-For spoofing"
CODES=""
for i in $(seq 1 40); do
  c=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE/secrets" \
    -H 'Content-Type: application/json' \
    -H "X-Forwarded-For: 10.9.9.$i" \
    -d '{"content":"flood","ttl_seconds":60,"max_views":1}')
  CODES="$CODES $c"
done
if printf '%s' "$CODES" | grep -qw '429'; then
  ok "burst eventually returns 429 even with rotating X-Forwarded-For"
else
  bad "no 429 in 40 creates with spoofed X-Forwarded-For — spoofable limiter"
fi

head "8. headers"
H=$(curl -sS -D - -o /dev/null "$BASE/")
chk_header() {
  if printf '%s' "$H" | grep -qi "^$1:"; then ok "header present: $1"; else bad "missing header: $1"; fi
}
chk_header 'Cache-Control'
chk_header 'Referrer-Policy'
if printf '%s' "$H" | grep -qi '^Cache-Control:.*no-store'; then ok "Cache-Control includes no-store"; else bad "Cache-Control missing no-store"; fi
if printf '%s' "$H" | grep -qi '^Referrer-Policy:.*no-referrer'; then ok "Referrer-Policy is no-referrer"; else bad "Referrer-Policy is not no-referrer"; fi
chk_header 'Content-Security-Policy'

head "9. /metrics information leak"
M=$(curl -sS "$BASE/metrics" 2>/dev/null || true)
if [ -z "$M" ]; then
  ok "/metrics absent or empty (nothing to leak)"
else
  if printf '%s' "$M" | grep -qiE 'secret_id|content|passphrase|token'; then
    bad "/metrics exposes per-secret fields"
  else
    ok "/metrics exposes aggregate counters only"
  fi
fi

head "10. input handling"
code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE/secrets" -H 'Content-Type: application/json' -d '{"content":"x","max_views":0}')
if [ "$code" = "400" ] || [ "$code" = "422" ]; then ok "max_views=0 rejected ($code)"; else bad "max_views=0 accepted ($code)"; fi

code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE/secrets" -H 'Content-Type: application/json' -d '{"content":"x","ttl_seconds":-5}')
if [ "$code" = "400" ] || [ "$code" = "422" ]; then ok "negative ttl rejected ($code)"; else bad "negative ttl accepted ($code)"; fi

code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE/secrets" -H 'Content-Type: application/json' -d 'not json at all')
if [ "$code" = "400" ] || [ "$code" = "415" ]; then ok "malformed body rejected ($code)"; else bad "malformed body accepted ($code)"; fi

head "11. path traversal and SSRF-shaped probes"
for p in "/s/..%2f..%2fetc%2fpasswd" "/s/%2e%2e/%2e%2e/etc/passwd" "/secrets/../../etc/passwd"; do
  code=$(curl -sS -o /dev/null -w '%{http_code}' "$BASE$p")
  case "$code" in
    200) bad "traversal-shaped path returned 200: $p" ;;
    5*)  bad "traversal-shaped path caused a server error ($code): $p" ;;
    *)   ok "traversal-shaped path handled ($code): $p" ;;
  esac
done

printf '\n\033[1mSummary\033[0m: %d pass, %d fail, %d skip\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ] || exit 1
