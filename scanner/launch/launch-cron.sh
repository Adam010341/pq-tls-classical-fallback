#!/bin/bash
# kit-c cron launcher (TEMPLATE) for a scheduled scan.   Usage: launch-cron.sh YYYY-MM-DD
#
# Not armed. Fill in the SETTINGS block during review; the launcher refuses to do anything while a value is FILL-ME.
# Intended crontab (crontab.example, for the 02:00-08:00 window): 02:05, then every 10 minutes from 02:15 to 06:55, on the
# scan date only. All dates and times below are local times in SCAN_TZ, with the window SCAN_WINDOW (start-end).
# Each invocation decides once, logs every decision to $BASE/launch-DATE.log (BASE = the parent of DIR), and then
# either exits or runs guard.py in the foreground (fresh, or --resume when DIR holds an unfinished run) until it ends:
#   exit if: wrong date / settings incomplete / DONE marker present (the run finished) / another launcher for this date
#            holds the launcher lock / a guard.py or run.py process for DIR is alive / local time before the window start
#            or at or after one hour before the window end (02:00 / 07:00 for 02:00-08:00: never start or resume in the
#            last hour) / date not announced or GO phrase not approved / STOP present
#            (needs a person) / clock not NTP-synchronized / `lab check` exit 1 (someone holds an exclusive registration
#            on the shared machine; the next cron tick retries) or any other `lab` failure
#   else:    `lab add -u LAB_UNTIL -p $$ "TLS scan ..."` (trap: lab done), then guard.py run --tz SCAN_TZ --window
#            SCAN_WINDOW [--resume]; after guard exits 0
#            with "RESULT: run finished cleanly" in DIR/guard.log, write DIR/DONE.
# It never sets GUARD_* test variables (any inherited ones are removed) and never removes STOP.
# Kill switch during a run: touch DIR/STOP. Cancel the campaign: remove the crontab lines.
set -u

# ---- BEGIN SETTINGS ----------------------------------------------------------------------------------------------
PATH=/usr/local/bin:/usr/bin:/bin
KIT=FILL-ME                     # directory of this scanner
BASE=FILL-ME                    # directory that holds the per-date output directories and launch-DATE.log
OUT_PREFIX=c1-                  # DIR = $BASE/$OUT_PREFIX$DATE (guard requires the date in the name)
TARGETS=FILL-ME                 # approved targets file
TARGETS_SHA256=FILL-ME          # its sha256
EXPECTED_EGRESS=FILL-ME         # the IPv4 source address announced to the network operator
EGRESS_PREFIX=140.116.          # network of this vantage (guard --egress-prefix); EXPECTED_EGRESS must start with it
VANTAGE_LABEL=FILL-ME           # e.g. "University campus, AS64500, City"
ALLOWED_DATES=FILL-ME           # comma-separated scan dates announced to the network operator
SCAN_TZ=FILL-ME                 # IANA time zone of this vantage, e.g. Asia/Taipei (guard --tz); dates and times are local
SCAN_WINDOW=FILL-ME             # announced local scan window HH:MM-HH:MM, start < end, e.g. 02:00-08:00 (guard --window)
GO_PHRASES=""                   # space-separated GO-<date>-OPERATOR-APPROVED phrases, added only after the operator's approval for that night
FAMILIES=4
WWW=add
MODE=pinned
RESOLVER=system                 # system, or the IPv4 address of a public resolver (a separate campaign; README "Resolver")
PROTO=https                     # https, smtp (then TARGETS is an MX host list, WWW=off, and EHLO_NAME is required) or quic
                                # (then TARGETS is quic_targets.py's name list, WWW=off; guard's default --quic-timeout 8)
EHLO_NAME=""                    # smtp only: EHLO name, a host name that identifies the scanner (guard --ehlo-name)
MAX_MINUTES=360                 # guard maximum; the watchdog stops every run at the window end anyway
PYTHON=/usr/bin/python3
OPENSSL_BIN=FILL-ME             # OpenSSL 3.5.x with X25519MLKEM768
OPENSSL_CONF_FILE=FILL-ME
LAB_UNTIL=08:00                 # `lab add -u`: the guard's watchdog ends every run by 08:00
LAB_DESC="TLS key-share scan (guard.py): handshakes at most 18/s, network-bound, light CPU"
# ---- END SETTINGS ------------------------------------------------------------------------------------------------

DATE=${1:-}
if ! [[ $DATE =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
  echo "usage: $0 YYYY-MM-DD" >&2; exit 2
fi
for v in KIT BASE OUT_PREFIX TARGETS TARGETS_SHA256 EXPECTED_EGRESS EGRESS_PREFIX VANTAGE_LABEL ALLOWED_DATES SCAN_TZ SCAN_WINDOW PYTHON OPENSSL_BIN OPENSSL_CONF_FILE; do
  if [ -z "${!v}" ] || [ "${!v}" = FILL-ME ]; then
    echo "launch-cron.sh: setting $v is not filled in; refusing" >&2; exit 2
  fi
done
# `date` silently falls back to UTC for an unknown TZ, so the zone must be a real zoneinfo file
if ! [[ $SCAN_TZ =~ ^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+)*$ ]] || [ ! -f "/usr/share/zoneinfo/$SCAN_TZ" ]; then
  echo "launch-cron.sh: SCAN_TZ '$SCAN_TZ' is not an IANA time zone in /usr/share/zoneinfo; refusing" >&2; exit 2
fi
if ! [[ $SCAN_WINDOW =~ ^([01][0-9]|2[0-3]):([0-5][0-9])-([01][0-9]|2[0-3]):([0-5][0-9])$ ]]; then
  echo "launch-cron.sh: SCAN_WINDOW '$SCAN_WINDOW' is not HH:MM-HH:MM; refusing" >&2; exit 2
fi
w_start=$((10#${BASH_REMATCH[1]} * 60 + 10#${BASH_REMATCH[2]}))
w_end=$((10#${BASH_REMATCH[3]} * 60 + 10#${BASH_REMATCH[4]}))
if [ "$w_start" -ge "$w_end" ]; then
  echo "launch-cron.sh: SCAN_WINDOW '$SCAN_WINDOW' must start before it ends within one local day; refusing" >&2; exit 2
fi
w_last=$((w_end - 60))          # never start or resume in the last hour of the window
hm() { printf '%02d:%02d' $(($1 / 60)) $(($1 % 60)); }
DIR=$BASE/$OUT_PREFIX$DATE
LOG=$BASE/launch-$DATE.log
mkdir -p "$BASE" || exit 2

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [local $SCAN_TZ $(TZ=$SCAN_TZ date '+%F %T')] pid $$: $*" >> "$LOG"; }

# 1. never run with test overrides
stripped=""
for v in $(compgen -e); do
  case "$v" in GUARD_*|KITC_GUARD_NONCE) stripped="$stripped $v"; unset "$v" ;; esac
done
[ -n "$stripped" ] && log "WARNING: removed inherited test/override variables:$stripped"
export OPENSSL="$OPENSSL_BIN" OPENSSL_CONF="$OPENSSL_CONF_FILE"

# 2. one launcher at a time per date (the lock is inherited by guard.py, so it stays held while a run is going on)
exec 9>>"$BASE/.launch-$DATE.lock"
if ! flock -n 9; then
  log "EXIT: another launcher for $DATE holds $BASE/.launch-$DATE.lock (a run is in progress or a launcher is deciding)"
  exit 0
fi

today=$(TZ=$SCAN_TZ date +%F)
hhmm=$(TZ=$SCAN_TZ date +%H%M)
if [ "$today" != "$DATE" ]; then
  log "EXIT: local date ($SCAN_TZ) is $today, not $DATE (crontab lines fire every year; remove them after the campaign)"; exit 0
fi

# 3. finished?
if [ -e "$DIR/DONE" ]; then
  log "EXIT: run finished ($DIR/DONE exists)"; exit 0
fi

# 4. a guard.py or run.py process for DIR alive?
alive=""
for d in /proc/[0-9]*; do
  p=${d#/proc/}
  [ "$p" = "$$" ] && continue
  c=$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null) || continue
  case "$c" in
    *guard.py*" $DIR "*|*run.py*" $DIR "*) alive="$alive $p" ;;
  esac
done
if [ -n "$alive" ]; then
  log "EXIT: guard.py/run.py process(es) for $DIR alive:$alive"; exit 0
fi

# 5. time of day: start or resume only in [window start, window end - 1 h)   (02:00-08:00: [02:00, 07:00))
now_min=$((10#${hhmm:0:2} * 60 + 10#${hhmm:2:2}))
if [ "$now_min" -lt "$w_start" ]; then
  log "EXIT: local time ($SCAN_TZ) $hhmm is before the window start $(hm $w_start)"; exit 0
fi
if [ "$now_min" -ge "$w_last" ]; then
  log "EXIT: local time ($SCAN_TZ) $hhmm is at or after $(hm $w_last) (one hour before the window end $(hm $w_end)); not starting or resuming"; exit 0
fi

# 6. announced date and the operator's GO phrase for it
go="GO-$DATE-OPERATOR-APPROVED"
case ",$ALLOWED_DATES," in *",$DATE,"*) ;; *) log "EXIT: $DATE is not in ALLOWED_DATES ($ALLOWED_DATES)"; exit 0 ;; esac
case " $GO_PHRASES " in *" $go "*) ;; *) log "EXIT: $go is not in GO_PHRASES (not approved for this night)"; exit 0 ;; esac

# 7. STOP needs a person
if [ -e "$DIR/STOP" ]; then
  log "EXIT: $DIR/STOP exists ($(head -c 200 "$DIR/STOP" | tr '\n' ' ')); a stopped run is never restarted or resumed by cron"
  exit 0
fi

# 8. clock (guard check (k) repeats this; checked here so an unsynchronized clock is logged and retried next tick)
ntp=$(timedatectl show -p NTPSynchronized --value 2>&1); ntp_rc=$?
if [ $ntp_rc -ne 0 ] || [ "$ntp" != yes ]; then
  log "EXIT: clock not NTP-synchronized (timedatectl exit $ntp_rc, output '$ntp'); next tick retries"; exit 0
fi

# 9. shared-machine registry
lab check > /dev/null 2>&1 9>&-; lab_rc=$?
if [ $lab_rc -eq 1 ]; then
  log "EXIT: lab check exit 1: someone holds an exclusive registration; next tick retries. Board: $(lab 2>&1 9>&- | tr '\n' ' ' | head -c 600)"
  exit 0
elif [ $lab_rc -ne 0 ]; then
  log "EXIT: lab check failed with exit $lab_rc (registry unusable); not starting"; exit 0
fi

# 10. fresh or resume
mode=fresh
for f in results.tsv probes.log run-meta.json guard-meta.json .guard.lock traces.jsonl.xz; do
  [ -e "$DIR/$f" ] && mode=resume
done

id=$(lab add -u "$LAB_UNTIL" -p $$ "$LAB_DESC" 9>&-); add_rc=$?
if [ $add_rc -ne 0 ] || [ -z "$id" ]; then
  log "EXIT: lab add failed (exit $add_rc, id '$id'); not starting"; exit 0
fi
trap 'lab done "$id" > /dev/null 2>&1 9>&-' EXIT
trap 'exit 143' TERM INT HUP
log "registered lab id=$id until $LAB_UNTIL; starting guard.py run ($mode) for $DIR"

args=(run --date "$DATE" --allowed-dates "$ALLOWED_DATES" --out "$DIR" --targets "$TARGETS"
      --targets-sha256 "$TARGETS_SHA256" --expected-egress "$EXPECTED_EGRESS" --egress-prefix "$EGRESS_PREFIX"
      --vantage-label "$VANTAGE_LABEL"
      --max-minutes "$MAX_MINUTES" --families "$FAMILIES" --www "$WWW" --mode "$MODE" --tz "$SCAN_TZ" --window "$SCAN_WINDOW"
      --resolver "$RESOLVER" --proto "$PROTO" --go "$go")
[ "$PROTO" = smtp ] && args+=(--ehlo-name "$EHLO_NAME")
[ "$mode" = resume ] && args+=(--resume)
cd "$KIT" || { log "EXIT: cannot cd to $KIT"; exit 0; }
"$PYTHON" -I "$KIT/guard.py" "${args[@]}" >> "$LOG" 2>&1
rc=$?
result=$(grep 'RESULT:' "$DIR/guard.log" 2>/dev/null | tail -1 | sed 's/.*RESULT: //')
log "guard.py ($mode) exited $rc; last guard.log RESULT: ${result:-none}"
if [ $rc -eq 0 ] && [[ $result == "run finished cleanly"* ]]; then
  echo "finished $(date -Is) launcher pid $$" > "$DIR/DONE"
  log "DONE: wrote $DIR/DONE"
fi
exit 0
