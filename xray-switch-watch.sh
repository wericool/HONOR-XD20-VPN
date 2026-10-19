#!/bin/sh
# Independent, bounded supervisor for one recorded router transaction worker.
JOB=$1
WORKER=$2
WORKER_STAMP=$3
PENDING=/data/xray-manager/switch/pending.json
JOBFILE=/data/xray-manager/switch/pending.id
umask 077
number() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }
stamp() (
    number "$1" || exit 1
    read -r LINE < "/proc/$1/stat" || exit 1
    TAIL=${LINE##*) }
    [ "$TAIL" != "$LINE" ] || exit 1
    set -f
    set -- $TAIL
    [ "$#" -ge 20 ] || exit 1
    shift 19
    number "$1" || exit 1
    printf '%s\n' "$1"
)
alive() {
    GOT=$(stamp "$WORKER" 2>/dev/null) || return 1
    [ "$GOT" = "$WORKER_STAMP" ]
}
current_job() {
    [ -f "$PENDING" ] && [ ! -L "$PENDING" ] && [ -f "$JOBFILE" ] && [ ! -L "$JOBFILE" ] || return 1
    CURRENT=
    read -r CURRENT < "$JOBFILE" || return 1
    [ "$CURRENT" = "$JOB" ]
}
case "$JOB" in ''|*[!0-9a-f]*) exit 1 ;; esac
[ "${#JOB}" = 20 ] && number "$WORKER" && number "$WORKER_STAMP" || exit 1
N=0
while alive && [ "$N" -lt 60 ]; do
    current_job || exit 0
    sleep 3
    N=$((N + 1))
done
if alive; then
    current_job || exit 0
    # Only signal the process identified when this supervisor was started.
    current_job && alive && kill -TERM "$WORKER" 2>/dev/null
    N=0
    while alive && [ "$N" -lt 20 ]; do sleep 3; N=$((N + 1)); done
    current_job && alive && kill -KILL "$WORKER" 2>/dev/null
fi
current_job || exit 0
# An orphaned ctl validation is bounded at 30 seconds; let its lock settle.
sleep 5
N=0
while current_job && [ "$N" -lt 3 ]; do
    sh /data/xray-test/xray-switch.sh "$JOB" recover && exit 0
    N=$((N + 1))
    [ "$N" -ge 3 ] || sleep 20
done
exit 1
