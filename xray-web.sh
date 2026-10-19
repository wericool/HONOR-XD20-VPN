#!/bin/sh
# Optional authenticated local sites panel; independent of VPN routing ownership.
DATA=/data/xray-test
BIN=$DATA/httpd
WEB=$DATA/web
CONF=$DATA/httpd-private.conf
PIDFILE=/tmp/xd20-xray-web.pid
LOG=/tmp/xd20-xray-web.log
LOCK=/tmp/xd20-xray-web.lock
STATE=/tmp/xd20-xray-web.state
CHAIN=XD20_XRAY_WEB
IPT=iptables
OWN_LOCK=0
STARTING=0
umask 077
say() { printf '%s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
number() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }
safe_empty_remove() {
    case "$1" in /tmp/xd20-xray-web.lock|/tmp/xd20-xray-web.state) ;; *) return 1 ;; esac
    [ -d "$1" ] && [ ! -L "$1" ] || return 1
    for E in "$1"/* "$1"/.[!.]* "$1"/..?*; do
        if [ -e "$E" ] || [ -L "$E" ]; then return 1; fi
    done
    rm -r "$1"
}
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
same_stamp() {
    number "$1" && number "$2" || return 1
    GOT=$(stamp "$1" 2>/dev/null) || return 1
    [ "$GOT" = "$2" ]
}
our_exe() {
    number "$1" || return 1
    EXE=$(ls -l "/proc/$1/exe" 2>/dev/null) || return 1
    case "$EXE" in *" -> $BIN") return 0 ;; *) return 1 ;; esac
}
load_pid() {
    HP= HS= EXTRA=
    [ -f "$PIDFILE" ] || return 1
    read -r HP HS EXTRA < "$PIDFILE" || return 1
    [ -z "$EXTRA" ] && same_stamp "$HP" "$HS" && our_exe "$HP"
}
no_unrecorded_httpd() {
    for EXEPATH in /proc/[0-9]*/exe; do
        [ -e "$EXEPATH" ] || continue
        CANDIDATE=${EXEPATH#/proc/}
        CANDIDATE=${CANDIDATE%/exe}
        our_exe "$CANDIDATE" && fail 'An unrecorded httpd uses our private binary; retry after active requests finish.'
    done
}
lock() {
    if ! mkdir "$LOCK" 2>/dev/null; then
        LP= LS=
        [ -f "$LOCK/owner" ] && read -r LP LS < "$LOCK/owner"
        same_stamp "$LP" "$LS" && fail 'Another web service operation is running.'
        [ -f "$LOCK/owner" ] || fail 'Unrecognized web service lock.'
        rm -f "$LOCK/owner"
        safe_empty_remove "$LOCK" || fail 'Cannot remove stale web lock.'
        mkdir "$LOCK" || fail 'Cannot acquire web service lock.'
    fi
    OWN_LOCK=1
    SELF_STAMP=$(stamp "$$") || fail 'Cannot identify this web controller.'
    printf '%s %s\n' "$$" "$SELF_STAMP" > "$LOCK/owner" || fail 'Cannot record web lock.'
}
owned_state() {
    MARK=
    [ -d "$STATE" ] && [ ! -L "$STATE" ] && [ -f "$STATE/owner" ] || return 1
    read -r MARK < "$STATE/owner" || return 1
    [ "$MARK" = XD20_XRAY_WEB_V1 ]
}
remove_rule() {
    BASE=$1
    shift
    N=0
    while "$IPT" -C "$BASE" "$@" 2>/dev/null; do
        [ "$N" -lt 16 ] || return 1
        "$IPT" -D "$BASE" "$@" || return 1
        N=$((N + 1))
    done
}
remove_own_rules() {
    remove_rule "$CHAIN" -i br0 -s 192.168.3.0/24 -d 192.168.3.1 -p tcp --dport 8088 -j ACCEPT || return 1
    remove_rule "$CHAIN" -p tcp --dport 8088 -j DROP || return 1
    remove_rule "$CHAIN" -j RETURN
}
known_chain() {
    [ -f "$STATE/chain" ] || return 1
    "$IPT" -S "$CHAIN" > "$LOCK/chain" 2>/dev/null || return 1
    while IFS= read -r GOT_LINE; do
        MATCH=0
        while IFS= read -r WANT_LINE; do [ "$GOT_LINE" = "$WANT_LINE" ] && MATCH=1; done < "$STATE/chain"
        [ "$MATCH" = 1 ] || return 1
    done < "$LOCK/chain"
    rm -f "$LOCK/chain"
}
firewall_start() {
    if [ -e "$STATE" ]; then
        owned_state || fail 'Unrecognized web firewall state.'
        if "$IPT" -S "$CHAIN" >/dev/null 2>&1; then
            known_chain || fail 'Web chain contains an unfamiliar rule.'
        fi
    else
        "$IPT" -S "$CHAIN" >/dev/null 2>&1 && fail 'Web firewall chain name is already used.'
        mkdir "$STATE" || fail 'Cannot create web firewall state.'
        printf '%s\n' XD20_XRAY_WEB_V1 > "$STATE/owner" || fail 'Cannot mark web firewall ownership.'
    fi
    "$IPT" -S "$CHAIN" >/dev/null 2>&1 || "$IPT" -N "$CHAIN" || fail 'Cannot create web INPUT chain.'
    remove_own_rules || fail 'Cannot reconcile owned web rules.'
    "$IPT" -A "$CHAIN" -i br0 -s 192.168.3.0/24 -d 192.168.3.1 -p tcp --dport 8088 -j ACCEPT || fail 'Cannot allow primary LAN access.'
    "$IPT" -A "$CHAIN" -p tcp --dport 8088 -j DROP || fail 'Cannot block other sources.'
    "$IPT" -A "$CHAIN" -j RETURN || fail 'Cannot complete web INPUT chain.'
    remove_rule INPUT -j "$CHAIN" || fail 'Cannot reconcile web INPUT jump.'
    "$IPT" -I INPUT 1 -j "$CHAIN" || fail 'Cannot install web INPUT jump.'
    "$IPT" -S "$CHAIN" > "$STATE/chain" || fail 'Cannot save web firewall ownership.'
}
firewall_stop() {
    [ ! -e "$STATE" ] && return 0
    owned_state || fail 'Unrecognized web firewall state; refusing removal.'
    remove_rule INPUT -j "$CHAIN" || fail 'Cannot remove owned web INPUT jump.'
    remove_own_rules || fail 'Cannot remove owned web rules.'
    if "$IPT" -S "$CHAIN" >/dev/null 2>&1; then
        "$IPT" -X "$CHAIN" || fail 'Web chain still contains or is referenced by unfamiliar rules.'
    fi
    rm -f "$STATE/owner" "$STATE/chain"
    safe_empty_remove "$STATE" || fail 'Unexpected additional web state files.'
}
stop_httpd() {
    if load_pid; then
        TARGET=$HP
        TARGET_STAMP=$HS
        same_stamp "$TARGET" "$TARGET_STAMP" && our_exe "$TARGET" && kill -TERM "$TARGET" 2>/dev/null
        N=0
        while same_stamp "$TARGET" "$TARGET_STAMP" && our_exe "$TARGET" && [ "$N" -lt 5 ]; do
            sleep 1
            N=$((N + 1))
        done
        if same_stamp "$TARGET" "$TARGET_STAMP" && our_exe "$TARGET"; then
            kill -KILL "$TARGET" 2>/dev/null
            sleep 1
        fi
        same_stamp "$TARGET" "$TARGET_STAMP" && our_exe "$TARGET" && fail 'Owned web server did not stop.'
    else
        no_unrecorded_httpd
    fi
    rm -f "$PIDFILE"
}
finish() {
    RESULT=$?
    trap - 0
    trap '' 1 2 15
    if [ "$STARTING" = 1 ]; then
        (stop_httpd; firewall_stop) >/dev/null 2>&1
    fi
    if [ "$OWN_LOCK" = 1 ]; then
        rm -f "$LOCK/owner" "$LOCK/chain"
        safe_empty_remove "$LOCK" 2>/dev/null
    fi
    exit "$RESULT"
}
trap finish 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15
check_auth() {
    [ -f "$CONF" ] && [ -s "$CONF" ] && [ ! -L "$CONF" ] || fail 'Missing private httpd authentication configuration.'
    AUTH=0
    while IFS= read -r LINE; do
        case "$LINE" in /:*)
            CREDS=${LINE#/:}
            USERNAME=${CREDS%%:*}
            PASSWORD=${CREDS#*:}
            [ "$PASSWORD" != "$CREDS" ] && [ -n "$USERNAME" ] && [ -n "$PASSWORD" ] || fail 'Empty root authentication rule.'
            [ "$USERNAME" != '*' ] && [ "$PASSWORD" != '*' ] || fail 'Wildcard authentication is not allowed.'
            AUTH=1
            ;;
        esac
    done < "$CONF"
    [ "$AUTH" = 1 ] || fail 'Root Basic authentication rule is missing.'
    chmod 600 "$CONF" || fail 'Cannot protect private authentication file.'
}
start() {
    if load_pid; then
        check_auth
        firewall_start
        say "Sites panel already running, PID=$HP."
        return 0
    fi
    no_unrecorded_httpd
    [ -x "$BIN" ] || fail 'Missing executable private httpd.'
    [ -d "$WEB" ] && [ ! -L "$WEB" ] && [ -f "$WEB/index.html" ] && [ -x "$WEB/cgi-bin/sites.cgi" ] || fail 'Missing local panel files.'
    check_auth
    STARTING=1
    firewall_start
    [ ! -L "$LOG" ] || fail 'Refusing symlinked web log.'
    : > "$LOG" || fail 'Cannot create private web log.'
    "$BIN" -f -p 192.168.3.1:8088 -h "$WEB" -c "$CONF" -r 'HONOR VPN Sites' </dev/null >> "$LOG" 2>&1 &
    CHILD=$!
    CHILD_STAMP=$(stamp "$CHILD") || fail 'Web server exited before PID record.'
    printf '%s %s\n' "$CHILD" "$CHILD_STAMP" > "$PIDFILE" || fail 'Cannot record web process ownership.'
    sleep 1
    load_pid || fail 'Web server exited during startup; private log retained.'
    STARTING=0
    say "Sites panel running, PID=$HP, URL=http://192.168.3.1:8088/."
}
status() {
    if load_pid; then say "Sites panel running, PID=$HP, URL=http://192.168.3.1:8088/."; else say 'Sites panel is down.'; fi
    owned_state && say 'Web firewall state=owned' || say 'Web firewall state=absent'
}
ACTION=${1:-status}
case "$ACTION" in
    status) status; exit $? ;;
    check)
        load_pid && owned_state && "$IPT" -C INPUT -j "$CHAIN" &&
        "$IPT" -C "$CHAIN" -i br0 -s 192.168.3.0/24 -d 192.168.3.1 -p tcp --dport 8088 -j ACCEPT &&
        "$IPT" -C "$CHAIN" -p tcp --dport 8088 -j DROP &&
        "$IPT" -C "$CHAIN" -j RETURN
        exit $?
        ;;
    start|stop|restart) ;;
    *) fail 'Usage: xray-web.sh start|stop|restart|status|check' ;;
esac
lock
case "$ACTION" in
    start) start ;;
    stop) stop_httpd; firewall_stop; say 'Sites panel stopped; VPN was not changed.' ;;
    restart) stop_httpd; firewall_stop; start ;;
esac
