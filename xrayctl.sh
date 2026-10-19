#!/bin/sh
# Xray-only controller for the verified HONOR XD20 debug firmware.
# Runtime is in executable /dev tmpfs. Only the compressed binary stays in /data.
# Configuration and runtime logs are private; this controller does not print them.
DATA=/data/xray-test
RUN=/dev/xd20-xray
BIN=$RUN/xray
CONF=$DATA/xray.json
CA=$DATA/cacert.pem
PIDFILE=/tmp/xd20-xray.pid
LOG=/tmp/xd20-xray.log
LOCK=/tmp/xd20-xray.lock
FULL=/tmp/xd20-xray.full
ACTIVE=/tmp/xd20-xray.active
MODEFILE=$DATA/mode
WATCH=/tmp/xd20-xray.watch
WATCHPID=/tmp/xd20-xray.watch.pid
ROUTE=$DATA/xray-route.sh
DNS=$DATA/xray-dns.sh
WEB=$DATA/xray-web.sh
AUTOSTART=$DATA/autostart.enabled
DISABLED=$DATA/vpn.disabled
OWN_LOCK=0
STARTING=0
XRAY_PID=
XRAY_STAMP=
umask 077

say() { printf '%s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
number() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }
clock_ok() {
    CLOCK_NOW=$(date +%s 2>/dev/null) || return 1
    number "$CLOCK_NOW" || return 1
    # v26.9.8 initializes Chromium GREASE headers before reading the config.
    # A 1970 clock produces a negative version and panics in package init.
    # This is a plausibility guard, not a substitute for NTP or TLS verification.
    [ "$CLOCK_NOW" -ge 1767225600 ]
}
safe_empty_remove() {
    EMPTY_TARGET=$1
    case "$EMPTY_TARGET" in /dev/xd20-xray|/tmp/xd20-xray.lock) ;; *) return 1 ;; esac
    [ -d "$EMPTY_TARGET" ] && [ ! -L "$EMPTY_TARGET" ] || return 1
    for EMPTY_ENTRY in "$EMPTY_TARGET"/* "$EMPTY_TARGET"/.[!.]* "$EMPTY_TARGET"/..?*; do
        if [ -e "$EMPTY_ENTRY" ] || [ -L "$EMPTY_ENTRY" ]; then return 1; fi
    done
    # Stock firmware has no rmdir. The target is an exact owned path, now empty.
    rm -r "$EMPTY_TARGET"
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
    XRAY_PID=
    XRAY_STAMP=
    [ -f "$PIDFILE" ] || return 1
    read -r XRAY_PID XRAY_STAMP EXTRA < "$PIDFILE" || return 1
    [ -z "$EXTRA" ] || return 1
    same_stamp "$XRAY_PID" "$XRAY_STAMP" && our_exe "$XRAY_PID"
}
no_unrecorded_xray() {
    for EXEPATH in /proc/[0-9]*/exe; do
        [ -e "$EXEPATH" ] || continue
        CANDIDATE=${EXEPATH#/proc/}
        CANDIDATE=${CANDIDATE%/exe}
        if our_exe "$CANDIDATE"; then
            fail 'An Xray using our runtime exists without a matching PID record.'
        fi
    done
}
available() {
    while read -r K V U; do
        case "$K" in MemAvailable:) printf '%s\n' "$V"; return 0 ;; esac
    done < /proc/meminfo
    return 1
}
check_memory() {
    AVAIL=$(available) || fail 'MemAvailable unavailable.'
    number "$AVAIL" || fail 'Invalid MemAvailable.'
    [ "$AVAIL" -ge "$1" ] || fail "$2"
}
memory() {
    while read -r K V U; do
        case "$K" in MemAvailable:|SwapTotal:|SwapFree:) printf '%s %s %s\n' "$K" "$V" "$U" ;; esac
    done < /proc/meminfo
}
lock() {
    if ! mkdir "$LOCK" 2>/dev/null; then
        LP= LS=
        [ -f "$LOCK/owner" ] && read -r LP LS < "$LOCK/owner"
        if same_stamp "$LP" "$LS"; then fail 'Another controller operation is running.'; fi
        [ -f "$LOCK/owner" ] || fail 'Unrecognized controller lock; refusing to remove it.'
        rm -f "$LOCK/owner" || fail 'Cannot remove stale lock owner.'
        safe_empty_remove "$LOCK" || fail 'Cannot remove stale lock directory.'
        mkdir "$LOCK" || fail 'Cannot acquire the controller lock.'
    fi
    OWN_LOCK=1
    SELF_STAMP=$(stamp "$$") || fail 'Cannot identify this controller process.'
    printf '%s %s\n' "$$" "$SELF_STAMP" > "$LOCK/owner" || fail 'Cannot record the lock owner.'
}
remove_runtime() {
    [ ! -e "$RUN" ] && return 0
    [ ! -L "$RUN" ] && [ -d "$RUN" ] || fail 'Unexpected runtime directory type.'
    MARK=
    [ -f "$RUN/.owner" ] && read -r MARK < "$RUN/.owner"
    [ "$MARK" = XD20_XRAY_RUNTIME_V1 ] || fail 'Runtime directory ownership is unrecognized.'
    no_unrecorded_xray
    rm -f "$BIN" "$RUN/.owner" || fail 'Cannot remove owned runtime files.'
    safe_empty_remove "$RUN" || fail 'Unexpected additional files in the runtime directory.'
}
stop_runtime() {
    if load_pid; then
        TARGET=$XRAY_PID
        TARGET_STAMP=$XRAY_STAMP
        # Identity is checked again immediately before every signal.
        if same_stamp "$TARGET" "$TARGET_STAMP" && our_exe "$TARGET"; then
            kill -TERM "$TARGET" 2>/dev/null
        fi
        N=0
        while same_stamp "$TARGET" "$TARGET_STAMP" && our_exe "$TARGET" && [ "$N" -lt 5 ]; do
            sleep 1
            N=$((N + 1))
        done
        if same_stamp "$TARGET" "$TARGET_STAMP" && our_exe "$TARGET"; then
            kill -KILL "$TARGET" 2>/dev/null
            sleep 1
        fi
        if same_stamp "$TARGET" "$TARGET_STAMP" && our_exe "$TARGET"; then
            fail 'Owned Xray did not stop; preserving its runtime and PID record.'
        fi
    else
        no_unrecorded_xray
    fi
    rm -f "$PIDFILE"
    [ -d /sys/class/net/xray0 ] && fail 'xray0 still exists; refusing to delete an unowned interface.'
    remove_runtime
    say 'Xray stopped. Existing VPN routing safeguards were retained.'
}
finish() {
    RESULT=$?
    trap - 0
    trap '' 1 2 15
    if [ "$STARTING" = 1 ]; then
        # Failed startup only cleans a child recorded with executable and starttime.
        (stop_runtime) >/dev/null 2>&1
    fi
    if [ "$OWN_LOCK" = 1 ]; then
        rm -f "$LOCK/owner"
        safe_empty_remove "$LOCK" 2>/dev/null
    fi
    exit "$RESULT"
}
trap finish 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

prepare() {
    clock_ok || fail 'Router clock is earlier than January 2026; wait for time synchronization before starting Xray.'
    [ -d "$DATA" ] || fail 'Missing persistent directory.'
    [ -x "$DATA/ax3-gunzip" ] || fail 'Missing executable ax3-gunzip.'
    [ -s "$DATA/xray.gz" ] || fail 'Missing compressed Xray.'
    [ -s "$CONF" ] || fail 'Missing private xray.json.'
    [ -s "$CA" ] || fail 'Missing CA bundle.'
    [ -c /dev/net/tun ] || fail 'Missing TUN device.'
    [ ! -d /sys/class/net/xray0 ] || fail 'xray0 already exists; refusing to touch it.'
    no_unrecorded_xray
    remove_runtime
    rm -f "$PIDFILE"
    check_memory 49152 'Less than 48 MiB available before unpacking.'
    mkdir "$RUN" || fail 'Cannot create a fresh runtime directory.'
    printf '%s\n' XD20_XRAY_RUNTIME_V1 > "$RUN/.owner" || fail 'Cannot mark runtime ownership.'
    STARTING=1
    "$DATA/ax3-gunzip" -c "$DATA/xray.gz" > "$BIN" 2>> "$LOG" || fail 'Xray decompression failed.'
    chmod 700 "$BIN" || fail 'Cannot make Xray executable.'
    check_memory 20480 'Less than 20 MiB available after unpacking.'
}
record_child() {
    CHILD=$1
    CHILD_STAMP=$(stamp "$CHILD") || fail 'Xray exited before its PID could be recorded.'
    printf '%s %s\n' "$CHILD" "$CHILD_STAMP" > "$PIDFILE" || fail 'Cannot record Xray ownership.'
    # The asynchronous shell can still be between fork and exec at the first read.
    N=0
    while ! our_exe "$CHILD"; do
        same_stamp "$CHILD" "$CHILD_STAMP" || fail 'Xray exited before executable identity was verified.'
        [ "$N" -lt 3 ] || fail 'Started child executable did not become Xray.'
        sleep 1
        N=$((N + 1))
    done
}
start_runtime() {
    if load_pid; then
        [ -d /sys/class/net/xray0 ] || fail 'Owned Xray is alive but TUN is absent; use recover or stop first.'
        say "Xray already running, PID=$XRAY_PID."
        return 0
    fi
    prepare
    : > "$LOG" || fail 'Cannot create private runtime log.'
    chmod 600 "$LOG" "$CONF" "$CA"
    SSL_CERT_FILE="$CA" GOMAXPROCS=1 GOMEMLIMIT=16MiB "$BIN" run -c "$CONF" >> "$LOG" 2>&1 &
    CHILD=$!
    record_child "$CHILD"
    N=0
    while [ "$N" -lt 10 ]; do
        load_pid || fail 'Xray exited during startup; private log retained.'
        if [ -d /sys/class/net/xray0 ]; then
            STARTING=0
            say "Xray running, PID=$XRAY_PID, TUN=xray0."
            return 0
        fi
        sleep 1
        N=$((N + 1))
    done
    fail 'TUN did not appear within ten seconds.'
}
test_config() {
    if load_pid; then fail 'Stop Xray before validation; a second Xray process would increase memory use.'; fi
    prepare
    : > "$LOG" || fail 'Cannot create private validation log.'
    SSL_CERT_FILE="$CA" GOMAXPROCS=1 GOMEMLIMIT=16MiB "$BIN" run -test -c "$CONF" >> "$LOG" 2>&1 &
    CHILD=$!
    # A valid configuration test may exit before /proc is inspected.
    # Keep wait's exit status even in that case, without launching another child.
    CHILD_STAMP=$(stamp "$CHILD" 2>/dev/null)
    if number "$CHILD_STAMP"; then
        printf '%s %s\n' "$CHILD" "$CHILD_STAMP" > "$PIDFILE" || fail 'Cannot record validation ownership.'
    fi
    N=0
    while same_stamp "$CHILD" "$CHILD_STAMP" && [ "$N" -lt 30 ]; do
        sleep 1
        N=$((N + 1))
    done
    if same_stamp "$CHILD" "$CHILD_STAMP"; then fail 'Configuration validation exceeded thirty seconds.'; fi
    wait "$CHILD"
    RESULT=$?
    rm -f "$PIDFILE"
    remove_runtime
    STARTING=0
    say "CONFIG_TEST_EXIT=$RESULT (private log retained)"
    return "$RESULT"
}
route() { [ -f "$ROUTE" ] || fail 'Missing xray-route.sh.'; sh "$ROUTE" "$@"; }
dns() { [ -f "$DNS" ] || fail 'Missing xray-dns.sh.'; sh "$DNS" "$@"; }
web_optional() {
    [ -f "$WEB" ] && [ -x "$DATA/httpd" ] && [ -s "$DATA/httpd-private.conf" ] || return 0
    if [ "$1" = start ]; then
        sh "$WEB" check >/dev/null 2>&1 && return 0
    fi
    if ! sh "$WEB" "$1" >> /tmp/xd20-xray-web-control.log 2>&1; then
        say "WARNING: optional sites panel action '$1' failed; VPN service remains active."
    fi
    return 0
}
manager_cache_optional() {
    [ -x "$DATA/ax3-manager" ] || return 0
    GOMAXPROCS=1 GOMEMLIMIT=6MiB "$DATA/ax3-manager" action state >/dev/null 2>&1 || say 'WARNING: VPN state cache could not be refreshed.'
}
selected_mode() {
    MODE=selective
    [ -f "$MODEFILE" ] && read -r MODE < "$MODEFILE"
    case "$MODE" in selective|full|inverse) printf '%s\n' "$MODE" ;; *) fail 'Invalid persistent mode; expected selective, inverse or full.' ;; esac
}
active_mode() {
    MODE=
    [ -f "$ACTIVE" ] && read -r MODE < "$ACTIVE"
    case "$MODE" in selective|full|inverse) printf '%s\n' "$MODE" ;; *) fail 'Active VPN routing mode is unrecognized.' ;; esac
}
apply_mode() {
    APPLY_MODE=$1
    LIFETIME=$2
    start_runtime
    if [ "$APPLY_MODE" = selective ] || [ "$APPLY_MODE" = inverse ]; then dns start "$APPLY_MODE" || return $?; fi
    route apply "$APPLY_MODE" "$LIFETIME" || return $?
    printf '%s\n' "$APPLY_MODE" > "$ACTIVE" || fail 'Cannot record active routing mode.'
    if [ "$LIFETIME" = permanent ]; then : > "$FULL"; watch_on; fi
}
watch_off() { rm -f "$WATCH" "$WATCHPID"; }
watch_on() {
    [ -f "$FULL" ] || fail 'Permanent routing is not marked active.'
    WP= WS=
    [ -f "$WATCHPID" ] && read -r WP WS < "$WATCHPID"
    if [ -f "$WATCH" ] && same_stamp "$WP" "$WS"; then return 0; fi
    watch_off
    TOKEN="$$.$SELF_STAMP"
    printf '%s\n' "$TOKEN" > "$WATCH" || fail 'Cannot write watchdog token.'
    sh "$DATA/xrayctl.sh" watch "$TOKEN" </dev/null >> /tmp/xd20-xray-watch.log 2>&1 &
    WP=$!
    WS=$(stamp "$WP") || fail 'Watchdog exited during startup.'
    printf '%s %s\n' "$WP" "$WS" > "$WATCHPID"
}
watch_valid() {
    CURRENT=
    [ -f "$FULL" ] && [ -f "$WATCH" ] || return 1
    read -r CURRENT < "$WATCH" || return 1
    [ "$CURRENT" = "$1" ]
}
recover() {
    watch_valid "$1" || return 0
    RECOVER_MODE=$(active_mode) || return 1
    # The independent transaction supervisor covers even the interval while
    # this normal watchdog is disabled by stop. It alone restores failed jobs.
    [ ! -f /data/xray-manager/switch/pending.json ] || return 0
    if load_pid; then
        if [ ! -d /sys/class/net/xray0 ]; then stop_runtime; start_runtime; fi
    else
        stop_runtime
        start_runtime
    fi
    watch_valid "$1" || return 0
    if [ "$RECOVER_MODE" = selective ] || [ "$RECOVER_MODE" = inverse ]; then
        dns check "$RECOVER_MODE" >/dev/null 2>&1 || dns start "$RECOVER_MODE" || fail 'Could not recover selective DNS.'
    fi
    if ! route check "$RECOVER_MODE" >/dev/null 2>&1; then
        # Reconciliation is limited to routing objects owned by xray-route.sh.
        route apply "$RECOVER_MODE" permanent || fail 'Could not restore owned routing objects.'
    fi
    web_optional start
}
# Scheduled subscription refresh: the manager writes the due time (epoch) to
# refresh.next only when the user enabled it. The check is two file reads, and
# the Go manager starts only when the time has come.
REFRESH_NEXT=/data/xray-manager/refresh.next
maybe_refresh() {
    [ -f "$REFRESH_NEXT" ] && [ -x "$DATA/ax3-manager" ] || return 0
    [ ! -f /data/xray-manager/switch/pending.json ] || return 0
    NEXT=
    read -r NEXT < "$REFRESH_NEXT" || return 0
    number "$NEXT" || return 0
    NOW=$(date +%s 2>/dev/null) || return 0
    number "$NOW" || return 0
    [ "$NOW" -ge 1767225600 ] && [ "$NOW" -ge "$NEXT" ] || return 0
    GOMAXPROCS=1 GOMEMLIMIT=6MiB "$DATA/ax3-manager" action auto-refresh </dev/null >/dev/null 2>&1
}
watch_loop() {
    TOKEN=$1
    [ -n "$TOKEN" ] || fail 'Missing watchdog token.'
    trap - 0 1 2 15
    TICKS=0
    while watch_valid "$TOKEN"; do
        sleep 15
        watch_valid "$TOKEN" || break
        sh "$DATA/xrayctl.sh" recover "$TOKEN"
        TICKS=$((TICKS + 1))
        if [ "$TICKS" -ge 20 ]; then
            TICKS=0
            maybe_refresh &
        fi
    done
}
lan_ready() {
    [ -d /sys/class/net/br0 ] || return 1
    ADDRS=$(/bin/ip -4 addr show dev br0 2>/dev/null) || return 1
    case "$ADDRS" in *"inet "*) return 0 ;; *) return 1 ;; esac
}
status() {
    if load_pid; then
        say "Xray running, PID=$XRAY_PID."
        if [ -d /sys/class/net/xray0 ]; then say 'TUN=xray0 present'; else say 'TUN=xray0 absent'; fi
        while read -r K V U REST; do
            case "$K" in VmRSS:|VmSwap:|Threads:) printf '%s %s %s\n' "$K" "$V" "$U" ;; esac
        done < "/proc/$XRAY_PID/status"
    else
        say 'Xray is not running with a verified ownership record.'
    fi
    [ -f "$AUTOSTART" ] && say 'Autostart=enabled' || say 'Autostart=disabled'
    [ -f "$DISABLED" ] && say 'VPN setting=disabled; web panel retained' || say 'VPN setting=enabled'
    [ -f "$WATCH" ] && say 'Watchdog=enabled' || say 'Watchdog=disabled'
    say "Configured mode=$(selected_mode)"
    [ -f "$ACTIVE" ] && say "Active mode=$(active_mode)"
    memory
    [ -f "$ROUTE" ] && sh "$ROUTE" status
    [ -f "$DNS" ] && sh "$DNS" status
}

ACTION=${1:-status}
case "$ACTION" in
    watch) watch_loop "$2"; exit $? ;;
    status) status; exit $? ;;
    boot)
        [ -f "$AUTOSTART" ] || exit 0
        if [ -f /data/xray-manager/switch/pending.json ]; then
            [ -x "$DATA/ax3-manager" ] || fail 'Pending VPN transaction needs the manager before boot.'
            GOMAXPROCS=1 GOMEMLIMIT=6MiB "$DATA/ax3-manager" recover-switch || fail 'Cannot restore the interrupted VPN transaction.'
        fi
        WAIT_LOGGED=0
        # The rc.d hook runs this controller in the background. Delayed WAN/NTP
        # should not require another reboot or repeated Xray decompression.
        while ! lan_ready; do
            [ -f "$AUTOSTART" ] || exit 0
            if [ "$WAIT_LOGGED" = 0 ]; then
                say 'Waiting for the LAN address and a plausible router clock before starting Xray.'
                WAIT_LOGGED=1
            fi
            sleep 5
        done
        web_optional start
        if [ -f "$DISABLED" ]; then manager_cache_optional; exit 0; fi
        while ! clock_ok; do
            [ -f "$AUTOSTART" ] && [ ! -f "$DISABLED" ] || exit 0
            if [ "$WAIT_LOGGED" = 0 ]; then
                say 'Waiting for a plausible router clock before starting Xray.'
                WAIT_LOGGED=1
            fi
            sleep 5
        done
        ;;
    start|test|stop|rollback|full|selective|inverse|commit|recover|enable-autostart|disable-autostart|enable-vpn|disable-vpn) ;;
    *) fail 'Usage: xrayctl.sh start|test|status|stop|selective|inverse|full [trial|permanent]|commit|rollback|enable-autostart|disable-autostart|boot' ;;
esac
lock
case "$ACTION" in
    start) start_runtime ;;
    test) test_config; exit $? ;;
    stop)
        watch_off
        rm -f "$FULL" "$ACTIVE"
        [ -f "$DNS" ] && dns stop
        stop_runtime
        ;;
    rollback)
        watch_off
        web_optional stop
        rm -f "$FULL" "$ACTIVE" "$AUTOSTART"
        [ -f "$DNS" ] && dns stop
        stop_runtime
        route rollback || exit $?
        say 'Owned VPN routing removed; autostart disabled.'
        ;;
    full|selective|inverse)
        MODE=${2:-trial}
        case "$MODE" in trial|permanent) ;; *) fail 'Routing lifetime must be trial or permanent.' ;; esac
        apply_mode "$ACTION" "$MODE" || exit $?
        ;;
    commit)
        load_pid && [ -d /sys/class/net/xray0 ] || fail 'Xray/TUN is not ready.'
        COMMIT_MODE=$(active_mode) || exit 1
        route commit || exit $?
        route check "$COMMIT_MODE" || fail 'Committed routes do not pass the mode check.'
        : > "$FULL"
        watch_on
        ;;
    boot)
        [ -f "$AUTOSTART" ] || exit 0
        [ ! -f "$DISABLED" ] || exit 0
        BOOT_MODE=$(selected_mode) || exit 1
        apply_mode "$BOOT_MODE" permanent || exit $?
        web_optional start
        manager_cache_optional
        ;;
    recover) recover "$2" ;;
    disable-vpn)
        watch_off
        rm -f "$FULL" "$ACTIVE"
        [ -f "$DNS" ] && dns stop
        stop_runtime
        route rollback || exit $?
        printf '%s\n' XD20_VPN_DISABLED_V1 > "$DISABLED" || fail 'Cannot save disabled VPN setting.'
        chmod 600 "$DISABLED" || fail 'Cannot protect disabled VPN setting.'
        "$DATA/ax3-sync" || fail 'Cannot sync disabled VPN setting.'
        say 'VPN disabled. Internet uses the provider; the web panel remains available.'
        ;;
    enable-vpn)
        ENABLE_MODE=$(selected_mode) || exit 1
        apply_mode "$ENABLE_MODE" permanent || exit $?
        rm -f "$DISABLED" || fail 'Cannot clear disabled VPN setting.'
        printf '%s\n' XD20_XRAY_AUTOSTART_V1 > "$AUTOSTART" || fail 'Cannot save web/VPN boot hook setting.'
        chmod 600 "$AUTOSTART" || fail 'Cannot protect boot hook setting.'
        "$DATA/ax3-sync" || fail 'Cannot sync enabled VPN setting.'
        say 'VPN enabled and will resume after reboot.'
        ;;
    enable-autostart)
        load_pid && [ -d /sys/class/net/xray0 ] || fail 'Verify running Xray before enabling autostart.'
        [ -f "$FULL" ] || fail 'Commit the tested routing before enabling autostart.'
        SAVE_MODE=$(active_mode) || exit 1
        route check "$SAVE_MODE" || fail 'Verify selected routing mode before enabling autostart.'
        printf '%s\n' "$SAVE_MODE" > "$MODEFILE" || fail 'Cannot save autostart routing mode.'
        printf '%s\n' XD20_XRAY_AUTOSTART_V1 > "$AUTOSTART"
        chmod 600 "$AUTOSTART"
        say 'Autostart enabled.'
        ;;
    disable-autostart) rm -f "$AUTOSTART"; say 'Autostart disabled.' ;;
esac
