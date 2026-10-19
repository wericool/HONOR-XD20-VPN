#!/bin/sh
# Selective DNS helper (also serves inverse mode: everything via VPN DNS except the exception list). Routes/firewall are exclusively owned by xray-route.sh.
DATA=/data/xray-test
BIN=$DATA/dnsmasq
SET=xd20_vpn
SETOWNER=/tmp/xd20-vpn-set.owner
SETMARK=XD20_VPN_IPSET_V1
MODE=selective
CONF=/tmp/xd20-dnsmasq.conf
PIDFILE=/tmp/xd20-dnsmasq.pid
DAEMONPID=/tmp/xd20-dnsmasq.daemon.pid
LOG=/tmp/xd20-dnsmasq.log
LOCK=/tmp/xd20-dnsmasq.lock
OWN_LOCK=0
umask 077
say() { printf '%s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
number() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }
safe_empty_remove() {
    EMPTY_TARGET=$1
    [ "$EMPTY_TARGET" = /tmp/xd20-dnsmasq.lock ] || return 1
    [ -d "$EMPTY_TARGET" ] && [ ! -L "$EMPTY_TARGET" ] || return 1
    for EMPTY_ENTRY in "$EMPTY_TARGET"/* "$EMPTY_TARGET"/.[!.]* "$EMPTY_TARGET"/..?*; do
        if [ -e "$EMPTY_ENTRY" ] || [ -L "$EMPTY_ENTRY" ]; then return 1; fi
    done
    # Only this exact owned directory, after confirming no entries remain.
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
    DP= DS= EXTRA=
    [ -f "$PIDFILE" ] || return 1
    read -r DP DS EXTRA < "$PIDFILE" || return 1
    [ -z "$EXTRA" ] && same_stamp "$DP" "$DS" && our_exe "$DP"
}
no_unrecorded_dns() {
    for EXEPATH in /proc/[0-9]*/exe; do
        [ -e "$EXEPATH" ] || continue
        CANDIDATE=${EXEPATH#/proc/}
        CANDIDATE=${CANDIDATE%/exe}
        our_exe "$CANDIDATE" && fail 'An unrecorded dnsmasq uses our persistent binary.'
    done
}
lock() {
    if ! mkdir "$LOCK" 2>/dev/null; then
        LP= LS=
        [ -f "$LOCK/owner" ] && read -r LP LS < "$LOCK/owner"
        same_stamp "$LP" "$LS" && fail 'Another DNS operation is running.'
        [ -f "$LOCK/owner" ] || fail 'Unrecognized DNS lock.'
        rm -f "$LOCK/owner"
        safe_empty_remove "$LOCK" || fail 'Cannot remove stale DNS lock.'
        mkdir "$LOCK" || fail 'Cannot acquire DNS lock.'
    fi
    OWN_LOCK=1
    SELF_STAMP=$(stamp "$$") || fail 'Cannot identify DNS controller.'
    printf '%s %s\n' "$$" "$SELF_STAMP" > "$LOCK/owner" || fail 'Cannot record DNS lock.'
}
finish() {
    RESULT=$?
    trap - 0
    if [ "$OWN_LOCK" = 1 ]; then rm -f "$LOCK/owner"; safe_empty_remove "$LOCK" 2>/dev/null; fi
    exit "$RESULT"
}
trap finish 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15
set_exists() { ipset list "$SET" -terse >/dev/null 2>&1; }
owned_set() {
    MARK=
    [ -f "$SETOWNER" ] && read -r MARK < "$SETOWNER"
    [ "$MARK" = "$SETMARK" ]
}
SET_MAXELEM=65536
grow_set() {
    NEW=${SET}_grow
    ipset destroy "$NEW" >/dev/null 2>&1
    ipset create "$NEW" hash:net family inet hashsize 4096 maxelem "$SET_MAXELEM" || fail 'Cannot create enlarged ipset.'
    ipset save "$SET" | while read -r CMD NAME REST; do
        [ "$CMD" = add ] && printf 'add %s %s\n' "$NEW" "$REST"
    done | ipset restore -exist
    ipset swap "$NEW" "$SET" || { ipset destroy "$NEW" >/dev/null 2>&1; fail 'Cannot swap enlarged ipset.'; }
    ipset destroy "$NEW" >/dev/null 2>&1
    say "Selective ipset enlarged to maxelem=$SET_MAXELEM."
}
prepare_set() {
    if set_exists; then
        owned_set || fail 'Existing xd20_vpn ipset is not marked as ours.'
        INFO=$(ipset list "$SET" -terse) || fail 'Cannot inspect xd20_vpn.'
        case "$INFO" in *"Type: hash:net"*) ;; *) fail 'Unexpected xd20_vpn set type.' ;; esac
        case "$INFO" in *"family inet "*) ;; *) fail 'Unexpected xd20_vpn address family.' ;; esac
        # Older installs created the set with maxelem 8192; grow it in place of the old one.
        case "$INFO" in *"maxelem $SET_MAXELEM"*) ;; *) grow_set ;; esac
    else
        ipset create "$SET" hash:net family inet hashsize 4096 maxelem "$SET_MAXELEM" || fail 'Cannot create selective IPv4 ipset.'
        printf '%s\n' "$SETMARK" > "$SETOWNER" || fail 'Cannot mark ipset ownership.'
    fi
    if [ "$MODE" = inverse ]; then
        say 'Exception ipset ready.'
        return 0
    fi
    [ -f "$DATA/ip.lst" ] || fail 'Missing ip.lst.'
    COUNT=0
    while read -r NET EXTRA || [ -n "$NET" ]; do
        case "$NET" in ''|\#*) continue ;; *[!0-9./]*) fail 'Invalid character in ip.lst.' ;; esac
        case "$EXTRA" in ''|\#*) ;; *) fail 'Extra fields in ip.lst.' ;; esac
        ipset add "$SET" "$NET" -exist >/dev/null 2>&1 || fail 'Invalid IP/network or full selective ipset.'
        COUNT=$((COUNT + 1))
    done < "$DATA/ip.lst"
    say "Static IPv4 entries=$COUNT."
}
make_conf_inverse() {
    BYPASS=$DATA/bypass.lst
    [ ! -L "$CONF" ] || fail 'Refusing symlinked DNS configuration.'
    {
        printf '%s\n' 'port=5353' 'interface=br0' 'listen-address=192.168.3.1' 'bind-interfaces'
        # Default: resolve through the VPN. Exceptions use the router's normal DNS.
        printf '%s\n' 'no-resolv' 'no-hosts' 'server=127.0.0.1#5354' 'cache-size=1500' 'no-negcache'
        printf 'pid-file=%s\n' "$DAEMONPID"
        printf '%s\n' 'user=root'
    } > "$CONF" || fail 'Cannot create private DNS configuration.'
    COUNT=0
    if [ -f "$BYPASS" ] && [ ! -L "$BYPASS" ]; then
        while read -r DOMAIN EXTRA || [ -n "$DOMAIN" ]; do
            case "$DOMAIN" in ''|\#*) continue ;; esac
            case "$DOMAIN" in *[!a-zA-Z0-9.-]*|.*|*.) fail 'Invalid domain name in bypass.lst.' ;; esac
            case "$EXTRA" in ''|\#*) ;; *) fail 'Extra fields in bypass.lst.' ;; esac
            printf 'server=/%s/127.0.0.1#53\n' "$DOMAIN" >> "$CONF" || fail 'Cannot append exception DNS upstream.'
            printf 'ipset=/%s/%s\n' "$DOMAIN" "$SET" >> "$CONF" || fail 'Cannot append exception domain.'
            COUNT=$((COUNT + 1))
        done < "$BYPASS"
    fi
    say "Exception domain suffixes=$COUNT."
}
make_conf() {
    if [ "$MODE" = inverse ]; then make_conf_inverse; return $?; fi
    [ -f "$DATA/domain.lst" ] || fail 'Missing domain.lst.'
    [ ! -L "$CONF" ] || fail 'Refusing symlinked DNS configuration.'
    {
        printf '%s\n' 'port=5353' 'interface=br0' 'listen-address=192.168.3.1' 'bind-interfaces'
        printf '%s\n' 'no-resolv' 'no-hosts' 'server=127.0.0.1#53' 'cache-size=1500' 'no-negcache'
        printf 'pid-file=%s\n' "$DAEMONPID"
        printf '%s\n' 'user=root'
    } > "$CONF" || fail 'Cannot create private DNS configuration.'
    COUNT=0
    while read -r DOMAIN EXTRA || [ -n "$DOMAIN" ]; do
        case "$DOMAIN" in ''|\#*) continue ;; esac
        case "$DOMAIN" in *[!a-zA-Z0-9.-]*|.*|*.) fail 'Invalid domain name in domain.lst.' ;; esac
        case "$EXTRA" in ''|\#*) ;; *) fail 'Extra fields in domain.lst.' ;; esac
        printf 'server=/%s/127.0.0.1#5354\n' "$DOMAIN" >> "$CONF" || fail 'Cannot append selected DNS upstream.'
        printf 'ipset=/%s/%s\n' "$DOMAIN" "$SET" >> "$CONF" || fail 'Cannot append selected domain.'
        COUNT=$((COUNT + 1))
    done < "$DATA/domain.lst"
    [ "$COUNT" -gt 0 ] || fail 'Selected domain list is empty.'
    say "Selected domain suffixes=$COUNT."
}
start() {
    if load_pid; then
        if set_exists && owned_set; then
            say "Selective DNS already running, PID=$DP."
            return 0
        fi
        if set_exists; then fail 'Running DNS has an unrecognized ipset.'; fi
        # Recreate a missing set with an empty DNS cache so answers repopulate it.
        stop
    fi
    no_unrecorded_dns
    [ -x "$BIN" ] || fail 'Missing executable dnsmasq.'
    prepare_set
    make_conf
    [ ! -L "$LOG" ] || fail 'Refusing symlinked DNS log.'
    : > "$LOG" || fail 'Cannot create DNS log.'
    "$BIN" --test --conf-file="$CONF" >> "$LOG" 2>&1 || fail 'dnsmasq configuration validation failed; private log retained.'
    "$BIN" --keep-in-foreground --conf-file="$CONF" </dev/null >> "$LOG" 2>&1 &
    CHILD=$!
    CHILD_STAMP=$(stamp "$CHILD") || fail 'dnsmasq exited before PID record.'
    printf '%s %s\n' "$CHILD" "$CHILD_STAMP" > "$PIDFILE" || fail 'Cannot record DNS process ownership.'
    sleep 1
    load_pid || fail 'dnsmasq exited during startup; private log retained.'
    say "Selective DNS running, PID=$DP, port=5353, set=$SET."
}
stop() {
    if load_pid; then
        TARGET=$DP
        TARGET_STAMP=$DS
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
        same_stamp "$TARGET" "$TARGET_STAMP" && our_exe "$TARGET" && fail 'Owned dnsmasq did not stop.'
    else
        no_unrecorded_dns
    fi
    rm -f "$PIDFILE" "$DAEMONPID"
    say 'Selective DNS stopped; its ipset remains for fail-closed routing.'
}
status() {
    if load_pid; then say "Selective DNS running, PID=$DP, port=5353."; else say 'Selective DNS is down.'; fi
    if set_exists; then
        owned_set && say 'Selective ipset=owned' || say 'Selective ipset=unrecognized'
        ipset list "$SET" -terse
    else
        say 'Selective ipset=absent'
    fi
}
# Mode: explicit argument, else the active routing mode, else the saved mode.
resolve_mode() {
    WANT=$1
    if [ -z "$WANT" ]; then
        [ -f /tmp/xd20-xray.active ] && read -r WANT < /tmp/xd20-xray.active
    fi
    if [ -z "$WANT" ]; then
        [ -f "$DATA/mode" ] && read -r WANT < "$DATA/mode"
    fi
    case "$WANT" in
        inverse)
            MODE=inverse
            SET=xd20_bypass
            SETOWNER=/tmp/xd20-bypass-set.owner
            SETMARK=XD20_BYPASS_IPSET_V1
            ;;
        *) MODE=selective ;;
    esac
}
ACTION=${1:-status}
resolve_mode "$2"
case "$ACTION" in
    status) status; exit $? ;;
    check) load_pid && set_exists && owned_set; exit $? ;;
    start|stop|restart|purge) ;;
    *) fail 'Usage: xray-dns.sh start|stop|restart|status|check|purge' ;;
esac
lock
case "$ACTION" in
    start) start ;;
    stop) stop ;;
    restart) stop; start ;;
    purge)
        stop
        if set_exists; then
            owned_set || fail 'Refusing to purge an unowned ipset.'
            # The kernel refuses destruction while any firewall rule still refers to this set.
            ipset destroy "$SET" || fail 'Selective ipset is still referenced; rollback routing first.'
        fi
        rm -f "$SETOWNER" "$CONF"
        say 'Owned selective DNS ipset removed.'
        ;;
esac
