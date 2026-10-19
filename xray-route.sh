#!/bin/sh
# HONOR XD20: primary-LAN routing into an already-running Xray TUN.
# This script never changes the main routing table, WAN NAT, or guest br1.
# DNS port 53 is DNATed to a public resolver and follows the same TUN policy.
# Private/local destinations remain reachable through the stock main table.
# IPv6 forwarding from br0 is blocked because this configuration is IPv4-only.
# Existing hardware-offloaded connections require separate runtime verification.
# Selective mode requires DNS helper5353 and native ipset xd20_vpn. It preserves
# bit0x100 in conntrack while leaving firmware-owned markbits intact. Encrypted
# DNS that bypasses this helper cannot populate the domain-derived destination set.
# "inverse" is selective routing turned around: everything goes through the TUN
# except destinations in the owned ipset xd20_bypass, which the DNS helper fills
# from the user's exception list. It reuses every selective chain and rule.
# Usage: apply pc|full|selective|inverse [trial|permanent], commit, check [mode], status, rollback.
# A trial has an independent 120-second rollback watchdog. Permanent is explicit.

IP=/bin/ip
IPT=iptables
IP6T=ip6tables
SELF=/data/xray-test/xray-route.sh
STATE=/tmp/xd20-xray-route
LOCK=/tmp/xd20-xray-route.lock
TABLE=110
PREF=1100
FWD=XD20_XRAY_FWD
DNS=XD20_XRAY_DNS
V6=XD20_XRAY_V6
MANGLE=XD20_XRAY_MARK
INPUT=XD20_XRAY_IN
SET=xd20_vpn
SETOWNER=/tmp/xd20-vpn-set.owner
SETMARK=XD20_VPN_IPSET_V1
MARK=0x100/0x100
PRIVATE='10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.0/8 169.254.0.0/16 224.0.0.0/4 255.255.255.255/32'
LOCKED=0
NEW_STATE=0
MODE=
NETWORK=
TOKEN=
KIND=
umask 077

say() { printf '%s\n' "$*"; }
# Selective and inverse share chains, marks, DNS interception and the ipset flow.
is_set_mode() { [ "$MODE" = selective ] || [ "$MODE" = inverse ]; }
set_for_mode() {
    if [ "$1" = inverse ]; then
        SET=xd20_bypass
        SETOWNER=/tmp/xd20-bypass-set.owner
        SETMARK=XD20_BYPASS_IPSET_V1
    else
        SET=xd20_vpn
        SETOWNER=/tmp/xd20-vpn-set.owner
        SETMARK=XD20_VPN_IPSET_V1
    fi
}
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
seconds() { read -r UP REST < /proc/uptime || return 1; printf '%s\n' "${UP%%.*}"; }
safe_remove_empty() {
    # Stock firmware has rm but no rmdir. Only these two absolute owned paths
    # are permitted, and recursive rm is reached only after proving emptiness.
    case "$1" in "$LOCK"|"$STATE") ;; *) return 1 ;; esac
    [ -d "$1" ] && [ ! -L "$1" ] || return 1
    for ENTRY in "$1"/* "$1"/.[!.]* "$1"/..?*; do
        if [ -e "$ENTRY" ] || [ -L "$ENTRY" ]; then return 1; fi
    done
    rm -r "$1"
}
start_ticks() {
    [ -r "/proc/$1/stat" ] || return 1
    read -r STAT < "/proc/$1/stat" || return 1
    STAT=${STAT##*) }
    set -- $STAT
    [ "$#" -ge 20 ] || return 1
    N=1
    while [ "$N" -lt 20 ]; do shift; N=$((N + 1)); done
    printf '%s\n' "$1"
}
lock_acquire() {
    if ! mkdir "$LOCK" 2>/dev/null; then
        [ -d "$LOCK" ] && [ ! -L "$LOCK" ] && [ -r "$LOCK/pid" ] || return 1
        read -r OLD_PID OLD_START < "$LOCK/pid" || return 1
        case "$OLD_PID" in ''|*[!0-9]*) return 1 ;; esac
        case "$OLD_START" in ''|*[!0-9]*) return 1 ;; esac
        ACTUAL=$(start_ticks "$OLD_PID" 2>/dev/null)
        [ "$ACTUAL" != "$OLD_START" ] || return 1
        # Remove only a stale lock with a recorded process identity.
        rm -f "$LOCK/pid" "$LOCK/routes" "$LOCK/chain" "$LOCK/rules" || return 1
        safe_remove_empty "$LOCK" 2>/dev/null || return 1
        mkdir "$LOCK" 2>/dev/null || return 1
    fi
    LOCKED=1
    ME_START=$(start_ticks "$$") || return 1
    printf '%s %s\n' "$$" "$ME_START" > "$LOCK/pid" || return 1
}
unlock() {
    [ "$LOCKED" = 1 ] || return 0
    # The independent watchdog also creates these scratch files during rollback.
    # Keep every unlock path self-contained, including its EXIT trap.
    rm -f "$LOCK/routes" "$LOCK/chain" "$LOCK/rules" "$LOCK/pid"
    safe_remove_empty "$LOCK" 2>/dev/null
    LOCKED=0
}
load_state() {
    [ -d "$STATE" ] && [ ! -L "$STATE" ] && [ -r "$STATE/owner" ] || return 1
    read -r OWNER < "$STATE/owner" || return 1
    [ "$OWNER" = XD20-XRAY-ROUTE-1 ] || return 1
    read -r TOKEN MODE NETWORK KIND < "$STATE/state" || return 1
    case "$TOKEN" in ''|*[!0-9-]*) return 1 ;; esac
    case "$MODE:$NETWORK" in pc:192.168.3.3/32|full:192.168.3.0/24|selective:192.168.3.0/24|inverse:192.168.3.0/24) ;; *) return 1 ;; esac
    case "$KIND" in trial|permanent) ;; *) return 1 ;; esac
    set_for_mode "$MODE"
}
pref_present() {
    "$IP" rule show 2>/dev/null > "$LOCK/rules" || return 1
    FOUND=1
    while read -r FIRST REST; do [ "$FIRST" = "$PREF:" ] && FOUND=0; done < "$LOCK/rules"
    rm -f "$LOCK/rules"
    return "$FOUND"
}
# A repair may restore missing recorded rules, but never accepts unfamiliar ones.
subset() {
    CURRENT=$1
    EXPECTED=$2
    [ -r "$EXPECTED" ] || return 1
    while IFS= read -r LINE; do
        MATCH=0
        while IFS= read -r WANT; do [ "$LINE" = "$WANT" ] && MATCH=1; done < "$EXPECTED"
        [ "$MATCH" = 1 ] || return 1
    done < "$CURRENT"
}
owned_resources_only() {
    "$IP" route show table "$TABLE" > "$LOCK/routes" 2>/dev/null || return 1
    subset "$LOCK/routes" "$STATE/routes" || return 1
    for CHAIN in $(chains4); do
        if "$IPT" -t "$(chain_table "$CHAIN")" -S "$CHAIN" > "$LOCK/chain" 2>/dev/null; then
            subset "$LOCK/chain" "$STATE/$CHAIN" || return 1
        fi
    done
    if "$IP6T" -S "$V6" > "$LOCK/chain" 2>/dev/null; then
        subset "$LOCK/chain" "$STATE/$V6" || return 1
    fi
    "$IP" rule show > "$LOCK/rules" 2>/dev/null || return 1
    while IFS= read -r LINE; do
        case "$LINE" in "$PREF:"*)
            MATCH=0
            while IFS= read -r WANT; do [ "$LINE" = "$WANT" ] && MATCH=1; done < "$STATE/rule"
            [ "$MATCH" = 1 ] || return 1
        ;; esac
    done < "$LOCK/rules"
    rm -f "$LOCK/routes" "$LOCK/chain" "$LOCK/rules"
}
chains4() {
    printf '%s %s\n' "$FWD" "$DNS"
    is_set_mode && printf '%s %s\n' "$MANGLE" "$INPUT"
    return 0
}
chain_table() {
    case "$1" in "$DNS") printf 'nat\n' ;; "$MANGLE") printf 'mangle\n' ;; *) printf 'filter\n' ;; esac
}
policy_rule() {
    if is_set_mode; then
        "$IP" rule "$1" priority "$PREF" fwmark "$MARK" table "$TABLE"
    else
        "$IP" rule "$1" priority "$PREF" from "$NETWORK" iif br0 table "$TABLE"
    fi
}
check_iptables_check() {
    "$1" -C FORWARD -j RETURN >/dev/null 2>&1
    CHECK_EXIT=$?
    case "$CHECK_EXIT" in 0|1) return 0 ;; *) return 1 ;; esac
}
owned_set_present() {
    [ -r "$SETOWNER" ] || return 1
    read -r SET_OWNER < "$SETOWNER" || return 1
    [ "$SET_OWNER" = "$SETMARK" ] || return 1
    ipset list "$SET" >/dev/null 2>&1
}
remove_rule() {
    TOOL=$1; TAB=$2; CHAIN=$3; shift 3
    COUNT=0
    while "$TOOL" -t "$TAB" -C "$CHAIN" "$@" 2>/dev/null; do
        [ "$COUNT" -lt 16 ] || return 1
        "$TOOL" -t "$TAB" -D "$CHAIN" "$@" || return 1
        COUNT=$((COUNT + 1))
    done
}
forward_rules() {
    ACTION=$1
    "$IPT" -t filter "$ACTION" "$FWD" -i xray0 -o br0 -d "$NETWORK" -j ACCEPT || return 1
    for CIDR in $PRIVATE; do
        "$IPT" -t filter "$ACTION" "$FWD" -i br0 -s "$NETWORK" -d "$CIDR" -j RETURN || return 1
    done
    "$IPT" -t filter "$ACTION" "$FWD" -i br0 -s "$NETWORK" -o xray0 -j ACCEPT || return 1
    if is_set_mode; then
        "$IPT" -t filter "$ACTION" "$FWD" -i br0 -s "$NETWORK" -m mark --mark "$MARK" -j DROP || return 1
    else
        "$IPT" -t filter "$ACTION" "$FWD" -i br0 -s "$NETWORK" -j DROP || return 1
    fi
    "$IPT" -t filter "$ACTION" "$FWD" -j RETURN || return 1
}
remove_forward_rules() {
    remove_rule "$IPT" filter "$FWD" -i xray0 -o br0 -d "$NETWORK" -j ACCEPT || return 1
    for CIDR in $PRIVATE; do
        remove_rule "$IPT" filter "$FWD" -i br0 -s "$NETWORK" -d "$CIDR" -j RETURN || return 1
    done
    remove_rule "$IPT" filter "$FWD" -i br0 -s "$NETWORK" -o xray0 -j ACCEPT || return 1
    if is_set_mode; then
        remove_rule "$IPT" filter "$FWD" -i br0 -s "$NETWORK" -m mark --mark "$MARK" -j DROP || return 1
    else
        remove_rule "$IPT" filter "$FWD" -i br0 -s "$NETWORK" -j DROP || return 1
    fi
    remove_rule "$IPT" filter "$FWD" -j RETURN || return 1
}
mangle_rules() {
    ACTION=$1
    "$IPT" -t mangle "$ACTION" "$MANGLE" -i br0 -s "$NETWORK" -j CONNMARK --restore-mark --nfmask 0x100 --ctmask 0x100 || return 1
    if [ "$MODE" = inverse ]; then
        "$IPT" -t mangle "$ACTION" "$MANGLE" -i br0 -s "$NETWORK" -m set ! --match-set "$SET" dst -j MARK --set-xmark "$MARK" || return 1
    else
        "$IPT" -t mangle "$ACTION" "$MANGLE" -i br0 -s "$NETWORK" -m set --match-set "$SET" dst -j MARK --set-xmark "$MARK" || return 1
    fi
    "$IPT" -t mangle "$ACTION" "$MANGLE" -i br0 -s "$NETWORK" -m mark --mark "$MARK" -j CONNMARK --save-mark --nfmask 0x100 --ctmask 0x100 || return 1
    "$IPT" -t mangle "$ACTION" "$MANGLE" -j RETURN || return 1
}
remove_mangle_rules() {
    remove_rule "$IPT" mangle "$MANGLE" -i br0 -s "$NETWORK" -j CONNMARK --restore-mark --nfmask 0x100 --ctmask 0x100 || return 1
    if [ "$MODE" = inverse ]; then
        remove_rule "$IPT" mangle "$MANGLE" -i br0 -s "$NETWORK" -m set ! --match-set "$SET" dst -j MARK --set-xmark "$MARK" || return 1
    else
        remove_rule "$IPT" mangle "$MANGLE" -i br0 -s "$NETWORK" -m set --match-set "$SET" dst -j MARK --set-xmark "$MARK" || return 1
    fi
    remove_rule "$IPT" mangle "$MANGLE" -i br0 -s "$NETWORK" -m mark --mark "$MARK" -j CONNMARK --save-mark --nfmask 0x100 --ctmask 0x100 || return 1
    remove_rule "$IPT" mangle "$MANGLE" -j RETURN || return 1
}
input_rules() {
    ACTION=$1
    for PROTO in udp tcp; do
        "$IPT" -t filter "$ACTION" "$INPUT" -i br0 -s "$NETWORK" -d 192.168.3.1 -p "$PROTO" --dport 5353 -j ACCEPT || return 1
        "$IPT" -t filter "$ACTION" "$INPUT" -p "$PROTO" --dport 5353 -j DROP || return 1
    done
    "$IPT" -t filter "$ACTION" "$INPUT" -j RETURN || return 1
}
remove_input_rules() {
    for PROTO in udp tcp; do
        remove_rule "$IPT" filter "$INPUT" -i br0 -s "$NETWORK" -d 192.168.3.1 -p "$PROTO" --dport 5353 -j ACCEPT || return 1
        remove_rule "$IPT" filter "$INPUT" -p "$PROTO" --dport 5353 -j DROP || return 1
    done
    remove_rule "$IPT" filter "$INPUT" -j RETURN || return 1
}
remove_dns_rules() {
    if is_set_mode; then
        for PROTO in udp tcp; do
            remove_rule "$IPT" nat "$DNS" -p "$PROTO" -j DNAT --to-destination 192.168.3.1:5353 || return 1
        done
    else
        remove_rule "$IPT" nat "$DNS" -j DNAT --to-destination 1.1.1.1 || return 1
    fi
}
dns_rules() {
    if is_set_mode; then
        for PROTO in udp tcp; do
            "$IPT" -t nat -A "$DNS" -p "$PROTO" -j DNAT --to-destination 192.168.3.1:5353 || return 1
        done
    else
        "$IPT" -t nat -A "$DNS" -j DNAT --to-destination 1.1.1.1 || return 1
    fi
}
ensure_routes() {
    # Install failclosed routing before changing firewall chains during repair.
    "$IP" route replace unreachable default metric 3000 table "$TABLE" || return 1
    for CIDR in $PRIVATE; do "$IP" route replace throw "$CIDR" metric 10 table "$TABLE" || return 1; done
    if ! pref_present; then
        policy_rule add || return 1
    fi
    "$IP" route replace default dev xray0 metric 10 table "$TABLE" || return 1
}
ensure_firewall() {
    "$IPT" -n -L "$FWD" >/dev/null 2>&1 || "$IPT" -N "$FWD" || return 1
    "$IPT" -t nat -n -L "$DNS" >/dev/null 2>&1 || "$IPT" -t nat -N "$DNS" || return 1
    "$IP6T" -n -L "$V6" >/dev/null 2>&1 || "$IP6T" -N "$V6" || return 1
    if is_set_mode; then
        "$IPT" -t mangle -n -L "$MANGLE" >/dev/null 2>&1 || "$IPT" -t mangle -N "$MANGLE" || return 1
        "$IPT" -n -L "$INPUT" >/dev/null 2>&1 || "$IPT" -N "$INPUT" || return 1
        remove_mangle_rules || return 1
        mangle_rules -A || return 1
        remove_input_rules || return 1
        input_rules -A || return 1
    fi
    # All rules removed here are exact rules installed by this script.
    remove_forward_rules || return 1
    forward_rules -A || return 1
    remove_dns_rules || return 1
    dns_rules || return 1
    remove_rule "$IP6T" filter "$V6" -i br0 -j DROP || return 1
    remove_rule "$IP6T" filter "$V6" -j RETURN || return 1
    "$IP6T" -A "$V6" -i br0 -j DROP || return 1
    "$IP6T" -A "$V6" -j RETURN || return 1
    remove_rule "$IPT" filter FORWARD -j "$FWD" || return 1
    "$IPT" -I FORWARD 1 -j "$FWD" || return 1
    remove_rule "$IP6T" filter FORWARD -j "$V6" || return 1
    "$IP6T" -I FORWARD 1 -j "$V6" || return 1
    if is_set_mode; then
        remove_rule "$IPT" mangle PREROUTING -j "$MANGLE" || return 1
        "$IPT" -t mangle -I PREROUTING 1 -j "$MANGLE" || return 1
        remove_rule "$IPT" filter INPUT -j "$INPUT" || return 1
        "$IPT" -I INPUT 1 -j "$INPUT" || return 1
    fi
    for PROTO in udp tcp; do
        remove_rule "$IPT" nat PREROUTING -i br0 -s "$NETWORK" -p "$PROTO" --dport 53 -j "$DNS" || return 1
        "$IPT" -t nat -I PREROUTING 1 -i br0 -s "$NETWORK" -p "$PROTO" --dport 53 -j "$DNS" || return 1
    done
}
snapshot() {
    "$IP" route show table "$TABLE" > "$STATE/routes" 2>/dev/null || return 1
    "$IP" rule show > "$LOCK/rules" || return 1
    : > "$STATE/rule" || return 1
    while IFS= read -r LINE; do case "$LINE" in "$PREF:"*) printf '%s\n' "$LINE" >> "$STATE/rule" ;; esac; done < "$LOCK/rules"
    rm -f "$LOCK/rules"
    [ -s "$STATE/rule" ] || return 1
    for CHAIN in $(chains4); do
        "$IPT" -t "$(chain_table "$CHAIN")" -S "$CHAIN" > "$STATE/$CHAIN" || return 1
    done
    "$IP6T" -S "$V6" > "$STATE/$V6" || return 1
    printf 'ready\n' > "$STATE/ready"
}
rollback_unlocked() {
    load_state || return 1
    RESULT=0
    for PROTO in udp tcp; do
        remove_rule "$IPT" nat PREROUTING -i br0 -s "$NETWORK" -p "$PROTO" --dport 53 -j "$DNS" || RESULT=1
    done
    remove_rule "$IPT" filter FORWARD -j "$FWD" || RESULT=1
    remove_rule "$IP6T" filter FORWARD -j "$V6" || RESULT=1
    if is_set_mode; then
        remove_rule "$IPT" mangle PREROUTING -j "$MANGLE" || RESULT=1
        remove_rule "$IPT" filter INPUT -j "$INPUT" || RESULT=1
        remove_mangle_rules || RESULT=1
        remove_input_rules || RESULT=1
    fi
    remove_forward_rules || RESULT=1
    remove_dns_rules || RESULT=1
    remove_rule "$IP6T" filter "$V6" -i br0 -j DROP || RESULT=1
    remove_rule "$IP6T" filter "$V6" -j RETURN || RESULT=1
    for CHAIN in $(chains4); do
        TAB=$(chain_table "$CHAIN")
        if "$IPT" -t "$TAB" -n -L "$CHAIN" >/dev/null 2>&1; then "$IPT" -t "$TAB" -X "$CHAIN" || RESULT=1; fi
    done
    if "$IP6T" -n -L "$V6" >/dev/null 2>&1; then "$IP6T" -X "$V6" || RESULT=1; fi
    # Exact RPDB and route deletion: never flush a shared table or parent chain.
    DEL_COUNT=0
    while policy_rule del 2>/dev/null; do
        DEL_COUNT=$((DEL_COUNT + 1))
        [ "$DEL_COUNT" -lt 16 ] || { RESULT=1; break; }
    done
    "$IP" route del default dev xray0 metric 10 table "$TABLE" 2>/dev/null
    "$IP" route del unreachable default metric 3000 table "$TABLE" 2>/dev/null
    for CIDR in $PRIVATE; do "$IP" route del throw "$CIDR" metric 10 table "$TABLE" 2>/dev/null; done
    # The table was initially claimed only when empty. Preserve ownership state
    # if any route remains, rather than claiming a successful rollback.
    if "$IP" route show table "$TABLE" > "$LOCK/routes" 2>/dev/null; then
        [ ! -s "$LOCK/routes" ] || RESULT=1
    else
        RESULT=1
    fi
    pref_present && RESULT=1
    if [ "$RESULT" = 0 ]; then
        rm -f "$STATE/owner" "$STATE/state" "$STATE/ready" "$STATE/committed" "$STATE/watchdog" "$STATE/routes" "$STATE/rule" "$STATE/$FWD" "$STATE/$DNS" "$STATE/$V6" "$STATE/$MANGLE" "$STATE/$INPUT"
        safe_remove_empty "$STATE" 2>/dev/null || RESULT=1
    fi
    return "$RESULT"
}
cleanup() {
    EXIT_CODE=$?
    trap - 0
    trap '' 1 2 15
    if [ "$NEW_STATE" = 1 ] && [ "$EXIT_CODE" != 0 ]; then
        rollback_unlocked || say 'WARNING: partial rollback retained ownership state for inspection.'
    fi
    rm -f "$LOCK/routes" "$LOCK/chain" "$LOCK/rules"
    unlock
    exit "$EXIT_CODE"
}
committed() {
    [ -r "$STATE/committed" ] || return 1
    read -r COMMITTED < "$STATE/committed" || return 1
    [ "$COMMITTED" = "$TOKEN" ]
}
check_ready() {
    load_state && [ -r "$STATE/ready" ] || return 1
    [ -d /sys/class/net/xray0 ] || return 1
    "$IP" route show table "$TABLE" > "$LOCK/routes" 2>/dev/null || return 1
    ROUTE_LINES=0
    while IFS= read -r LINE; do ROUTE_LINES=$((ROUTE_LINES + 1)); done < "$LOCK/routes"
    [ "$ROUTE_LINES" = 9 ] || return 1
    subset "$LOCK/routes" "$STATE/routes" || return 1
    pref_present || return 1
    "$IPT" -C FORWARD -j "$FWD" || return 1
    "$IP6T" -C FORWARD -j "$V6" || return 1
    for PROTO in udp tcp; do "$IPT" -t nat -C PREROUTING -i br0 -s "$NETWORK" -p "$PROTO" --dport 53 -j "$DNS" || return 1; done
    if is_set_mode; then
        "$IPT" -t mangle -C PREROUTING -j "$MANGLE" || return 1
        "$IPT" -C INPUT -j "$INPUT" || return 1
        owned_set_present || return 1
    fi
    for CHAIN in $(chains4); do
        "$IPT" -t "$(chain_table "$CHAIN")" -S "$CHAIN" > "$LOCK/chain" || return 1
        subset "$LOCK/chain" "$STATE/$CHAIN" && subset "$STATE/$CHAIN" "$LOCK/chain" || return 1
    done
    "$IP6T" -S "$V6" > "$LOCK/chain" || return 1
    subset "$LOCK/chain" "$STATE/$V6" && subset "$STATE/$V6" "$LOCK/chain" || return 1
    owned_resources_only || return 1
}

ACTION=${1:-status}
if [ "$ACTION" = watchdog ]; then
    EXPECT_TOKEN=$2
    START=$(seconds) || exit 1
    # This child is detached from the Telnet foreground and does not use kill.
    trap '' 1
    while :; do
        load_state || exit 0
        [ "$TOKEN" = "$EXPECT_TOKEN" ] || exit 0
        committed && exit 0
        NOW=$(seconds) || exit 1
        [ $((NOW - START)) -lt 120 ] || break
        sleep 1
    done
    ATTEMPTS=0
    while ! lock_acquire; do
        ATTEMPTS=$((ATTEMPTS + 1)); [ "$ATTEMPTS" -lt 30 ] || exit 1; sleep 1
    done
    trap unlock 0
    load_state || exit 0
    [ "$TOKEN" = "$EXPECT_TOKEN" ] || exit 0
    committed && exit 0
    rollback_unlocked || exit 1
    exit 0
fi

lock_acquire || fail 'Routing is locked by another operation; retry shortly.'
trap cleanup 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15
case "$ACTION" in
apply)
    WANT_MODE=${2:-}
    WANT_KIND=${3:-trial}
    case "$WANT_MODE" in pc) WANT_NETWORK=192.168.3.3/32 ;; full|selective|inverse) WANT_NETWORK=192.168.3.0/24 ;; *) fail 'Use apply pc|full|selective|inverse [trial|permanent].' ;; esac
    set_for_mode "$WANT_MODE"
    case "$WANT_KIND" in trial|permanent) ;; *) fail 'Use trial or permanent.' ;; esac
    [ -d /sys/class/net/xray0 ] || fail 'Start Xray and verify xray0 before applying routes.'
    check_iptables_check "$IPT" || fail 'iptables -C is required for exact owned-rule checks.'
    check_iptables_check "$IP6T" || fail 'ip6tables -C is required for IPv6 protection checks.'
    if [ "$WANT_MODE" = selective ] || [ "$WANT_MODE" = inverse ]; then
        owned_set_present || fail "Start the DNS helper and create its owned native ipset $SET before $WANT_MODE routing."
    fi
    if [ -e "$STATE" ]; then
        load_state || fail 'Existing routing state is unrecognized; refusing changes.'
        [ "$MODE" = "$WANT_MODE" ] || fail 'Rollback the current mode before switching routing mode.'
        [ -r "$STATE/ready" ] || fail 'Incomplete owned state requires explicit rollback.'
        owned_resources_only || fail 'An owned table, priority or chain contains an unfamiliar rule; refusing repair.'
    else
        "$IPT" -C FORWARD -j "$FWD" >/dev/null 2>&1 && fail 'Forward jump collision.'
        MODE=$WANT_MODE
        for CHAIN in $(chains4); do "$IPT" -t "$(chain_table "$CHAIN")" -n -L "$CHAIN" >/dev/null 2>&1 && fail 'IPv4 chain name collision.'; done
        "$IP6T" -n -L "$V6" >/dev/null 2>&1 && fail 'IPv6 chain name collision.'
        "$IP6T" -S FORWARD >/dev/null 2>&1 || fail 'Cannot protect IPv6 forwarding.'
        pref_present && fail 'RPDB priority1100 is already used.'
        "$IP" route show table "$TABLE" > "$LOCK/routes" 2>/dev/null || fail 'Cannot inspect routing table110.'
        [ ! -s "$LOCK/routes" ] || fail 'Routing table110 is already used.'
        rm -f "$LOCK/routes"
        mkdir "$STATE" || fail 'Cannot claim a fresh routing state directory.'
        TOKEN="$$-$(seconds)"
        MODE=$WANT_MODE; NETWORK=$WANT_NETWORK; KIND=$WANT_KIND
        printf 'XD20-XRAY-ROUTE-1\n' > "$STATE/owner" || fail 'Cannot write ownership marker.'
        printf '%s %s %s %s\n' "$TOKEN" "$MODE" "$NETWORK" "$KIND" > "$STATE/state" || fail 'Cannot write ownership state.'
        NEW_STATE=1
    fi
    ensure_routes || fail 'Cannot apply the failclosed RPDB/TUN routes.'
    ensure_firewall || fail 'Cannot apply DNS, forwarding or IPv6 protection.'
    snapshot || fail 'Cannot record exact owned routing rules.'
    if [ "$WANT_KIND" = permanent ]; then
        printf '%s\n' "$TOKEN" > "$STATE/committed" || fail 'Cannot commit routing.'
        KIND=permanent
        printf '%s %s %s %s\n' "$TOKEN" "$MODE" "$NETWORK" "$KIND" > "$STATE/state" || fail 'Cannot update committed state.'
    elif [ "$NEW_STATE" = 1 ]; then
        [ -r "$SELF" ] || fail 'Install this script at /data/xray-test/xray-route.sh before a trial.'
        ( trap '' 1; sh "$SELF" watchdog "$TOKEN" </dev/null >/tmp/xd20-xray-route-watchdog.log 2>&1 ) &
        WD=$!
        WD_START=$(start_ticks "$WD") || fail 'Cannot identify the rollback watchdog.'
        printf '%s %s %s\n' "$WD" "$WD_START" "$TOKEN" > "$STATE/watchdog" || fail 'Cannot record rollback watchdog.'
    fi
    check_ready || fail 'Routing verification failed.'
    NEW_STATE=0
    say "ROUTING=ready MODE=$MODE NETWORK=$NETWORK KIND=$KIND"
    [ "$KIND" = trial ] && say 'Rollback watchdog: 120 seconds. Run commit after the external-IP/DNS test.'
    ;;
commit)
    load_state || fail 'No recognized routing state to commit.'
    check_ready || fail 'Routes are incomplete or Xray TUN is absent; not committing.'
    printf '%s\n' "$TOKEN" > "$STATE/committed" || fail 'Cannot cancel trial rollback.'
    KIND=permanent
    printf '%s %s %s %s\n' "$TOKEN" "$MODE" "$NETWORK" "$KIND" > "$STATE/state" || fail 'Cannot record commitment.'
    say "ROUTING=committed MODE=$MODE"
    ;;
check|status)
    if ! load_state; then say 'ROUTING=absent'; exit 1; fi
    EXPECT_MODE=${2:-$MODE}
    [ "$EXPECT_MODE" = "$MODE" ] || fail 'The installed routing mode differs from the requested mode.'
    if check_ready; then
        say "ROUTING=ready MODE=$MODE NETWORK=$NETWORK KIND=$KIND"
    else
        say "ROUTING=incomplete MODE=$MODE NETWORK=$NETWORK KIND=$KIND"
        exit 1
    fi
    ;;
rollback)
    if [ ! -e "$STATE" ]; then say 'ROUTING=absent'; exit 0; fi
    load_state || fail 'Unrecognized state; refusing to remove routing rules.'
    rollback_unlocked || fail 'Some owned rules could not be removed; ownership state retained.'
    say 'ROUTING=rolled_back'
    ;;
*) fail 'Use apply pc|full|selective|inverse [trial|permanent], commit, check [mode], status or rollback.' ;;
esac
exit 0
