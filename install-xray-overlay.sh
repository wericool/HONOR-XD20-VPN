#!/bin/sh
# Prepare only the minimal /etc overlay for the already verified debug26 router.
# The first reboot must be performed with autostart.enabled ABSENT.
# This script does not alter mounted /etc, the Xray process, or network rules.
set -u
umask 077

DATA=/data/xray-test
STAGE=$DATA/overlay-stage.$$
LOCK=$DATA/overlay-install.lock
SERVER=192.168.3.3
VERSION=WS7100-20-10.0.5.26_main_debug_patch26
HOOK=S99xd20xray
REMOUNTED=0
OWN_LOCK=0
OWN_STAGE=0
COMMITTED=0

say() { printf '%s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
exists() { [ -e "$1" ] || [ -L "$1" ]; }
safe_empty_remove() {
    case "$1" in "$STAGE"|"$LOCK") ;; *) return 1 ;; esac
    [ -d "$1" ] && [ ! -L "$1" ] || return 1
    for EMPTY_ENTRY in "$1"/* "$1"/.[!.]* "$1"/..?*; do
        exists "$EMPTY_ENTRY" && return 1
    done
    rm -r "$1"
}

patch_mode() {
    while read -r M_SOURCE M_TARGET M_FSTYPE M_OPTIONS M_REST; do
        [ "$M_TARGET" = /patch ] || continue
        [ "$M_SOURCE" = /dev/mtdblock23 ] && [ "$M_FSTYPE" = jffs2 ] || return 1
        case ",$M_OPTIONS," in *",$1,"*) return 0 ;; *) return 1 ;; esac
    done < /proc/mounts
    return 1
}

restore_ro() {
    [ "$REMOUNTED" = 1 ] || return 0
    ATTEMPT=0
    while [ "$ATTEMPT" -lt 3 ]; do
        if mount -o remount,ro /dev/mtdblock23 /patch && patch_mode ro; then
            REMOUNTED=0
            return 0
        fi
        ATTEMPT=$((ATTEMPT + 1))
        [ "$ATTEMPT" -ge 3 ] || sleep 1
    done
    printf '%s\n' 'ERROR: /patch could not be restored read-only; run mount -o remount,ro /dev/mtdblock23 /patch before reboot.' >&2
    return 1
}

cleanup() {
    RESULT=$?
    trap - EXIT HUP INT TERM
    restore_ro || RESULT=1
    if [ "$OWN_STAGE" = 1 ]; then
        rm -f "$STAGE/$HOOK" "$STAGE/patch.ver"
        safe_empty_remove "$STAGE" 2>/dev/null || :
    fi
    if [ "$OWN_LOCK" = 1 ]; then safe_empty_remove "$LOCK" 2>/dev/null || :; fi
    if [ "$RESULT" -ne 0 ] && [ "$COMMITTED" = 1 ]; then
        printf '%s\n' 'Overlay marker was committed. Autostart is still disabled. Inspect /patch and /data/patch before reboot.' >&2
    fi
    exit "$RESULT"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

guard_mounts() {
    PATCH_SEEN=0
    DATA_SEEN=0
    while read -r SOURCE TARGET FSTYPE OPTIONS REST; do
        case "$TARGET" in
            /patch)
                [ "$SOURCE" = /dev/mtdblock23 ] || fail 'Unexpected /patch source.'
                [ "$FSTYPE" = jffs2 ] || fail 'Unexpected /patch filesystem.'
                case ",$OPTIONS," in *,ro,*) ;; *) fail '/patch must initially be read-only.' ;; esac
                PATCH_SEEN=1
                ;;
            /data)
                [ "$SOURCE" = /dev/mtdblock12 ] || fail 'Unexpected /data source.'
                [ "$FSTYPE" = jffs2 ] || fail 'Unexpected /data filesystem.'
                case ",$OPTIONS," in *,rw,*) ;; *) fail '/data must be writable.' ;; esac
                DATA_SEEN=1
                ;;
            /etc|/etc/rc.d|/patch/etc)
                fail 'An /etc mount is already active; do not edit its lower directory.'
                ;;
        esac
    done < /proc/mounts
    [ "$PATCH_SEEN" = 1 ] || fail '/patch is not mounted.'
    [ "$DATA_SEEN" = 1 ] || fail '/data is not mounted.'
}

guard_collisions() {
    exists /data/patch && fail '/data/patch already exists; nothing will be overwritten.'
    exists "/etc/rc.d/$HOOK" && fail 'The live /etc hook path already exists.'
    exists "$DATA/autostart.enabled" && fail 'Disable autostart before preparing the first overlay reboot.'
    for ENTRY in /patch/* /patch/.[!.]* /patch/..?*; do
        if exists "$ENTRY"; then fail '/patch contains existing files or links; nothing will be overwritten.'; fi
    done
}

[ "$#" -eq 0 ] || fail 'Usage: sh install-xray-overlay.sh'
[ -d "$DATA" ] && [ ! -L "$DATA" ] || fail 'The verified Xray data directory is missing or is a link.'
[ -d /patch ] && [ ! -L /patch ] || fail 'Unexpected /patch directory.'
[ -f "$DATA/xrayctl.sh" ] && [ ! -L "$DATA/xrayctl.sh" ] || fail 'The Xray controller is not installed.'
[ -f "$DATA/ax3-sync" ] && [ -x "$DATA/ax3-sync" ] && [ ! -L "$DATA/ax3-sync" ] || fail 'The verified static sync helper is missing or is a link.'
sh -n "$DATA/xrayctl.sh" || fail 'The Xray controller does not parse.'
guard_mounts
guard_collisions
mkdir "$LOCK" || fail 'Another overlay installer is running, or its lock remains.'
OWN_LOCK=1
mkdir "$STAGE" || fail 'The unique overlay staging directory could not be created.'
OWN_STAGE=1

wget -g -v -l "$STAGE/$HOOK" -r "/$HOOK" "$SERVER" || fail 'Boot hook transfer failed.'
wget -g -v -l "$STAGE/patch.ver" -r /xd20-patch.ver "$SERVER" || fail 'Version marker transfer failed.'
[ -s "$STAGE/$HOOK" ] || fail 'The boot hook is empty.'
sh -n "$STAGE/$HOOK" || fail 'The boot hook does not parse.'
HOOK_TAG_SEEN=0
while IFS= read -r LINE; do
    case "$LINE" in '# XD20_XRAY_BOOT_HOOK_V1:'*) HOOK_TAG_SEEN=1 ;; esac
done < "$STAGE/$HOOK"
[ "$HOOK_TAG_SEEN" = 1 ] || fail 'Unexpected boot hook.'
read -r GOT_VERSION < "$STAGE/patch.ver" || fail 'Could not read the version marker.'
[ "$GOT_VERSION" = "$VERSION" ] || fail 'The version marker does not exactly match debug26.'
VERSION_LINES=0
while IFS= read -r LINE || [ -n "$LINE" ]; do
    VERSION_LINES=$((VERSION_LINES + 1))
done < "$STAGE/patch.ver"
[ "$VERSION_LINES" -eq 1 ] || fail 'The version marker must contain exactly one line.'

# Recheck after transfer, immediately before creating any persistent overlay data.
guard_mounts
guard_collisions
mkdir /data/patch || fail 'Could not create the new overlay directory.'
mkdir /data/patch/etc || fail 'Could not create the new etc lower directory.'
mkdir /data/patch/etc/rc.d || fail 'Could not create the new rc.d lower directory.'
chmod 755 /data/patch /data/patch/etc /data/patch/etc/rc.d || fail 'Could not set overlay directory permissions.'
cp "$STAGE/$HOOK" "/data/patch/etc/rc.d/$HOOK" || fail 'Could not install the boot hook.'
chmod 555 "/data/patch/etc/rc.d/$HOOK" || fail 'Could not make the boot hook read-only and executable.'
cp "$STAGE/patch.ver" /data/patch/patch.ver || fail 'Could not install the version marker data.'
chmod 444 /data/patch/patch.ver || fail 'Could not make the version marker read-only.'
"$DATA/ax3-sync" || fail 'Could not sync the staged overlay data.'

# Restore read-only even if the remount command partially changes state then fails.
REMOUNTED=1
mount -o remount,rw /dev/mtdblock23 /patch || fail 'Could not remount /patch writable.'
patch_mode rw || fail '/patch still does not report writable after remount.'
ln -s /data/patch/etc /patch/etc || fail 'Could not create the etc link.'
# Activation marker is deliberately the final persistent mutation.
ln -s /data/patch/patch.ver /patch/patch.ver || fail 'Could not create the activation marker link.'
COMMITTED=1
"$DATA/ax3-sync" || fail 'Could not sync the overlay activation marker.'
restore_ro || fail 'Could not restore /patch read-only.'

say 'Minimal /etc overlay prepared; the live /etc mount has not changed.'
say 'Autostart remains disabled. Reboot once and verify /etc overlay and /etc/rc.d/S99xd20xray before enabling it.'
say 'Rollback before reboot: keep autostart.enabled absent, remount /patch rw, rename /patch/patch.ver to /patch/patch.ver.disabled, sync, remount /patch ro.'
say 'Rollback after an overlay reboot: disable Xray autostart first, rename only the /patch activation marker while rw, sync, remount ro, then reboot. Do not edit the mounted overlay lower directory.'
exit 0
