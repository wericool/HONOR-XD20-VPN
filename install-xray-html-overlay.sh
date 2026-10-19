#!/bin/sh
# XD20_XRAY_HTML_V1: new HTML overlay only; existing /etc lowerdir is immutable.
# Installed assets add one native route and menu. They do not replace index.lua,
# main.js, login logic, the stock VPN view, or any native API/security settings.
set -u
umask 077
DATA=/data/xray-test
DEST=/data/patch/html
STAGE=$DATA/html-stage.$$
LOCK=$DATA/html-install.lock
SERVER=192.168.3.3
REMOUNTED=0
OWN_LOCK=0
OWN_STAGE=0
COMMITTED=0

say() { printf '%s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
exists() { [ -e "$1" ] || [ -L "$1" ]; }
size_is() {
    SIZE_PATH=$1
    SIZE_EXPECT=$2
    SIZE_GOT=$(wc -c < "$SIZE_PATH") || return 1
    set -- $SIZE_GOT
    [ "$#" -eq 1 ] && [ "$1" = "$SIZE_EXPECT" ]
}
safe_empty_remove() {
    case "$1" in "$LOCK"|"$STAGE") ;; *) return 1 ;; esac
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
    say 'ERROR: Restore /patch read-only before reboot: mount -o remount,ro /dev/mtdblock23 /patch' >&2
    return 1
}
cleanup() {
    RESULT=$?
    trap - EXIT HUP INT TERM
    restore_ro || RESULT=1
    if [ "$OWN_STAGE" = 1 ]; then
        rm -f "$STAGE/router.js" "$STAGE/store.js" "$STAGE/xray.js"
        safe_empty_remove "$STAGE" 2>/dev/null || :
    fi
    if [ "$OWN_LOCK" = 1 ]; then safe_empty_remove "$LOCK" 2>/dev/null || :; fi
    if [ "$RESULT" -ne 0 ] && [ "$COMMITTED" = 1 ]; then
        say 'The HTML overlay link was committed. Inspect /patch/html before reboot.' >&2
    fi
    exit "$RESULT"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

guard_mounts() {
    PATCH_SEEN=0
    DATA_SEEN=0
    ETC_SEEN=0
    while read -r SOURCE TARGET FSTYPE OPTIONS REST; do
        case "$TARGET" in
            /patch)
                [ "$SOURCE" = /dev/mtdblock23 ] && [ "$FSTYPE" = jffs2 ] || fail 'Unexpected /patch filesystem.'
                case ",$OPTIONS," in *,ro,*) ;; *) fail '/patch must initially be read-only.' ;; esac
                PATCH_SEEN=1
                ;;
            /data)
                [ "$SOURCE" = /dev/mtdblock12 ] && [ "$FSTYPE" = jffs2 ] || fail 'Unexpected /data filesystem.'
                case ",$OPTIONS," in *,rw,*) ;; *) fail '/data must be writable.' ;; esac
                DATA_SEEN=1
                ;;
            /etc)
                [ "$FSTYPE" = overlay ] || fail 'The verified /etc overlay is absent.'
                case ",$OPTIONS," in *,ro,*) ;; *) fail 'The existing /etc overlay is not read-only.' ;; esac
                case ",$OPTIONS," in *,lowerdir=/patch/etc:/etc,*) ;; *) fail 'Unexpected /etc lower directories.' ;; esac
                ETC_SEEN=1
                ;;
            /html|/patch/html|/data/patch/html)
                fail 'An HTML mount already exists. Do not edit a mounted lower directory.'
                ;;
        esac
    done < /proc/mounts
    [ "$PATCH_SEEN" = 1 ] && [ "$DATA_SEEN" = 1 ] && [ "$ETC_SEEN" = 1 ] || fail 'Required verified mounts were not found.'
}
guard_existing() {
    exists "$DEST" && fail 'The HTML data path already exists; nothing will be overwritten.'
    exists /patch/html && fail 'The HTML overlay link already exists.'
    exists /patch/html.disabled && fail 'An inactive HTML overlay already exists; inspect it before proceeding.'
    [ -d /data/patch ] && [ ! -L /data/patch ] || fail 'Unexpected patch data directory.'
    [ -d /html ] && [ ! -L /html ] || fail 'Unexpected stock HTML directory.'
    [ -L /patch/etc ] && [ -L /patch/patch.ver ] || fail 'The verified etc integration links are absent.'
    ETC_LINK=$(ls -l /patch/etc) || fail 'Could not inspect the etc link.'
    VER_LINK=$(ls -l /patch/patch.ver) || fail 'Could not inspect the activation marker link.'
    case "$ETC_LINK" in *" -> /data/patch/etc") ;; *) fail 'The existing etc link has an unexpected target.' ;; esac
    case "$VER_LINK" in *" -> /data/patch/patch.ver") ;; *) fail 'The existing marker link has an unexpected target.' ;; esac
    GOT_VERSION=
    read -r GOT_VERSION < /data/patch/patch.ver || fail 'Could not read the existing version marker.'
    [ "$GOT_VERSION" = WS7100-20-10.0.5.26_main_debug_patch26 ] || fail 'The marker does not identify inspected debug26.'
    for PATCH_ENTRY in /patch/* /patch/.[!.]* /patch/..?*; do
        exists "$PATCH_ENTRY" || continue
        case "$PATCH_ENTRY" in /patch/etc|/patch/patch.ver) ;; *) fail 'An unrelated patch integration exists.' ;; esac
    done
    for STOCK_FILE in /html/router/router.js /html/vuex/store.js /html/html/index.html.lua /html/js/main.js; do
        [ -f "$STOCK_FILE" ] && [ ! -L "$STOCK_FILE" ] || fail 'An inspected stock UI source is absent or is a link.'
    done
    size_is /html/router/router.js 10021 || fail 'The stock router source size changed.'
    size_is /html/vuex/store.js 33462 || fail 'The stock menu source size changed.'
}
check_asset() {
    [ -f "$1" ] && [ ! -L "$1" ] || fail 'A transferred UI asset is absent or is a link.'
    size_is "$1" "$2" || fail 'A transferred UI asset has the wrong byte count.'
    ASSET_FIRST=
    IFS= read -r ASSET_FIRST < "$1" || fail 'A transferred UI asset has no first LF.'
    [ "$ASSET_FIRST" = "$3" ] || fail 'A transferred UI asset has an unexpected ownership marker.'
}

[ "$#" -eq 0 ] || fail 'Usage: sh install-xray-html-overlay.sh'
[ -d "$DATA" ] && [ ! -L "$DATA" ] || fail 'Unexpected Xray data directory.'
[ -f "$DATA/ax3-sync" ] && [ -x "$DATA/ax3-sync" ] && [ ! -L "$DATA/ax3-sync" ] || fail 'The verified static sync helper is absent.'
guard_mounts
guard_existing
mkdir "$LOCK" || fail 'Another HTML installer is running, or its lock remains.'
OWN_LOCK=1
mkdir "$STAGE" || fail 'Could not create the unique UI staging directory.'
OWN_STAGE=1

wget -g -v -l "$STAGE/router.js" -r /xd20-ui-router.js "$SERVER" || fail 'Native route transfer failed.'
wget -g -v -l "$STAGE/store.js" -r /xd20-ui-store.js "$SERVER" || fail 'Native menu transfer failed.'
wget -g -v -l "$STAGE/xray.js" -r /xd20-ui-view.js "$SERVER" || fail 'VPN view transfer failed.'
check_asset "$STAGE/router.js" 10125 '// XD20_XRAY_HTML_V1: additive native route; existing routes retained.'
check_asset "$STAGE/store.js" 32984 '// XD20_XRAY_HTML_V1: additive menu and label; native auth retained.'
check_asset "$STAGE/xray.js" 1644 '// XD20_XRAY_HTML_V1: this child route inherits the native router login guard.'

# The target is new and has never been an overlay lower directory.
guard_mounts
guard_existing
mkdir "$DEST" || fail 'Could not create the new HTML lower directory.'
mkdir "$DEST/router" "$DEST/vuex" "$DEST/views" || fail 'Could not create HTML asset directories.'
mkdir "$DEST/views/xray" || fail 'Could not create the VPN view directory.'
chmod 755 "$DEST" "$DEST/router" "$DEST/vuex" "$DEST/views" "$DEST/views/xray" || fail 'Could not set HTML directory permissions.'
cp "$STAGE/router.js" "$DEST/router/router.js" || fail 'Could not stage the native router asset.'
cp "$STAGE/store.js" "$DEST/vuex/store.js" || fail 'Could not stage the native menu asset.'
cp "$STAGE/xray.js" "$DEST/views/xray/xray.js" || fail 'Could not stage the VPN view asset.'
printf '%s\n' XD20_XRAY_HTML_V1 > "$DEST/.xd20-xray-html-v1" || fail 'Could not record HTML ownership.'
chmod 444 "$DEST/router/router.js" "$DEST/vuex/store.js" "$DEST/views/xray/xray.js" "$DEST/.xd20-xray-html-v1" || fail 'Could not make HTML assets read-only.'
"$DATA/ax3-sync" || fail 'Could not sync the prepared HTML lower directory.'

# /etc and its marker remain unchanged. Adding this link is the final activation.
REMOUNTED=1
mount -o remount,rw /dev/mtdblock23 /patch || fail 'Could not remount /patch writable.'
patch_mode rw || fail '/patch did not become writable.'
exists /patch/html && fail 'The HTML link appeared during staging.'
ln -s "$DEST" /patch/html || fail 'Could not create the HTML overlay link.'
COMMITTED=1
"$DATA/ax3-sync" || fail 'Could not sync the HTML activation link.'
restore_ro || fail 'Could not restore /patch read-only.'
say 'Native VPN route and menu are staged for the next boot. The current UI and /etc lower directory are unchanged.'
say 'After reboot verify /html overlay, normal router login, stock settings, and /html/index.html#/more/xray.'
say 'The native VPN menu opens the separate authenticated panel.'
say 'Rollback only this UI integration: rename the verified /patch/html link to /patch/html.disabled while /patch is rw, sync with ax3-sync, restore ro, then reboot.'
exit 0
