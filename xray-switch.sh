#!/bin/sh
# One-core transaction worker for the HONOR XD20. No submitted text is shell code.
DATA=/data/xray-test
STATE=/data/xray-manager/switch
MANAGER=$DATA/ax3-manager
CTL=$DATA/xrayctl.sh
MARKER=/tmp/xd20-xray.switching
JOB=$1
RECOVER=${2:-normal}
CHANGED=0
DONE=0
OWN_MARKER=0
umask 077
export GOMAXPROCS=1 GOMEMLIMIT=6MiB
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
status() { "$MANAGER" job-status "$JOB" "$1" "$2"; }
# Routing mode (selective|inverse) is a single word in $DATA/mode.
write_mode() {
    case "$1" in selective|inverse) ;; *) return 1 ;; esac
    [ ! -L "$DATA/mode" ] && [ ! -L "$DATA/mode.next" ] || return 1
    printf '%s\n' "$1" > "$DATA/mode.next" || return 1
    chmod 600 "$DATA/mode.next" || return 1
    mv -f "$DATA/mode.next" "$DATA/mode" || return 1
    "$DATA/ax3-sync" || return 1
}
restore() {
    if [ "$KIND" = toggle ]; then
        PREVIOUS=$("$MANAGER" toggle-previous "$JOB") || return 1
        case "$PREVIOUS" in enable|disable) ;; *) return 1 ;; esac
        status starting 'Восстанавливается прежнее состояние VPN.' || return 1
        RESTORE_MODE=$("$MANAGER" toggle-mode "$JOB" 2>/dev/null)
        if [ -n "$RESTORE_MODE" ]; then
            # A failed mode change may leave partial routing of the new mode.
            sh "$CTL" disable-vpn >/dev/null 2>&1
            case "$MODE" in selective|inverse) write_mode "$MODE" || return 1 ;; esac
        fi
        sh "$CTL" "$PREVIOUS-vpn" || return 1
        "$MANAGER" complete-toggle "$JOB" rollback || return 1
        CHANGED=0
        return 0
    fi
    [ -f "$STATE/backup.json" ] && [ ! -L "$STATE/backup.json" ] && [ -s "$STATE/backup.json" ] || return 1
    sh "$CTL" stop || return 1
    [ ! -L "$DATA/xray.restore.json" ] && [ ! -L "$DATA/xray.json" ] || return 1
    cp -f "$STATE/backup.json" "$DATA/xray.restore.json" || return 1
    chmod 600 "$DATA/xray.restore.json" || return 1
    mv -f "$DATA/xray.restore.json" "$DATA/xray.json" || return 1
    "$DATA/ax3-sync" || return 1
    # The Go status helper exits before Xray's memory check and decompression.
    status starting 'Восстанавливается прежний сервер.' || return 1
    sh "$CTL" "$MODE" permanent || return 1
    "$MANAGER" rollback-switch "$JOB" 'Новый сервер не прошёл проверку. Прежняя настройка восстановлена.' || return 1
    CHANGED=0
    return 0
}
finish() {
    RESULT=$?
    trap - 0
    trap '' 1 2 15
    if [ "$DONE" != 1 ]; then
        if [ "$CHANGED" = 1 ]; then
            if ! restore; then
                # Keep persistent pending/backup for watchdog or boot recovery.
                status failed 'Переключение прервано. Сохранённая настройка будет восстановлена при повторном запуске.'
            fi
        elif [ "$KIND" = toggle ]; then
            "$MANAGER" complete-toggle "$JOB" rollback
        else
            "$MANAGER" rollback-switch "$JOB" 'Переключение отменено; прежняя настройка сохранена.'
        fi
    fi
    if [ "$OWN_MARKER" = 1 ] && [ -f "$MARKER" ] && [ ! -L "$MARKER" ]; then
        MP= MS= MJ= EXTRA=
        read -r MP MS MJ EXTRA < "$MARKER"
        if [ "$MP" = "$$" ] && [ "$MS" = "$SELF_STAMP" ] && [ "$MJ" = "$JOB" ] && [ -z "$EXTRA" ]; then rm -f "$MARKER"; fi
    fi
    exit "$RESULT"
}
case "$JOB" in ''|*[!0-9a-f]*) exit 1 ;; esac
[ "${#JOB}" = 20 ] || exit 1
[ -x "$MANAGER" ] && [ -f "$CTL" ] && [ -x "$DATA/ax3-sync" ] || exit 1
[ -f "$DATA/xray-switch-watch.sh" ] && [ ! -L "$DATA/xray-switch-watch.sh" ] || exit 1
sh -n "$DATA/xray-switch-watch.sh" || exit 1
[ -d "$STATE" ] && [ ! -L "$STATE" ] || exit 1
for FILE in pending.json; do
    [ -f "$STATE/$FILE" ] && [ ! -L "$STATE/$FILE" ] && [ -s "$STATE/$FILE" ] || exit 1
done
MODE=$("$MANAGER" switch-mode "$JOB") || exit 1
case "$MODE" in selective|full|inverse) ;; *) exit 1 ;; esac
KIND=$("$MANAGER" job-kind "$JOB") || exit 1
case "$KIND" in
    switch)
        for FILE in candidate.json backup.json; do
            [ -f "$STATE/$FILE" ] && [ ! -L "$STATE/$FILE" ] && [ -s "$STATE/$FILE" ] || exit 1
        done
        ;;
    toggle) ;;
    *) exit 1 ;;
esac
case "$RECOVER" in normal|recover) ;; *) exit 1 ;; esac
if [ "$RECOVER" = recover ] && [ -f "$MARKER" ] && [ ! -L "$MARKER" ]; then
    RP= RS= RJ= EXTRA=
    read -r RP RS RJ EXTRA < "$MARKER" || exit 1
    [ "$RJ" = "$JOB" ] && [ -z "$EXTRA" ] || exit 1
    OLD_STAMP=$(stamp "$RP" 2>/dev/null)
    [ "$OLD_STAMP" != "$RS" ] || exit 1
    rm -f "$MARKER" || exit 1
fi
[ ! -e "$MARKER" ] && [ ! -L "$MARKER" ] || exit 1
SELF_STAMP=$(stamp "$$") || exit 1
( set -C; printf '%s %s %s\n' "$$" "$SELF_STAMP" "$JOB" > "$MARKER" ) || exit 1
OWN_MARKER=1
trap finish 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15
if [ "$RECOVER" = recover ]; then
    CHANGED=1
    restore
    RESULT=$?
    if [ "$RESULT" != 0 ]; then status failed 'Не удалось восстановить VPN. Резервная настройка сохранена для повторной попытки.'; fi
    DONE=1
    exit "$RESULT"
fi
# This supervisor survives even when stop disables the normal VPN watchdog.
sh "$DATA/xray-switch-watch.sh" "$JOB" "$$" "$SELF_STAMP" </dev/null >> "$STATE/supervisor.log" 2>&1 &
SUPERVISOR=$!
SUPERVISOR_STAMP=$(stamp "$SUPERVISOR") || exit 1
sleep 1
SUPERVISOR_NOW=$(stamp "$SUPERVISOR" 2>/dev/null) || exit 1
[ "$SUPERVISOR_NOW" = "$SUPERVISOR_STAMP" ] || exit 1
# Let the CGI parent exit before preparing the 32 MiB Xray executable.
sleep 2
CHANGED=1
if [ "$KIND" = toggle ]; then
    TARGET=$("$MANAGER" toggle-target "$JOB") || exit 1
    case "$TARGET" in enable|disable) ;; *) exit 1 ;; esac
    status switching 'Изменяется состояние VPN.' || exit 1
    if [ "$TARGET" = enable ]; then
        NEW_MODE=$("$MANAGER" toggle-mode "$JOB") || exit 1
        if [ -n "$NEW_MODE" ]; then
            status switching 'Меняется режим маршрутизации.' || exit 1
            sh "$CTL" disable-vpn || exit 1
            write_mode "$NEW_MODE" || exit 1
        fi
    fi
    sh "$CTL" "$TARGET-vpn" || exit 1
    if [ "$TARGET" = enable ]; then
        status running 'Проверяется выход в интернет через VPN.' || exit 1
        "$MANAGER" probe || exit 1
    fi
    "$MANAGER" complete-toggle "$JOB" || exit 1
    DONE=1
    exit 0
fi
status switching 'Проверяется выбранный сервер.' || exit 1
sh "$CTL" stop || exit 1
[ ! -L "$DATA/xray.next.json" ] && [ ! -L "$DATA/xray.json" ] || exit 1
cp -f "$STATE/candidate.json" "$DATA/xray.next.json" || exit 1
chmod 600 "$DATA/xray.next.json" || exit 1
mv -f "$DATA/xray.next.json" "$DATA/xray.json" || exit 1
"$DATA/ax3-sync" || exit 1
sh "$CTL" test || exit 1
status starting 'Запускается выбранный сервер.' || exit 1
sh "$CTL" "$MODE" permanent || exit 1
status running 'Проверяется выход в интернет через новый сервер.' || exit 1
"$MANAGER" probe || exit 1
"$MANAGER" commit-switch "$JOB" || exit 1
DONE=1
"$DATA/ax3-sync" || exit 1
exit 0
