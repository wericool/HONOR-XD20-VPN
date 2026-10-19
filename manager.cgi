#!/bin/sh
# Authenticated CGI gate. The Go manager owns JSON parsing, limits and responses.
MANAGER=/data/xray-test/ax3-manager
reply() {
    printf 'Status: %s\r\nContent-Type: application/json; charset=utf-8\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n{"ok":false,"error":"%s"}\n' "$1" "$2"
}
reject() { reply "$1" "$2"; exit 1; }
number() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }
[ "${HTTP_HOST:-}" = 192.168.3.1:8088 ] || reject '403 Forbidden' 'Открой панель по адресу http://192.168.3.1:8088/.'
case "${REMOTE_ADDR:-}" in 192.168.3.*) ;; *) reject '403 Forbidden' 'Панель доступна только в основной сети роутера.' ;; esac
count_lines() {
    N=0
    [ -f "$1" ] && [ ! -L "$1" ] || { printf '0'; return 0; }
    while read -r L || [ -n "$L" ]; do
        case "$L" in ''|\#*) ;; *) N=$((N + 1)) ;; esac
    done < "$1"
    printf '%s' "$N"
}
first_word() {
    V=
    [ -f "$1" ] && [ ! -L "$1" ] && read -r V _ < "$1"
    case "$V" in selective|full|inverse) printf '%s' "$V" ;; esac
}
json_status() {
    RUNNING=false; [ -d /sys/class/net/xray0 ] && RUNNING=true
    DISABLED=false; [ -f /data/xray-test/vpn.disabled ] && DISABLED=true
    MEM=0
    while read -r K V _; do case "$K" in MemAvailable:) MEM=$V; break ;; esac; done < /proc/meminfo
    UP=0
    read -r UP _ < /proc/uptime; UP=${UP%%.*}
    printf 'Content-Type: application/json; charset=utf-8\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n'
    printf '{"ok":true,"running":%s,"disabled":%s,"mode":"%s","active":"%s","memAvailableKb":%s,"uptimeSeconds":%s,"domains":%s,"bypass":%s}\n'         "$RUNNING" "$DISABLED" "$(first_word /data/xray-test/mode)" "$(first_word /tmp/xd20-xray.active)" "${MEM:-0}" "${UP:-0}"         "$(count_lines /data/xray-test/domain.lst)" "$(count_lines /data/xray-test/bypass.lst)"
}
case "${REQUEST_METHOD:-}:${QUERY_STRING:-}" in
    GET:status) json_status; exit 0 ;;
    GET:events)
        printf 'Content-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n'
        [ -f /tmp/xd20-manager-events.log ] && [ ! -L /tmp/xd20-manager-events.log ] && cat /tmp/xd20-manager-events.log
        exit 0
        ;;
esac
case "${REQUEST_METHOD:-}" in
    GET)
        # Public state is generated atomically by the manager. Polling a switch
        # must not start another Go process while Xray is being unpacked.
        if [ -f /data/xray-manager/public-state.json ] && [ ! -L /data/xray-manager/public-state.json ]; then
            printf 'Content-Type: application/json; charset=utf-8\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n'
            cat /data/xray-manager/public-state.json
            exit $?
        fi
        ;;
    POST)
        [ "${HTTP_ORIGIN:-}" = http://192.168.3.1:8088 ] || reject '403 Forbidden' 'Запрос должен идти из этой панели.'
        [ "${HTTP_X_XD20_UI:-}" = manager-v1 ] || reject '403 Forbidden' 'Не найден заголовок панели.'
        case "${CONTENT_TYPE:-}" in application/json|application/json\;\ charset=utf-8) ;; *) reject '415 Unsupported Media Type' 'Неверный формат запроса.' ;; esac
        number "${CONTENT_LENGTH:-}" || reject '411 Length Required' 'Не указана длина запроса.'
        [ "$CONTENT_LENGTH" -ge 2 ] && [ "$CONTENT_LENGTH" -le 16384 ] || reject '413 Content Too Large' 'Запрос слишком большой. Максимум — 16384 байта.'
        # Avoid starting a Go helper during the single-core switch/unpack.
        [ ! -e /data/xray-manager/switch/pending.json ] && [ ! -L /data/xray-manager/switch/pending.json ] || reject '409 Conflict' 'Действие ещё выполняется. Дождись завершения и перечитай состояние.'
        ;;
    *) reject '405 Method Not Allowed' 'Поддерживаются только чтение и сохранение настроек.' ;;
esac
[ -x "$MANAGER" ] || reject '503 Service Unavailable' 'Управление подписками пока недоступно.'
# No shell expansion or interpretation of submitted data. stdin remains untouched.
exec "$MANAGER" cgi
