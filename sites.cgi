#!/bin/sh
# Authenticated list editor for the private XD20 panel. No user data is executed.
DATA=/data/xray-test
LIST=$DATA/domain.lst
LOCK=/tmp/xd20-sites.lock
TEMP=$DATA/.domain.web.$$.tmp
RAW=/tmp/xd20-sites.$$.raw
MAX_DOMAINS=4096
MAX_BYTES=262144
BACKUP=$DATA/.domain.web.$$.previous
OWN_LOCK=0
OWN_TEMP=0
OWN_RAW=0
OWN_BACKUP=0
OWN_ADAPTER=0
umask 077
LC_ALL=C
export LC_ALL
set -f

reply() {
    CODE=$1
    TEXT=$2
    printf 'Status: %s\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n%s\n' "$CODE" "$TEXT"
}
reject() { reply "$1" "$2"; exit 1; }
number() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }
stamp() (
    number "$1" || exit 1
    read -r LINE < "/proc/$1/stat" || exit 1
    TAIL=${LINE##*) }
    [ "$TAIL" != "$LINE" ] || exit 1
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
safe_empty_remove() {
    case "$1" in /tmp/xd20-sites.lock|/tmp/xd20-manager-adapter.lock) ;; *) return 1 ;; esac
    [ -d "$1" ] && [ ! -L "$1" ] || return 1
    # Globbing is disabled while validating domains; enable only in this subshell.
    (
        set +f
        for E in "$1"/* "$1"/.[!.]* "$1"/..?*; do
            if [ -e "$E" ] || [ -L "$E" ]; then exit 1; fi
        done
        rm -r "$1"
    )
}
finish() {
    RESULT=$?
    trap - 0
    [ "$OWN_TEMP" = 1 ] && rm -f "$TEMP"
    [ "$OWN_RAW" = 1 ] && rm -f "$RAW"
    [ "$OWN_BACKUP" = 1 ] && rm -f "$BACKUP"
    [ "$OWN_ADAPTER" = 1 ] && safe_empty_remove /tmp/xd20-manager-adapter.lock 2>/dev/null
    if [ "$OWN_LOCK" = 1 ]; then rm -f "$LOCK/owner"; safe_empty_remove "$LOCK" 2>/dev/null; fi
    exit "$RESULT"
}
trap finish 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15
lock() {
    if ! mkdir "$LOCK" 2>/dev/null; then
        P= S=
        [ -f "$LOCK/owner" ] && read -r P S < "$LOCK/owner"
        same_stamp "$P" "$S" && reject '409 Conflict' 'Другой запрос сохраняет список. Повтори через несколько секунд.'
        [ -f "$LOCK/owner" ] || reject '503 Service Unavailable' 'Не удалось получить блокировку списка.'
        rm -f "$LOCK/owner"
        safe_empty_remove "$LOCK" || reject '503 Service Unavailable' 'Не удалось удалить прежнюю блокировку.'
        mkdir "$LOCK" || reject '503 Service Unavailable' 'Не удалось получить блокировку списка.'
    fi
    OWN_LOCK=1
    S=$(stamp "$$") || reject '500 Internal Server Error' 'Не удалось определить процесс редактора.'
    printf '%s %s\n' "$$" "$S" > "$LOCK/owner" || reject '500 Internal Server Error' 'Не удалось записать блокировку.'
}
valid_domain() (
    DOMAIN=$1
    [ "${#DOMAIN}" -le 253 ] || exit 1
    case "$DOMAIN" in ''|.*|*.|*..*|*[!a-zA-Z0-9.-]*) exit 1 ;; *.*) ;; *) exit 1 ;; esac
    IFS=.
    set -- $DOMAIN
    [ "$#" -ge 2 ] || exit 1
    for LABEL in "$@"; do
        [ -n "$LABEL" ] && [ "${#LABEL}" -le 63 ] || exit 1
        case "$LABEL" in -*|*-|*[!a-zA-Z0-9-]*) exit 1 ;; esac
        LAST=$LABEL
    done
    # Bare IPv4 addresses belong in the separate static IP list, not domain.lst.
    case "$LAST" in *[a-zA-Z]*) exit 0 ;; *) exit 1 ;; esac
)

# httpd.conf protects '/' and every CGI with Basic authentication.
# Literal Host rejects DNS rebinding; non-simple header plus Origin protects POST.
[ "${HTTP_HOST:-}" = 192.168.3.1:8088 ] || reject '403 Forbidden' 'Открой панель по адресу http://192.168.3.1:8088/.'
case "${REMOTE_ADDR:-}" in 192.168.3.*) ;; *) reject '403 Forbidden' 'Панель доступна только в основной сети роутера.' ;; esac
# Two lists share this editor: sites for the VPN (default) and exceptions that
# bypass the VPN in "everything through VPN" mode (?list=bypass).
WHICH=sites
case "${QUERY_STRING:-}" in
    ''|list=sites) ;;
    list=bypass) WHICH=bypass; LIST=$DATA/bypass.lst ;;
    *) reject '400 Bad Request' 'Неизвестный список.' ;;
esac
if [ "$WHICH" = bypass ] && [ -d "$DATA" ] && [ ! -e "$LIST" ] && [ ! -L "$LIST" ]; then
    ( set -C; : > "$LIST" ) 2>/dev/null && chmod 600 "$LIST"
fi
[ -d "$DATA" ] && [ ! -L "$LIST" ] && [ -f "$LIST" ] || reject '503 Service Unavailable' 'Файл списка сайтов недоступен.'
case "${REQUEST_METHOD:-}" in
    GET)
        printf 'Content-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n'
        while read -r DOMAIN EXTRA || [ -n "$DOMAIN" ]; do
            case "$DOMAIN" in ''|\#*) continue ;; esac
            valid_domain "$DOMAIN" && printf '%s\n' "$DOMAIN"
        done < "$LIST"
        exit 0
        ;;
    POST) ;;
    *) reject '405 Method Not Allowed' 'Поддерживаются только чтение и сохранение списка.' ;;
esac
[ "${HTTP_ORIGIN:-}" = http://192.168.3.1:8088 ] || reject '403 Forbidden' 'Запрос должен идти из этой панели.'
[ "${HTTP_X_XD20_UI:-}" = sites-v1 ] || reject '403 Forbidden' 'Не найден заголовок панели.'
case "${CONTENT_TYPE:-}" in text/plain|text/plain\;\ charset=utf-8) ;; *) reject '415 Unsupported Media Type' 'Неверный формат списка.' ;; esac
number "${CONTENT_LENGTH:-}" || reject '411 Length Required' 'Не указана длина запроса.'
MIN_BYTES=2
[ "$WHICH" = bypass ] && MIN_BYTES=1
[ "$CONTENT_LENGTH" -ge "$MIN_BYTES" ] && [ "$CONTENT_LENGTH" -le "$MAX_BYTES" ] || reject '413 Content Too Large' "Список должен занимать от $MIN_BYTES до $MAX_BYTES байт."
# BusyBox httpd passes exactly CONTENT_LENGTH bytes to CGI stdin. The body is
# one domain per line (several per line are accepted too). Every line is
# validated and streamed to a private file; the total must match CONTENT_LENGTH,
# which also rejects NUL bytes and a missing final newline.
( set -C; : > "$RAW" ) 2>/dev/null || reject '500 Internal Server Error' 'Не удалось создать временный список.'
OWN_RAW=1
exec 3> "$RAW" || reject '500 Internal Server Error' 'Не удалось открыть временный список.'
GOT=0
COUNT=0
while IFS= read -r LINE || [ -n "$LINE" ]; do
    GOT=$(( GOT + ${#LINE} + 1 ))
    [ "$GOT" -le "$CONTENT_LENGTH" ] || reject '400 Bad Request' 'Размер списка не совпадает с заголовком запроса.'
    case "$LINE" in *[!a-zA-Z0-9.\ -]*) reject '422 Unprocessable Content' 'Используй только доменные имена латиницей, по одному на строку.' ;; esac
    for DOMAIN in $LINE; do
        valid_domain "$DOMAIN" || reject '422 Unprocessable Content' "Некорректное имя сайта: $DOMAIN. Нужен домен без https://, пути, порта и звёздочки."
        COUNT=$(( COUNT + 1 ))
        [ "$COUNT" -le "$MAX_DOMAINS" ] || reject '422 Unprocessable Content' "Слишком много сайтов: максимум $MAX_DOMAINS."
        printf '%s\n' "$DOMAIN" >&3 || reject '500 Internal Server Error' 'Не удалось записать временный список.'
    done
done
exec 3>&-
[ "$GOT" -eq "$CONTENT_LENGTH" ] || reject '400 Bad Request' 'Список должен завершаться переводом строки.'
[ "$COUNT" -gt 0 ] || [ "$WHICH" = bypass ] || reject '422 Unprocessable Content' 'Укажи хотя бы один сайт.'

lock
if [ -d /data/xray-manager ]; then
    mkdir /tmp/xd20-manager-adapter.lock 2>/dev/null || reject '409 Conflict' 'Сейчас сохраняются настройки VPN. Повтори через несколько секунд.'
    OWN_ADAPTER=1
fi
[ ! -f /data/xray-manager/switch/pending.json ] || reject '409 Conflict' 'Сейчас переключается сервер VPN. Сохрани список после завершения.'
( set -C; : > "$TEMP" ) 2>/dev/null || reject '500 Internal Server Error' 'Не удалось создать временный список.'
OWN_TEMP=1
( set -C; : > "$BACKUP" ) 2>/dev/null || reject '500 Internal Server Error' 'Не удалось сохранить прежний список.'
OWN_BACKUP=1
while IFS= read -r LINE || [ -n "$LINE" ]; do printf '%s\n' "$LINE"; done < "$LIST" > "$BACKUP" || reject '500 Internal Server Error' 'Не удалось сохранить прежний список.'
# Remove duplicates: sort -u when available, otherwise a slower order-keeping shell pass.
if command -v sort >/dev/null 2>&1; then
    sort -u "$RAW" > "$TEMP" || reject '500 Internal Server Error' 'Не удалось записать новый список.'
else
    SEEN=' '
    while read -r DOMAIN; do
        case "$SEEN" in *" $DOMAIN "*) continue ;; esac
        printf '%s\n' "$DOMAIN" >> "$TEMP" || reject '500 Internal Server Error' 'Не удалось записать новый список.'
        SEEN="$SEEN$DOMAIN "
    done < "$RAW"
fi
chmod 600 "$TEMP" "$BACKUP" || reject '500 Internal Server Error' 'Не удалось защитить список.'
mv -f "$TEMP" "$LIST" || reject '500 Internal Server Error' 'Не удалось сохранить список.'
OWN_TEMP=0
if ! sh "$DATA/xray-dns.sh" restart >> /tmp/xd20-sites-apply.log 2>&1; then
    if mv -f "$BACKUP" "$LIST"; then
        OWN_BACKUP=0
        sh "$DATA/xray-dns.sh" restart >> /tmp/xd20-sites-apply.log 2>&1
        reject '503 Service Unavailable' 'DNS не принял новый список. Прежний список восстановлен.'
    fi
    OWN_BACKUP=0
    reject '500 Internal Server Error' 'Не удалось применить или восстановить список. Нужна проверка через Telnet.'
fi
[ "$WHICH" = bypass ] && reply '200 OK' 'Список исключений сохранён.' && exit 0
reply '200 OK' 'Список сохранён. Для новых сайтов при необходимости переподключи Wi-Fi или перезапусти браузер. Адреса удалённых сайтов могут оставаться в VPN до перезагрузки роутера.'
