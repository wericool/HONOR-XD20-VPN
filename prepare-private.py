#!/usr/bin/env python3
"""Prepare only the reader's private initial configuration. No network calls.

The public kit contains no VPN account, subscription or panel password. Run this
interactively in a terminal with Python 3.10+ after exporting one VLESS TCP/TLS
server URI from your own VPN client. Other transports require separate review;
this helper refuses options it cannot faithfully preserve.
"""
from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import warnings
from urllib.parse import parse_qsl, urlsplit


class InputError(ValueError):
    """Messages never include submitted secrets."""


def valid_host(host: str) -> bool:
    if not host or len(host) > 253 or not host.isascii():
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        return len(labels) >= 2 and all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            is not None for label in labels
        )
    return address.version == 4 and address.is_global


def parse_vless(uri: str) -> dict:
    if not uri.startswith("vless://") or len(uri) > 32768:
        raise InputError("Нужна одна собственная ссылка vless://, не ссылка подписки.")
    if any(ord(char) < 32 or char.isspace() for char in uri):
        raise InputError("В ссылке недопустимы пробелы и управляющие символы.")
    if re.search(r"%(?![0-9A-Fa-f]{2})", uri):
        raise InputError("В ссылке обнаружено неправильное URL-кодирование.")
    try:
        parts = urlsplit(uri)
        if parts.path or parts.netloc.count("@") != 1:
            raise InputError("Формат ссылки не поддержан.")
        credential, endpoint = parts.netloc.rsplit("@", 1)
        if not re.fullmatch(
            r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}", credential
        ):
            raise InputError("В ссылке должен быть обычный UUID пользователя VLESS.")
        # Keep the exact host spelling used by Go's url.Hostname() for the seed
        # equality check. IPv6 initial endpoints are deliberately not supported.
        if endpoint.count(":") != 1:
            raise InputError("Первоначальный сервер должен использовать домен или публичный IPv4.")
        host, port_text = endpoint.rsplit(":", 1)
        if not valid_host(host) or not port_text.isascii() or not port_text.isdecimal():
            raise InputError("Адрес или порт сервера не подходит для этого помощника.")
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise InputError("Порт сервера должен быть от 1 до 65535.")
        pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True)
    except (ValueError, UnicodeError) as error:
        if isinstance(error, InputError):
            raise
        raise InputError("Не удалось разобрать ссылку сервера.") from None

    allowed = {"type", "security", "encryption", "flow", "sni", "fp", "alpn", "headerType", "allowInsecure", "insecure"}
    query: dict[str, str] = {}
    for key, value in pairs:
        if key not in allowed or key in query:
            raise InputError("В ссылке есть дополнительные или повторяющиеся параметры. Нужен отдельный разбор, без их удаления.")
        query[key] = value
    transport = query.get("type", "").lower()
    if transport not in ("", "tcp", "raw") or query.get("security", "").lower() != "tls":
        raise InputError("Этот помощник готовит только VLESS через TCP и TLS. REALITY, XHTTP, WS и gRPC здесь не поддержаны.")
    if query.get("headerType", "") not in ("", "none"):
        raise InputError("TCP с HTTP-заголовком здесь не поддержан.")
    if query.get("encryption", "none") not in ("", "none"):
        raise InputError("Дополнительное шифрование VLESS требует отдельного разбора.")
    for key in ("allowInsecure", "insecure"):
        if query.get(key, "").lower() not in ("", "0", "false", "no"):
            raise InputError("Нельзя отключать проверку TLS-сертификата.")
    flow = query.get("flow", "")
    if flow not in ("", "xtls-rprx-vision"):
        raise InputError("Этот вариант flow не поддержан.")
    sni = query.get("sni", "") or host
    if not valid_host(sni):
        raise InputError("TLS serverName должен быть обычным доменом или публичным IPv4.")
    tls: dict = {"serverName": sni, "allowInsecure": False}
    fingerprint = query.get("fp", "")
    if fingerprint:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", fingerprint):
            raise InputError("Неподдержанный формат TLS fingerprint.")
        tls["fingerprint"] = fingerprint
    alpn = query.get("alpn", "")
    if alpn:
        entries = alpn.split(",")
        if any(re.fullmatch(r"[A-Za-z0-9./_-]{1,64}", entry) is None for entry in entries):
            raise InputError("Неподдержанный формат ALPN.")
        tls["alpn"] = entries
    user: dict = {"id": credential, "encryption": "none"}
    if flow:
        user["flow"] = flow
    return {
        "tag": "vpn", "protocol": "vless",
        "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
        "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": tls},
    }


def check_subscription(url: str) -> None:
    if not url:
        return
    if any(ord(char) < 33 for char in url) or len(url) > 4096 or not url.startswith("https://"):
        raise InputError("Нужна обычная HTTPS-ссылка подписки или пустой ввод.")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise InputError("Неверный формат ссылки подписки.") from None
    if parts.scheme != "https" or parts.username is not None or parts.password is not None or parts.fragment or not valid_host(parts.hostname or ""):
        raise InputError("Ссылка подписки должна вести на публичный HTTPS-сервер без логина в URL и без фрагмента.")
    if port is not None and not 1 <= port <= 65535:
        raise InputError("Неверный порт ссылки подписки.")


def check_access(login: str, password: str) -> None:
    if re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", login) is None:
        raise InputError("Логин: 1–32 латинских буквы, цифры, точки, дефисы или подчёркивания.")
    if not 8 <= len(password) <= 128 or any(ord(char) < 33 or ord(char) > 126 or char == ":" for char in password):
        raise InputError("Пароль: 8–128 печатных латинских символов без пробелов и двоеточия.")


def create_private(uri: str, subscription: str, login: str, password: str, output: Path, domain_file: Path) -> None:
    outbound = parse_vless(uri)
    check_subscription(subscription)
    check_access(login, password)
    domains = [line.strip() for line in domain_file.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if not domains:
        raise InputError("В комплекте отсутствует первоначальный список доменов.")
    config = {
        "log": {"access": "none", "loglevel": "warning"},
        "inbounds": [
            {"tag": "tun-in", "port": 0, "protocol": "tun", "settings": {"name": "xray0", "mtu": 1500, "gateway": [], "autoSystemRoutingTable": [], "autoOutboundsInterface": ""}},
            {"tag": "dns-vpn", "listen": "127.0.0.1", "port": 5354, "protocol": "dokodemo-door", "settings": {"address": "1.1.1.1", "port": 53, "network": "tcp,udp"}},
            {"tag": "manager-socks", "listen": "127.0.0.1", "port": 10809, "protocol": "socks", "settings": {"auth": "noauth", "udp": False}},
        ],
        "outbounds": [outbound],
        "routing": {"rules": [{"type": "field", "inboundTag": ["manager-socks"], "outboundTag": "vpn"}]},
    }
    initial = {"name": "Мой первоначальный сервер", "content": uri, "fetchMode": "auto" if subscription else "direct"}
    if subscription:
        initial["url"] = subscription
    seed = {"subscriptions": [initial], "currentConfig": config, "domains": domains}
    # Refuse the whole output directory, including symlinks. Never replace a
    # reader's previous credentials/configuration accidentally.
    if output.exists() or output.is_symlink():
        raise InputError("Папка вывода уже существует. Выбери новую папку; прежние секреты не перезаписаны.")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    documents = {
        "xray.json": json.dumps(config, ensure_ascii=False, indent=2) + "\n",
        "seed.json": json.dumps(seed, ensure_ascii=False, indent=2) + "\n",
        "httpd-private.conf": f"/:{login}:{password}\n",
    }
    for name, content in documents.items():
        target = output / name
        with target.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass  # Windows ACLs must be managed separately by the reader.


def main() -> int:
    parser = argparse.ArgumentParser(description="Создать собственные секретные файлы для первоначального запуска HONOR XD20.")
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parent / "reader-private", help="Новая папка вывода; по умолчанию reader-private рядом со скриптом.")
    options = parser.parse_args()
    if not sys.stdin.isatty():
        print("Запусти помощник в интерактивном терминале: ввод секретов из файла или pipe отключён.", file=sys.stderr)
        return 1
    warnings.simplefilter("error", getpass.GetPassWarning)
    print("Секреты не выводятся. Нужна собственная ссылка одного сервера VLESS TCP/TLS, экспортированная из VPN-клиента.")
    try:
        uri = getpass.getpass("Ссылка сервера (скрытый ввод): ").strip()
        subscription = getpass.getpass("Обычная HTTPS-подписка для будущих обновлений (можно пусто): ").strip()
        login = input("Свой логин панели [vpn]: ").strip() or "vpn"
        password = getpass.getpass("Свой пароль панели: ")
        confirmation = getpass.getpass("Повтори пароль: ")
        if password != confirmation:
            raise InputError("Пароли не совпадают.")
        create_private(uri, subscription, login, password, options.out, Path(__file__).resolve().parent / "domain.lst")
    except (InputError, OSError) as error:
        # OSError filenames may contain personal local paths; omit details.
        message = str(error) if isinstance(error, InputError) else "Не удалось создать собственные файлы. Проверь доступ и наличие свободного места."
        print(message, file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("Подготовка отменена.", file=sys.stderr)
        return 1
    except getpass.GetPassWarning:
        print("Скрытый ввод недоступен. Запусти помощник в обычном терминале; секреты не запрашивались открытым текстом.", file=sys.stderr)
        return 1
    print("Созданы xray.json, seed.json и httpd-private.conf в собственной папке вывода.")
    print("НЕ публикуй эту папку. После переноса удали её из каталога HTTP-сервера и останови сервер.")
    print("Подготовка файлов не доказывает работу VPN-сервера: проверка выполняется на роутере по гайду.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
