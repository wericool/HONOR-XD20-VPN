# Обновление действующей установки

Эта инструкция нужна, если VPN из этого проекта уже установлен и работает. **BIN прошивать не нужно.** На роутере должны существовать `/data/xray-test`, `/data/xray-manager` и рабочая панель. Не запускай заново `seed` и установщики overlay.

Обновляются только восемь файлов. Рабочие `xray.json`, `xray.gz`, `domain.lst`, `ip.lst`, `mode`, подписки и вход панели сохраняются. **Не копируй демонстрационный `domain.lst` поверх своего.**

## 1. Подготовка и копия

Скачай экспорт настроек во вкладке «Система», если эта функция уже есть. Храни его локально: в нём могут быть ключи и подписки. Запомни текущий сервер и режим. Подключись из основной сети HONOR.

Для дополнительной копии старого менеджера можно временно дать существующему защищённому HTTP-серверу ссылку на один файл. Выполни в root shell:

```sh
ln -s /data/xray-test/ax3-manager /data/xray-test/web/ax3-manager.before-update
```

С компьютера сохрани файл `http://192.168.3.1:8088/ax3-manager.before-update`, используя существующий вход панели. Проверь, что скачан бинарник, а не страница ошибки. После скачивания сразу убери ссылку:

```sh
rm -f /data/xray-test/web/ax3-manager.before-update
```

Проверь, что каталога `prev-public-v1` ещё нет; если он существует, выбери новое имя и используй его во всех командах. Сохрани прежние скрипты и страницу:

```sh
mkdir /data/xray-test/prev-public-v1
cp -f /data/xray-test/xrayctl.sh /data/xray-test/prev-public-v1/xrayctl.sh
cp -f /data/xray-test/xray-route.sh /data/xray-test/prev-public-v1/xray-route.sh
cp -f /data/xray-test/xray-dns.sh /data/xray-test/prev-public-v1/xray-dns.sh
cp -f /data/xray-test/xray-switch.sh /data/xray-test/prev-public-v1/xray-switch.sh
cp -f /data/xray-test/web/cgi-bin/sites.cgi /data/xray-test/prev-public-v1/sites.cgi
cp -f /data/xray-test/web/cgi-bin/manager.cgi /data/xray-test/prev-public-v1/manager.cgi
cp -f /data/xray-test/web/index.html /data/xray-test/prev-public-v1/index.html
```

Команды в Telnet вводи по одной. На исследованном роутере составные строки могли искажаться, а код возврата не всегда доказывал замену файла.

## 2. Место и передача

Нужно минимум **9 МиБ свободно в `/data`**, чтобы новый менеджер временно лежал рядом со старым. При нехватке места остановись и разбери содержимое; не удаляй работающий бинарник ради продолжения.

В штатном BusyBox команды `df` нет. В комплект включена отдельная утилита `df` из исходного community-пакета. Для проверки временно скачай её в исполняемый tmpfs `/dev`, выполни `df -k` и удали.

На компьютере из корня распакованного комплекта запусти временный HTTP-сервер. Адрес компьютера в примере — `192.168.3.3`; замени его своим адресом в основной сети HONOR:

```powershell
python -m http.server 80 --bind 192.168.3.3 --directory .
```

В раздаваемой папке должны быть только публичные файлы релиза. Личные экспорты и старый бинарник для отката держи отдельно. Доступ к TCP 80 разрешай только из своей LAN, предпочтительно только роутеру.

На роутере:

```sh
wget -g -v -l /dev/xd20-update-df -r /df 192.168.3.3
chmod 700 /dev/xd20-update-df
/dev/xd20-update-df -k
rm -f /dev/xd20-update-df
```

Смотри столбец `Available` строки `/data`: единица измерения — 1024 байта.

Скачай обновление под временными именами:

```sh
wget -g -v -l /data/xray-test/ax3-manager.new -r /ax3-manager 192.168.3.3
wget -g -v -l /data/xray-test/xrayctl.sh.new -r /xrayctl.sh 192.168.3.3
wget -g -v -l /data/xray-test/xray-route.sh.new -r /xray-route.sh 192.168.3.3
wget -g -v -l /data/xray-test/xray-dns.sh.new -r /xray-dns.sh 192.168.3.3
wget -g -v -l /data/xray-test/xray-switch.sh.new -r /xray-switch.sh 192.168.3.3
wget -g -v -l /data/xray-test/web/cgi-bin/sites.cgi.new -r /sites.cgi 192.168.3.3
wget -g -v -l /data/xray-test/web/cgi-bin/manager.cgi.new -r /manager.cgi 192.168.3.3
wget -g -v -l /data/xray-test/web/index.html.new -r /sites-index.html 192.168.3.3
```

## 3. Проверки перед заменой

Проверь SHA256 скачанного ZIP на компьютере по файлу релиза, затем файлы распакованного комплекта по `SHA256SUMS.txt`. На роутере сверь `wc -c` каждого `.new` с `MANIFEST.tsv`. По возможности скачай `.new` обратно через временную ссылку в защищённой панели, как в шаге 1, и сравни SHA256 с исходником. Размер сам по себе не заменяет проверку хеша.

Для текущего релиза размеры восьми файлов:

| Файл в комплекте | Байты |
| --- | ---: |
| ax3-manager | 7274656 |
| xrayctl.sh | 19682 |
| xray-route.sh | 23365 |
| xray-dns.sh | 11022 |
| xray-switch.sh | 7582 |
| sites.cgi | 10570 |
| manager.cgi | 4336 |
| sites-index.html | 53018 |

```sh
sh -n /data/xray-test/xrayctl.sh.new
sh -n /data/xray-test/xray-route.sh.new
sh -n /data/xray-test/xray-dns.sh.new
sh -n /data/xray-test/xray-switch.sh.new
sh -n /data/xray-test/web/cgi-bin/sites.cgi.new
sh -n /data/xray-test/web/cgi-bin/manager.cgi.new
chmod 700 /data/xray-test/ax3-manager.new /data/xray-test/xrayctl.sh.new /data/xray-test/xray-route.sh.new /data/xray-test/xray-dns.sh.new /data/xray-test/xray-switch.sh.new
chmod 700 /data/xray-test/web/cgi-bin/sites.cgi.new /data/xray-test/web/cgi-bin/manager.cgi.new
chmod 600 /data/xray-test/web/index.html.new
/data/xray-test/ax3-manager.new version
```

`sh -n` не должен сообщать ошибок; менеджер должен ответить `xd20-manager-1`. Строка версии общая для нескольких сборок: конкретную публикацию отличают хеши. При любой ошибке ничего не заменяй.

## 4. Применение

```sh
mv -f /data/xray-test/ax3-manager.new /data/xray-test/ax3-manager
mv -f /data/xray-test/xrayctl.sh.new /data/xray-test/xrayctl.sh
mv -f /data/xray-test/xray-route.sh.new /data/xray-test/xray-route.sh
mv -f /data/xray-test/xray-dns.sh.new /data/xray-test/xray-dns.sh
mv -f /data/xray-test/xray-switch.sh.new /data/xray-test/xray-switch.sh
mv -f /data/xray-test/web/cgi-bin/sites.cgi.new /data/xray-test/web/cgi-bin/sites.cgi
mv -f /data/xray-test/web/cgi-bin/manager.cgi.new /data/xray-test/web/cgi-bin/manager.cgi
mv -f /data/xray-test/web/index.html.new /data/xray-test/web/index.html
/data/xray-test/ax3-sync
```

Открой панель и нажми Ctrl+F5. Проверь вкладку «Система», свой список сайтов и подписки. Сохрани список сайтов через панель: так расширится предел ipset. Обнови свои подписки, проверь серверы и HTTPS-выход.

Для автообновления задай интервал, например 6 часов. Чтобы обновился уже работающий сторож, можно выключить и включить VPN через панель; соединение ненадолго прервётся. Перезагрузка не обязательна. Сохраняй свой обычный selective-режим; inverse-режим этой публикации на устройстве не проверялся.

Проверь устройство без отдельного VPN-приложения, сайт из списка и сайт вне списка. Останови HTTP-сервер на компьютере и убери только временно созданное правило firewall.

## 5. Откат

При сбое верни семь скриптов/страницу из `prev-public-v1` командами `cp -f` в исходные назначения из шага 1. Старый `ax3-manager`, сохранённый на компьютере, передай под именем `.new`, проверь размер/хеш и права 0700, затем замени через `mv -f`. Выполни `/data/xray-test/ax3-sync`. Верни обычный selective-режим и проверь статус; при необходимости перезапусти VPN через панель.

Если нужен аварийный выход из VPN, а не откат файлов:

```sh
sh /data/xray-test/xrayctl.sh rollback
```

Он удаляет собственные VPN-правила, отключает автозапуск и останавливает дополнительную панель. Это не восстановление базовой прошивки.
