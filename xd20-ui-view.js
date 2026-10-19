// XD20_XRAY_HTML_V1: this child route inherits the native router login guard.
define(function() {
    return {
        name: 'xd20-xray-sites',
        template: '<section id="xd20-xray-view" style="padding:24px 20px 12px">' +
            '<h2 style="font-size:22px;line-height:1.4;margin:0 0 14px">VPN: подписки и сайты</h2>' +
            '<p style="font-size:14px;line-height:1.6;margin:0 0 14px">' +
                'Выбирай сервер из сохранённых подписок и меняй список сайтов. Настройки действуют для основной сети Wi-Fi и LAN роутера.' +
            '</p>' +
            '<p style="font-size:14px;line-height:1.6;margin:0 0 20px">' +
                '<a href="http://192.168.3.1:8088/" target="_blank" rel="noopener noreferrer" ' +
                    'style="display:inline-block;padding:12px 20px;border-radius:6px;background:#00bfc7;color:#fff;text-decoration:none">Открыть панель VPN</a>' +
            '</p>' +
            '<p style="font-size:14px;line-height:1.6;margin:0 0 14px">В панели можно включать и выключать VPN, менять сайты, обновлять подписки, выбирать сервер и проверять задержку.</p>' +
            '<p style="font-size:14px;line-height:1.6;margin:0 0 14px">Панель открывается в отдельной вкладке и использует свой логин и пароль. Их можно изменить во вкладке «Доступ».</p>' +
            '</section>'
    };
});
