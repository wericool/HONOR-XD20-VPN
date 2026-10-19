// XD20_XRAY_HTML_V1: additive menu and label; native auth retained.
define('api/mutations',function() {
    return {
        // get请求后数据处理
        commonCommit: function(state,payload) {
            if(typeof payload.res !== 'undefined' && !payload.res.ERRORSTATUS) {
                payload.$set(state, payload.name, payload.res)
            }
        },
        // 手动提交API数据修改后的数据处理
        changeApiState: function(state, changeArr) {
            if(changeArr[1][1] === true) {
                changeArr[2](state, changeArr[0], changeArr[1][0])
                return
            }
            for (var key in changeArr[1]) {
                if(typeof state[changeArr[0]][key] !== 'undefined') {
                    changeArr[2](state[changeArr[0]], key, changeArr[1][key])
                }else{
                    console.log(changeArr[0]+'中不存在数据'+key)
                }
            }
        }
    }
})
,define('api/getters',function() {
    return {
        // 黑白名单列表
        WlanFilterList: function(state) {
            if(state.wlanfilterenhance) {
                var filter = state.wlanfilterenhance[0];
                var obj = {};
                obj.MacFilterPolicy = filter.MacFilterPolicy;
                obj.MACAddressControlEnabled = filter.MACAddressControlEnabled;
                obj.BMACAddresses = [];
                obj.WMACAddresses = [];
                filter.BMACAddresses.forEach(function(item) {
                    obj.BMACAddresses.push(item.MACAddress)
                });
                filter.WMACAddresses.forEach(function(item) {
                    obj.WMACAddresses.push(item.MACAddress)
                });
                return obj;
            }else{
                return null
            }
        },
        deviceInfo: function(state){
            if(state.deviceinfo){
                var obj = state.deviceinfo;
                obj.httpFailedClass = "ic_router_httpfailed";
                obj.Capability = obj.devcap.SoftwareCapability;

                return obj;
            }else{
                return null
            }
        },
        HostInfoNameList: function(state) {
            if(state.HostInfo) {
                return state.HostInfo.map(function(item) {
                   return item.ActualName || item.HostName || item.MACAddress.replace(/:/g,'-')
                })
            }else{
                return null
            }
        },
        isBridge:function(state){
            if(!state.wan) return false
            return state.wan.ConnectionType == 'Bridged'
        },
        // 是否中继
        isRepeater:function(state){
            if(!state.wlanmode) return false
            return (state.wlanmode.WLANMode == 3 || state.wlanmode.HilinkStatus != 0)
        },
        disableArr:function(state, getters){
            if(getters.isRepeater){
                return [
                    "internet",
                    "devicecontrol"
                ]
            }else if(getters.isBridge){
                return ["devicecontrol"]
            }else{
                return []
            }
        },
        // 是否为定制产品
        isCustom: function(state) {
            return false;
        }
    }
}),
define('api/actions',function() {
    var vue = Vue.prototype
    return {
        /**
         * get请求公用API
         * @param {Object} context 
         * @param {Object} payload 数据载荷，包含name、param、message、upgrade(接口是否更新，默认为false)、stateName(当接口存入state的名称需要和name不同时传入，为false时不存储)
         */
        commonGet: function(context, payload) {
            if(!payload.upgrade && context.state[payload.name]) {
                return Promise.resolve(context.state[payload.name])
            }
            return vue.$util.$get(payload.name,payload.message,payload.param,payload.stateName,payload.timeout).then(function(res) {
                // 等待commit完成之后再次将结果返回
                if(res) {
                    if(payload.stateName !== false) {
                        context.commit('commonCommit',{name: payload.stateName || payload.name, res: res, $set: vue.$set})
                    }
                }
                return res
            })
        },
        /**
         * post请求公用API
         * @param {Object} context 
         * @param {Object} payload 数据载荷，包含name、res、$set、writeOnly(接口是否只写/需要get)、stateName(当接口存入state的名称需要和name不同时传入)
         */
        commonPost: function(context, payload) {
            var postData = {}
            if (payload.data && payload.data.data) {
               postData = payload.data; 
            } else if(payload.data) {
               postData.data = payload.data 
            }
            postData.csrf = context.rootState.csrf_obj;
            var message, buttonStr, i18n = context.rootState.i18n;
            if(payload.message) {
                message = payload.message === true ? i18n.t('loading') : payload.message
            }
            if(payload.loadingType === 'cancel') {
                buttonStr = i18n.t('cancel')
            }
            var loadingInfo = {
                text: message,
                loadingType: payload.loadingType,
                title: payload.title,
                buttonStr: buttonStr,
                cancelFn: payload.cancelFn
            };
            // 如果为enc，报文需要加密
            return (function(){
                if(payload.contentType&&payload.contentType.indexOf('enc') !== -1) {
                    return context.dispatch('enc', JSON.stringify(postData)).then(function(res) {
                        return res
                    })
                } else {
                    return Promise.resolve(postData)
                }
            })().then(function(encData) {
                var newData = encData;
                return vue.$util.$post(payload.name,newData,loadingInfo,payload.contentType,payload.timeout).then(function(res) {
                    var name = payload.stateName || payload.name
                    if(vue.$util.DEBUG) {
                        if(!context.state[name]) {
                            return {errcode: 0, debug: true}
                        }
                        var oldData = vue.$util.cloneObj(context.state[name])
                        for (var key in postData.data) {
                            oldData[key] = postData.data[key]
                        }
                        context.commit('commonCommit',{name: name, res: oldData, $set: vue.$set})
                        return {errcode: 0, data: oldData, debug: true}
                    }
                    if(res && res.csrf_param) {
                        context.commit('changeCsrf', {csrf_param: res.csrf_param, csrf_token: res.csrf_token})
                    }
                    if(!payload.writeOnly && res && res.errcode === 0) {
                        return context.dispatch('commonGet',{name: payload.name, upgrade: true, stateName: payload.stateName}).then(function() {
                            return res
                        })
                    }else{
                        return res
                    }
                })
            })
        },
        /**
         * 多并发get请求公用API
         * @param {Object} context vuex中context形参
         * @param {Array || Object} urlArr 接口名称数组/对象，对象时{names: urlArr, upgrade: true}
         */
        multiGets: function(context, urlArr) {
            var nameArr = [];
            var arr = urlArr.names || urlArr
            if(!urlArr.names || !urlArr.upgrade) {
                nameArr = arr.filter(function(item) {
                    return !context.state[item]
                })
            }else{
                nameArr = urlArr.names
            }
            if(nameArr.length === 0) {
                var resData = {}
                arr.forEach(function(name) {
                    resData[name] = context.state[name]
                })
                return resData
            }
            return vue.$util.$all(nameArr).then(function(res) {
                for (var key in res) {
                    context.commit('commonCommit',{name: key, res: res[key], $set: vue.$set})
                }
                return res
            })
        },
        /**
         * 修改Api下对应接口数据
         * @param {Object} context vuex中context形参
         * @param {Object} changeList 需要改变存储的Api列表，例如：{apiName1: {key1: newValue1, key2: newValue2}, apiName2: {key3: newValue3}}
         */
        changeApi: function(context, changeList) {
            for (var apiName in changeList) {
                if (changeList.hasOwnProperty(apiName)) {
                    var values = changeList[apiName];
                    context.commit('changeApiState', [apiName, values, vue.$set])    
                }
            }
        }
    }
}),define('api/index',[
    'api/mutations',
    'api/actions',
    'api/getters'
], function(mutations, actions, getters) {
    return {
        state: {},
        getters: getters,
        mutations: mutations,
        actions: actions 
    }
}),define('data/state',function() {
    // TODO: Nav部分的宏写在此处，对应之前Ember中的html.lua
    var Nav = [
        {
            id: 'home',
            url: 'home',
            active: true,
            disable: false
        },
        {
            id: 'internet',
            url: 'internet',
            active: false,
            disable: false
        },
        {
            id: 'wifi',
            url: 'wifi',
            active: false,
            disable: false
        },
        {
            id: 'devicecontrol',
            url: 'devicecontrol',
            active: false,
            disable: false
        },
        {
            id: 'more',
            url: 'more',
            active: false,
            disable: false
        }
    ]

    var Menus = [
        {
            id:'deviceinfo',
            focus: false,
            active: false,
        },
        {
            id: 'upgrade',
            focus: false,
            active: false,
        },
        {
            id: 'netsettings',
            focus: false,
            active: false,
            childMenus: [
                {
                    id: 'lan',
                    active: false
                },
                {
                    id: 'vpn',
                    active: false
                },
                {
                    // XD20_XRAY_HTML_V1: primary-router menu only.
                    id: 'xray',
                    active: false
                },
                {
                    id: 'iptv',
                    active: false
                },
                {
                    id: 'upnp',
                    active: false
                },
                {
                    id: 'wlanintelligent',
                    active: false
                },
                {
                    id: 'sipalg',
                    active: false
                },
                {
                    id: 'staticroute',
                    active: false
                },
                {
                    id: 'ipv6',
                    active: false
                }
            ]
        },
        {
            id: 'wifisettings',
            focus: false,
            active: false,
            childMenus: [
                {
                    id: 'wlanadvance',
                    active: false
                },
                {
                    id: 'wlanaccess',
                    active: false
                },
                {
                    id: 'wlanguest',
                    active: false
                },
                {
                    id: 'repeater',
                    active: false
                },
                {
                    id: 'wlaneco',
                    active: false
                },
            ]
        },
        {
            id: 'safesettings',
            focus: false,
            active: false,
            childMenus: [
                {
                    id: 'firewall',
                    active: false
                },
                {
                    id: 'nat',
                    active: false
                },
                {
                    id: 'dmz',
                    active: false
                },
                {
                    id: 'parentcontrol',
                    active: false
                },
            ]
        },
        {
            id: 'systemsettings',
            focus: false,
            active: false,
            childMenus: [
                {
                    id: 'account',
                    active: false
                },
                {
                    id: 'sntp',
                    active: false
                },
                {
                    id: 'wansettings',
                    active: false
                },
                {
                    id: 'reset',
                    active: false
                },
                {
                    id: 'diagnose',
                    active: false
                },
                {
                    id: 'mirror',
                    active: false
                }
            ]
        },
        {
            id: 'application',
            focus: false,
            active: false,
            childMenus: [
                {
                    id: 'smartpush',
                    active: false
                },
            ]
        }
    ];
var RepeaterMenus = [
        {
            id: 'deviceinfo',
            focus: false,
            active: false,
        },
        {
            id: 'upgrade',
            focus: false,
            active: false,
        },
        {
            id: 'netsettings',
            focus: false,
            active: false,
            childMenus: [
                {
                    id: 'upnp',
                    active: false
                },
                {
                    id: 'wlanintelligent',
                    active: false
                }
            ]
        },
        {
            id: 'wifisettings',
            focus: false,
            active: false,
            childMenus: [
                {
                    id: 'wlanaccess',
                    active: false
                },
                {
                    id: 'repeater',
                    active: false
                },
                {
                    id: 'wlaneco',
                    active: false
                },
            ]
        },
        {
            id: 'systemsettings',
            focus: false,
            active: false,
            childMenus: [
                {
                    id: 'sntp',
                    active: false
                },
                {
                    id: 'reset',
                    active: false
                },
                {
                    id: 'mirror',
                    active: false
                }
            ]
        },
        {
            id: 'application',
            focus: false,
            active: false,
            childMenus: [
                {
                    id: 'smartpush',
                    active: false
                },
            ]
        }
];

    var guideStatus = {
        guidePages: "",
        connectType:"",                     /*connecting页面状态 swanscan  wanscan  wandetect */
        isBridged:false,                    /*向导是否为中继模式*/
        isLineBridged:false,                /*向导是否是有线桥接*/
        hasHttpError:false,                 /*scaning waninfo 次数*/
        hasPPPoEError:false,
        hasDHCPError:false,
        detectCnt:0,                        /*scaning waninfo 次数*/
        detectStatus:0,                     /*探测wan connected次数*/
        detectWanConnectedCnt:10,           /*默认最大探测wan次数*/
        detectHTTPStatus:0,                 /*http探测次数*/
        accesscounted:0,
        isSetIntervaled:0,                  /*post client_heartbeat计时器*/
        isShowDetail:false,                 /*pppoe页面显示账号受限描述*/
        learnpurPage:"",                    /*旧路由学习的前一个页面*/
        isDHCPLearnSuccess:false,           /*DHCP旧路由学习成功*/
        isPPPLearnSuccess:false,            /*PPP旧路由学习成功*/
        wanLearnResult:"wanLearnInit",      //旧路由学习状态
        isLearnDHCPConnectErr:false,        /*dhcp旧路由学习拨号失败*/
        pppConnErr:"",                      /*ppp联网失败提示语*/
        pppConnInfoErr:"",                  /*ppp联网失败提示语info描述*/
        dhcpfailinfo:"",                    /*dhcp联网失败提示语*/
        isShowMac:false,                    /*是否显示mac克隆*/
        submitwanaccount:0,                 /*设置wan次数*/
        wanresultfaid:false,                /*wan*/
        /*pppHttpAccount:false,*/               /*PPP拨号获取到IP，但http探测失败*/
        /*dhcpHttpAccount:false, */             /*dhcp拨号获取到IP，但http探测失败*/
        wifiItem:{},                        /*向导中继wifi*/
        finishType:"",
        powerMode:null,                      /*WiFi功率模式*/
        isChangeIpv6:false                  /*是否修改IPv6开关状态*/
    }
    var BiFsmData = {
        curstate: "init",
        curresult: "",
        curreason: "",
        curitem: "",
        enterdate: null,
        content:{}
    }

    var login = {
        ence:null,
        encn:null,
        isLogin:undefined
    }
    var Domain = null;
    return {
        Nav: Nav,
        Menus: Menus,
        allMenus: Menus,
        RepeaterMenus:RepeaterMenus,
        guideStatus:guideStatus,
        Domain:Domain,
        BiFsmData:BiFsmData,
        login:login,
        showLeadAPP: isShowLeadAppPage           /* 是否显示引导app下载页面 */
    }
}),define('data/mutations',function() {
    function removeMenu(Menu, deleteMenu) {
        var oldMenu = JSON.parse(JSON.stringify(Menu));
        oldMenu = oldMenu.filter(function(item) {
            return deleteMenu[item.id] !== true
        });
        oldMenu.forEach(function(menu) {
            if(deleteMenu[menu.id] === 'CHILD') {
                delete menu.childMenus
            }else if(deleteMenu[menu.id]) {
                menu.childMenus = menu.childMenus.filter(function(item) {
                    return deleteMenu[menu.id].indexOf(item.id) == -1
                })
            }
        })
        return oldMenu
    };

    return {
        changeNav: function(state, id){
            state.Nav.forEach(function(ele) {
                ele.active = ele.id == id ? true : false
            });
        },
        changeNavDisable:function(state,arr){
            this.commit('changeMenus');
            state.Nav.forEach(function(item) {
                item.disable = false;
                for(var i = 0;i<arguments.length;i++){
                    if(item.id == arr[i]){
                        item.disable = true
                        item.active = false
                    }
                }
            });
        },
        changeMenus: function(state) {
            var allMenus = state.allMenus;
            if(this.getters.isRepeater) {
                state.Menus = removeMenu(state.RepeaterMenus, this.getters.deleteMenu)
            } else {
                state.Menus = removeMenu(allMenus, this.getters.deleteMenu)
            }
            var hash = window.location.hash;
            if(hash.indexOf('more') !== -1) {
                var id = hash.split('/').pop();
                this.commit('thirdTitleClick',{id:id})
            }
        },
        secondTitleClick: function(state, id) {
            state.Menus.forEach(function(ele) {
                if( ele.id == id ) {
                    ele.focus = true
                    ele.active = !ele.active
                }else {
                    ele.focus = false
                    ele.active = false
                }
            })
        },
        thirdTitleClick: function(state, payload) {
            if(payload.parentId) {
                state.Menus.forEach(function(ele) {
                    if(ele.id == payload.parentId) {
                        ele.childMenus.forEach(function(item) {
                            item.active = item.id === payload.id ? true : false
                        })
                    }
                })
            }else{
                state.Menus.forEach(function(ele) {
                    ele.focus = false
                    ele.active = false
                    if(ele.childMenus) {
                        ele.childMenus.forEach(function(item) {
                            if(item.id === payload.id) {
                                item.active = true
                                ele.focus = true
                                ele.active = true
                            }else{
                                item.active = false
                            }
                        })
                    }else{
                        var id = ele.url || ele.id;
                        if(id === payload.id) {
                            ele.focus = true
                            ele.active = true
                        }
                    }
                })
            }
        } 
    }
}),define('data/getters',function() {  
    function addToArr(deleteMenu, menu, name) {
        if(name===true || name === 'CHILD') {
            deleteMenu[menu] = name;
            return
        }
        if(deleteMenu[menu]) {
            deleteMenu[menu].push(name)
        } else {
            deleteMenu[menu] = [name]
        }
    };
    return {
        deleteMenu: function(state, getters, rootState) {
            var deleteMenu = {};
            var Api = rootState.Api;
            if(getters.isBridge) {
                addToArr(deleteMenu, 'wifisettings', 'wlanguest')
                addToArr(deleteMenu, 'netsettings', 'ipv6')
                addToArr(deleteMenu, 'netsettings', 'xray')
                addToArr(deleteMenu, 'safesettings', 'parentcontrol')
                addToArr(deleteMenu, 'netsettings', 'sipalg')
                addToArr(deleteMenu, 'netsettings', 'staticroute')
            }
            if (Api.deviceinfo&&!Api.deviceinfo.devcap.SoftwareCapability['63']) {
                addToArr(deleteMenu, 'systemsettings', 'wansettings')
            }else{
                addToArr(deleteMenu, 'systemsettings', 'ntwkportrate')
            }
            if(Api.deviceinfo&&!Api.deviceinfo.modcap.isSupportRepeaterConfig) {
                addToArr(deleteMenu, 'wifisettings', 'repeater')
            }
            if(Api.hilink_status&&Api.hilink_status.hilink_status==2) {
                addToArr(deleteMenu, 'wifisettings', 'repeater')
                addToArr(deleteMenu, 'netsettings', 'wlanintelligent')
            }
            if(!Api.deviceinfo.modcap.isSupport80211AX){
                if(getters.isRepeater){
                }
            }else{
                if(getters.isRepeater){
                }
            }
            if(Api.deviceinfo&&!Api.deviceinfo.modcap.isSupportSIPALGSwitch) {
                addToArr(deleteMenu, 'netsettings', 'sipalg')
            }
            if(Api.deviceinfo&&!Api.deviceinfo.modcap.isSupportStaticRoute) {
                addToArr(deleteMenu, 'netsettings', 'staticroute')
            }
            if(Api.hilink_status&&Api.hilink_status.hilink_status==2&& Api.location && Api.location.isRemote) {
                addToArr(deleteMenu, 'wifisettings', true)
            }
            return deleteMenu
        }
    }
    
}),define('data/actions',function() {
    return {
        thirdTitleClick: function(context, payload) {
            context.commit('thirdTitleClick', payload)
            context.commit('changeRoute', '/more/'+payload.id)
        }
    }
}),
define('data/index',[
    'data/state',
    'data/mutations',
    'data/actions',
    'data/getters'
], function(Data, mutations, actions, getters) {
    return {
        state: Data,
        mutations: mutations,
        actions: actions,
        getters: getters 
    }
}),define([
  '_router',
  'data/index',
  'api/index',
  '/lang/'+g_userLang+'/'+'vuex_res.js'
], function(router, Data, Api, lang) {
  Vue.use(VueI18n)
  Vue.use(Vuex)
  var vue = Vue.prototype;
  var messages = {}
  messages[g_userLang] = lang
  // XD20_XRAY_HTML_V1: label rendered by the unchanged native menu component.
  messages[g_userLang].xray = 'VPN: подписки и сайты'
  var i18n = new VueI18n({
    locale: g_userLang,
    fallbackLocale: 'zh',
    messages: messages
  })
  var loginTimes = 0;

  return new Vuex.Store({
    state: {
      i18n: i18n,
      csrf_obj: {},
      pubkey: undefined
    },
    mutations: {
      changeLang: function(state, lang) {
        state.i18n.locale = lang
      },
      changeRoute: function(state, path){
        router.push(path)
      },
      changeCsrf: function(state, csrf_obj) {
        state.csrf_obj = csrf_obj
      },
      changePubkey: function(state, newPubkey) {
        state.pubkey = newPubkey
      }
    },
    actions: {
      routePathChange: function(context, path) {
        var pathArr = path.split('/')
        context.commit('changeNav', pathArr[1])
        if(pathArr[2]) {
          context.commit('thirdTitleClick',{id:pathArr[2]})
        }
      },
      changeNavDisable: function(context,arr){
        context.commit('changeNavDisable',arr)
      },
      getEnc: function(context) {
        return context.dispatch('commonGet', {name: 'encpubkey', upgrade: true, stateName: false}).then(function(res) {
          context.commit('changePubkey', [res.EncpubkeyN, res.EncpubkeyE])
          return res
        })
      },
      //处理单个或多个enc
      resolveEnc: function(context, enc) {
        var pubkey = context.state.pubkey;
        if(typeof enc === 'object') {
            return enc.map(function(item) {
                return vue.$util.enc(item.toString(), pubkey)
            })
        } else {
            return vue.$util.enc(enc.toString(), pubkey)
        }
      },
      //加密
      enc: function(context, encstring) {
        if(!context.state.pubkey) {
          return context.dispatch('getEnc').then(function(res) {
            return context.dispatch('resolveEnc', encstring)
          })
        } else {
          return context.dispatch('resolveEnc', encstring)
        }
      },
      //解密 type: String || Object
      getPassword:function(context, type){
        if(typeof type === 'object') {
          type = type.type
          var mockData = type.mockData
        }
        var scram = CryptoJS.SCRAM();
        var wifiNonce = scram.nonce().toString();
        var wifiSalt = scram.nonce().toString();
        var nonceStr = wifiNonce + wifiSalt;
        return context.dispatch('enc', nonceStr).then(function(res) {
          var nonceData = res;
          var post_data = {
            'module':type,
            'nonce':nonceData
          };
          return context.dispatch('commonPost', {name: 'pwd', data: post_data, writeOnly: true,contentType:'application/json; charset=utf-8;enp'}).then(function(result) {
            if(mockData) {
              result = mockData
            }
            var password;
            if (0 == result['err']) {
              var scram = CryptoJS.SCRAM();
              var wifiEncrypted = result['pwd'];
              var salt = CryptoJS.enc.Hex.parse(wifiSalt);
              var iter = result['iter'];
              var saltedStr = scram.saltedPassword(wifiNonce, salt, iter);
              saltedStr = saltedStr.toString();
              var aesKey = saltedStr.substring(0,32);
              var aesIV = saltedStr.substring(32,64);
              var hmacKey = saltedStr.substring(48,64);
              var hashData = scram.signature(CryptoJS.enc.Hex.parse(wifiEncrypted), CryptoJS.enc.Hex.parse(hmacKey));
              hashData = hashData.toString();
              if (result['hash'] == hashData) {
                var encrypted = CryptoJS.enc.Base64.stringify(CryptoJS.enc.Hex.parse(wifiEncrypted));
                var decryptedData = vue.$util.getDAesString(encrypted,aesKey,aesIV);
                password = decryptedData; 
              }
              return password
            }
          })
        })
      },
      // 登录集中处理 data: {username, password}
      login: function(context, data) {
        loginTimes++;
        if(g_userScram == 1){
          var scram = CryptoJS.SCRAM({keySize: 8});
          var firstNonce = scram.nonce().toString();
          var password = data.password;
          var param = {name:'user_login_nonce',data:{username:data.username,firstnonce:firstNonce}};
          return context.dispatch('commonPost', param).then(function(res) {
            if(!res || res.errcode){
              if(loginTimes >= 5) {
                loginTimes = 0;
                return Promise.reject(res)
              } else {
                return context.dispatch('login', data)
              }
            }
            if(res.err == 0) {
              var salt = CryptoJS.enc.Hex.parse(res['salt']);
              var iter = res['iterations'];
              var finalNonce = res['servernonce'];
              var authMsg = firstNonce + "," + finalNonce + "," + finalNonce;
              var saltPassword = scram.saltedPassword(password,salt,iter).toString();
              var serverKey = scram.serverKey(CryptoJS.enc.Hex.parse(saltPassword));
              var clientKey = scram.clientKey(CryptoJS.enc.Hex.parse(saltPassword)).toString();
              var storekey = scram.storedKey(CryptoJS.enc.Hex.parse(clientKey));
              storekey = storekey.toString();
              var clientsignature = scram.signature(CryptoJS.enc.Hex.parse(storekey), authMsg);
              clientsignature = clientsignature.toString();
              clientsignature = CryptoJS.enc.Hex.parse(clientsignature);
              clientKey = CryptoJS.enc.Hex.parse(clientKey);
              for (var i = 0; i < clientKey.sigBytes/4; i++) {
                  clientKey.words[i] = clientKey.words[i] ^ clientsignature.words[i]
              }
              var param1 = {name:'user_login_proof',data:{clientproof:clientKey.toString(),finalnonce:finalNonce}};
              return context.dispatch('commonPost', param1).then(function(result) {
                if(result.err == 0){
                  var serverProof = scram.serverProof(password, salt, iter, authMsg);
                  serverProof = serverProof.toString();
                  if(result.serversignature == serverProof) {
                    var publicKey = result.rsan;
                    var publicKeySignature = scram.signature(CryptoJS.enc.Hex.parse(publicKey), serverKey);
                    publicKeySignature = publicKeySignature.toString();
                    if (result.rsapubkeysignature == publicKeySignature){
                      g_userLevel = result.level;
                      loginTimes = 0;
                      context.state.Data.login.ence = result.rsan
                      context.state.Data.login.encn = result.rsae
                      return Promise.resolve(result);
                    }
                  } else {
                    loginTimes = 0;
                    return Promise.reject(result)
                  }
                }else{
                  loginTimes = 0;
                  return Promise.reject(result)
                }
              })
            } else {
              loginTimes = 0;
              return Promise.reject(res)
            }
          })
        }else{
          var csrf_obj = context.state.csrf_obj;
          var post_data = {
            UserName: data.username,
            Password: data.password
          };
          var plaintPwd = data.username + base64Encode(SHA256(data.password)) + csrf_obj.csrf_param +csrf_obj.csrf_token;
          post_data["Password"] = SHA256(plaintPwd);
          post_data["LoginFlag"] = 1;
          return context.dispatch('commonPost', {name: 'user_login', data: post_data}).then(function(result) {
            loginTimes = 0;
            if('ok' == result['errorCategory']) {
              g_userLevel = result['level'];
              return Promise.resolve(result)
            } else if (1 != result.errcode) {
              return Promise.reject(result)
            }
          })
        }
      }
    },
    modules: {
      Data: Data,
      Api: Api
    }
  })
});