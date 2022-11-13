全部是手机自各路大神，没有自己原创

京东·淘宝历史价来自 **[yichahucha](https://github.com/yichahucha/surge/blob/master/README.md#surge)**  
* 京东：  
```properties
[rewrite_local]
^https?://api\.m\.jd\.com/client\.action\?functionId=(wareBusiness|serverConfig|basicConfig) url script-response-body https://raw.githubusercontent.com/yichahucha/surge/master/jd_price.js
[mitm]
hostname = api.m.jd.com
```  
* 淘宝：  
```properties
# 不生效或失效的需要卸载 tb 重装，注意不开脚本进 tb 会失效
[rewrite_local]
^http://.+/amdc/mobileDispatch url script-request-body https://raw.githubusercontent.com/yichahucha/surge/master/tb_price.js
^https?://trade-acs\.m\.taobao\.com/gw/mtop\.taobao\.detail\.getdetail url script-response-body https://raw.githubusercontent.com/yichahucha/surge/master/tb_price.js
[mitm]
hostname = trade-acs.m.taobao.com
```
