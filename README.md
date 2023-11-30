## Usage

__保存脚本执行__

```
wget -N --no-check-certificate -q -O xray.sh "https://cdn.jsdelivr.net/gh/uerax/xray-script@master/xray.sh" && chmod +x xray.sh && bash xray.sh
```

__不保存脚本执行__

```
bash -c "$(curl -L https://cdn.jsdelivr.net/gh/uerax/xray-script@master/xray.sh)" @
```

__国内机器__

```
wget -N --no-check-certificate -q -O xray.sh "https://mirror.ghproxy.com/https://raw.githubusercontent.com/uerax/xray-script/master/xray-cn.sh" && chmod +x xray.sh && bash xray.sh
```

`一键安装`

```
bash -c "$(curl -L https://cdn.jsdelivr.net/gh/uerax/xray-script@master/xray.sh)" @ install
```

`完全卸载`

```
bash -c "$(curl -L https://cdn.jsdelivr.net/gh/uerax/xray-script@master/xray.sh)" @ uninstall
```

## Script

实现一键安装的功能,只兼容 ubuntu 和 debian

现在已支持以下协议

- vless-tls-reality(推荐)
- hysteria2(推荐)
- trojan-tcp-tls(推荐)
- vless-grpc-reality
- vless-h2-reality
- trojan-grpc
- vmess-ws-tls
- vless-ws-tls
- vless-grpc
- vless-tcp-xtls-vision
- shadowsocket-2022
- trojan


## Question

* 分享链接可能存在问题,客户端如果解析失败可以手动填写参数