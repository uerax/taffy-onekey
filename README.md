## Usage

__保存脚本执行__

```
wget -N --no-check-certificate -q -O taffy.sh "https://raw.githubusercontent.com/uerax/taffy-onekey/master/taffy.sh" && chmod +x taffy.sh && bash taffy.sh
```

__不保存脚本执行__

```
bash -c "$(curl -sL https://raw.githubusercontent.com/uerax/taffy-onekey/master/taffy.sh)" @
```

__国内机器__

```
wget -N --no-check-certificate -q -O taffy-cn.sh "https://gh-proxy.com/https://raw.githubusercontent.com/uerax/taffy-onekey/master/taffy-cn.sh" && chmod +x taffy-cn.sh && bash taffy-cn.sh
```

`一键安装 Singbox`

```
bash -c "$(curl -sL https://raw.githubusercontent.com/uerax/taffy-onekey/master/taffy.sh)" @ singbox
```

`一键安装 Xray`

```
bash -c "$(curl -sL https://raw.githubusercontent.com/uerax/taffy-onekey/master/taffy.sh)" @ install
```

`一键安装 Hysteria`

```
bash -c "$(curl -sL https://raw.githubusercontent.com/uerax/taffy-onekey/master/taffy.sh)" @ hysteria
```

`完全卸载`

```
bash -c "$(curl -sL https://raw.githubusercontent.com/uerax/taffy-onekey/master/taffy.sh)" @ uninstall
```

## Script

实现一键安装的功能,只兼容 ubuntu 和 debian

现在已支持以下协议

- vless-tls-reality
- hysteria2
- trojan-tcp-tls
- trojan-tcp-tls-brutal
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