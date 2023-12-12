## Usage

__保存脚本执行__

```
wget -N --no-check-certificate -q -O taffy.sh "https://raw.githubusercontent.com/uerax/taffy-onekey/master/taffy.sh" && chmod +x taffy.sh && bash taffy.sh
```

__不保存脚本执行__

```
bash -c "$(curl -L https://raw.githubusercontent.com/uerax/taffy-onekey/master/taffy.sh)" @
```

__国内机器__

```
wget -N --no-check-certificate -q -O taffy.sh "https://mirror.ghproxy.com/https://raw.githubusercontent.com/uerax/taffy-onekey/master/taffy-cn.sh" && chmod +x taffy.sh && bash taffy.sh
```

`一键安装`

```
bash -c "$(curl -L https://raw.githubusercontent.com/uerax/taffy-onekey/master/taffy.sh)" @ install
```

`完全卸载`

```
bash -c "$(curl -L https://raw.githubusercontent.com/uerax/taffy-onekey/master/taffy.sh)" @ uninstall
```

## Script

实现一键安装的功能,只兼容 ubuntu 和 debian

现在已支持以下协议

- vless-tls-reality(推荐)
- hysteria2(推荐)
- trojan-tcp-tls(推荐)
- vless-grpc-reality(推荐)
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