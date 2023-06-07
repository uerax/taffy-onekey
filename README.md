## Usage

__保存脚本执行__

```
wget -N --no-check-certificate -q -O xray.sh "https://raw.githubusercontent.com/uerax/xray-script/master/xray.sh" && chmod +x xray.sh && bash xray.sh
```

__不保存脚本执行__

```
bash -c "$(curl -L https://raw.githubusercontent.com/uerax/xray-script/master/xray.sh)" @
```

## Script

自用脚本,实现一键安装的功能,只兼容 ubuntu 和 debian

现在已支持以下协议

- vless-grpc-reality(推荐)
- vless-tls-reality(推荐)
- trojan-tcp-tls(推荐)
- trojan-grpc
- vmess-ws-tls
- vless-ws-tls
- vless-grpc
- vless-tcp-xtls-vision
- shadowsocket-2022


