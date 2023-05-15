简单自用脚本,实现一键安装的功能,目前只兼容 ubuntu 和 debian

现在已支持以下协议

- trojan-tcp-tls
- trojan-grpc
- vmess-ws-tls
- vless-ws-tls
- vless-grpc
- vless-tcp-xtls-vision
- shadowsocket-2022

直接复制下面命令执行
```
wget -N --no-check-certificate -q -O xray.sh "https://raw.githubusercontent.com/uerax/xray-script/master/xray.sh" && chmod +x xray.sh && bash xray.sh
```

