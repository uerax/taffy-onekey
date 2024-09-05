amd="https://gh-proxy.com/https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
arm="https://gh-proxy.com/https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-arm64-v8a.zip"
link=""

case "$(uname -m)" in
    'armv8' | 'aarch64')
      link=${arm}
      ;;
    *)
      link=${amd}
      ;;
esac

mkdir -p /root/xray
cd /root/xray

wget ${link} -O Xray-linux.zip

unzip Xray-linux.zip

mv xray /usr/local/bin/
rm -r /root/xray
mkdir -p /usr/local/etc/xray

cat > /etc/systemd/system/xray.service << EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload