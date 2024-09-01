#!/usr/bin/env bash

#fonts color
Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
Blue='\033[0;34m'         # Blue
Purple='\033[0;35m'       # Purple
Cyan='\033[0;36m'         # Cyan
White='\033[0;37m'
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
Font="\033[0m"

singbox_cfg="/etc/sing-box/config.json"
xray_cfg="/usr/local/etc/xray/config.json"

xray_outbound=""
singbox_outbound=""

#vmess() {}

# shadowsocket start

xray_shadowsocket() {
    local item="$1"
    type=$(echo "$item" | jq -r '.protocol')
    port=$(echo "$item" | jq -r '.port')
    method=$(echo "$item" | jq -r '..settings.method')
    password=$(echo "$item" | jq -r '.settings.password')
    
    shadowsocket_info
}

singbox_shadowsocket() {
    local item="$1"
    type=$(echo "$item" | jq -r '.type')
    port=$(echo "$item" | jq -r '.listen_port')
    method=$(echo "$item" | jq -r '.method')
    password=$(echo "$item" | jq -r '.password')
    
    shadowsocket_info
}

shadowsocket_info() {
    xray_outbound="{
    \"protocol\": \"shadowsocks\",
    \"settings\": {
        \"servers\": [
            {
                \"address\": \"${ip}\",
                \"port\": ${port},
                \"method\": \"${method}\",
                \"password\": \"${password}\"
            }
        ]
    }\n}"
    singbox_outbound="{
    \"type\": \"shadowsocks\",
    \"server\": \"${ip}\",
    \"server_port\": ${port},
    \"method\": \"${method}\",
    \"password\": \"${password}\"\n}"
    qx_cfg="shadowsocks=$ip:$port, method=$method, password=$password, tag=$ip"
    clash_cfg="  - name: $ip\n    type: ss\n    server: '$ip'\n    port: $port\n    cipher: $method\n    password: $password\n    udp: true"
    tmp="${ss_method}:${password}"
    tmp=$(base64 <<< $tmp)
    link="ss://$tmp@${ip}:${port}"
    
    show_info
}

# shadowsocket end

# vless start
singbox_vless() {
    local item="$1"
    type=$(echo "$item" | jq -r '.type')
    port=$(echo "$item" | jq -r '.listen_port')
    password=$(echo "$item" | jq -r '.users[0].uuid')
    reality=$(echo "$item" | jq -r '.tls.reality')
    if [ -e "$reality" ]; then
        protocol=$(echo "$reality" | jq -r '.transport.type')
        pubkey=$(echo "$item" | jq -r '.users[0].name')
        domain=$(echo "$item" | jq -r '.tls.server_name')
        shortId=$(echo "$reality" | jq -r '.short_id[0]')
        if [ "$protocol" = "grpc" ]; then
            # reality+grpc
            servName=$(echo "$reality" | jq -r '.transport.service_name')
            link="vless://$password@$ip:$port?encryption=none&security=$reality&sni=$domain&sid=$shortId&fp=safari&pbk=$pubkey&type=$protocol&peer=$domain&allowInsecure=1&serviceName=$servName&mode=multi#$ip"
            clash_cfg="  - name: $ip\n    type: vless\n    server: '$ip'\n    port: $port\n    uuid: $password\n    network: $protocol\n    tls: true\n    udp: true\n    # skip-cert-verify: true\n    servername: $domain\n    grpc-opts:\n      grpc-service-name: \"${servName}\"\n    reality-opts:\n      public-key: $pubkey\n      short-id: $shortId\n    client-fingerprint: safari"
        elif [ "$protocol" = "http" ]; then
            # reality+h2
            link="vless://$password@$ip:$port?encryption=none&security=$reality&sid=$shortId&sni=$domain&fp=safari&pbk=$pubkey&type=http#$ip"
            clash_cfg="  - name: $ip\n    type: vless\n    server: '$ip'\n    port: $port\n    uuid: $password\n    tls: true\n    udp: true\n    network: h2\n    flow: ''\n    servername: $domain\n    reality-opts:\n      public-key: $pubkey\n      short-id: $shortId\n    client-fingerprint: safari"
        else
            # reality+tcp
            link="vless://$password@$ip:$port?encryption=none&flow=xtls-rprx-vision&security=$reality&sni=$domain&fp=safari&sid=$shortId&pbk=$pubkey&type=tcp&headerType=none#$ip"
            clash_cfg="  - name: $ip\n    type: vless\n    server: '$ip'\n    port: $port\n    uuid: $password\n    network: tcp\n    tls: true\n    udp: true\n    flow: xtls-rprx-vision\n    servername: $domain\n    reality-opts:\n      public-key: $pubkey\n      short-id: $shortId\n    client-fingerprint: safari"
        fi
        show_info
    else
        echo ""
    fi
}

xray_vless() {
    local item="$1"
    type=$(echo "$item" | jq -r '.protocol')
    port=$(echo "$item" | jq -r '.listen_port')
    password=$(echo "$item" | jq -r '.clients[0].id')
    reality=$(echo "$item" | jq -r '.streamSettings.security')
    if [ "$reality" = "reality" ]; then
        protocol=$(echo "$item" | jq -r '.streamSettings.network')
        pubkey=$(echo "$item" | jq -r '.key')
        domain=$(echo "$item" | jq -r '.streamSettings.realitySettings.serverNames[0]')
        shortId=$(echo "$reality" | jq -r '.streamSettings.realitySettings.shortIds[0]')
        if [ "$protocol" = "grpc" ]; then
            servName=$(echo "$item" | jq -r '.streamSettings.grpcSettings.serviceName')
            link="vless://$password@$ip:$port?encryption=none&security=$reality&sni=$domain&sid=$shortId&fp=safari&pbk=$pubkey&type=$protocol&peer=$domain&allowInsecure=1&serviceName=$servName&mode=multi#$ip"
            clash_cfg="  - name: $ip\n    type: vless\n    server: '$ip'\n    port: $port\n    uuid: $password\n    network: $protocol\n    tls: true\n    udp: true\n    # skip-cert-verify: true\n    servername: $domain\n    grpc-opts:\n      grpc-service-name: \"${servName}\"\n    reality-opts:\n      public-key: $pubkey\n      short-id: $shortId\n    client-fingerprint: safari"
        elif [ "$protocol" = "h2" ]; then
            link="vless://$password@$ip:$port?encryption=none&security=$reality&sid=$shortId&sni=$domain&fp=safari&pbk=$pubkey&type=http#$ip"
            clash_cfg="  - name: $ip\n    type: vless\n    server: '$ip'\n    port: $port\n    uuid: $password\n    tls: true\n    udp: true\n    network: h2\n    flow: ''\n    servername: $domain\n    reality-opts:\n      public-key: $pubkey\n      short-id: $shortId\n    client-fingerprint: safari"        
        else
            # reality+tcp
            link="vless://$password@$ip:$port?encryption=none&flow=xtls-rprx-vision&security=$reality&sni=$domain&fp=safari&sid=$shortId&pbk=$pubkey&type=tcp&headerType=none#$ip"
            clash_cfg="  - name: $ip\n    type: vless\n    server: '$ip'\n    port: $port\n    uuid: $password\n    network: tcp\n    tls: true\n    udp: true\n    flow: xtls-rprx-vision\n    servername: $domain\n    reality-opts:\n      public-key: $pubkey\n      short-id: $shortId\n    client-fingerprint: safari"
        fi
        show_info
    else
        echo ""
    fi
}
# vless end

# hysteria2 start
singbox_hy2() {
    local item="$1"
    type=$(echo "$item" | jq -r '.type')
    port=$(echo "$item" | jq -r '.listen_port')
    up=$(echo "$item" | jq -r '.up_mbps')
    down=$(echo "$item" | jq -r '.down_mbps')
    password=$(echo "$item" | jq -r '.users[0].uuid')
    
    link="hysteria2://${password}@${ip}:${port}?peer=https://live.qq.com&insecure=1&obfs=none#${ip}"

    clash_cfg="  - name: $ip\n    type: hysteria2\n    server: '$ip'\n    port: $port\n    up: $down Mbps\n    down: $up Mbps\n    password: $password\n    sni: https://live.qq.com\n    skip-cert-verify: true\n    alpn:\n      - h3"

    show_info
}

# hysteria2 end


xray_range() {

    if [ ! -e "$xray_cfg" ]; then
        echo "Xray Config does not exist. Exiting."
        exit 1  # 非零的退出状态表示异常退出
    fi

    ip=$(curl -s4 https://ip.me)
    ipv6=$(curl -s6 https://ip.me)
    # 遍历 JSON 数组并调用相应函数
    jq -c '.inbounds[]' $xray_cfg | while read -r inbound; do
        type=$(echo "$inbound" | jq -r '.protocol')
        case "$type" in
            "shadowsocks")
                xray_shadowsocket "$inbound"
                ;;
            "vless")
                xray_vless "$inbound"
                ;;
            *)
                ;;
        esac
    done
    
}

singbox_range() {

    if [ ! -e "$singbox_cfg" ]; then
        echo "Singbox Config does not exist. Exiting."
        exit 1  # 非零的退出状态表示异常退出
    fi

    # 遍历 JSON 数组并调用相应函数
    jq -c '.inbounds[]' $singbox_cfg | while read -r inbound; do
        type=$(echo "$inbound" | jq -r '.type')

        case "$type" in
            "shadowsocks")
                singbox_shadowsocket "$inbound"
                ;;
            "vless")
                singbox_vless "$inbound"
                ;;
            "hysteria2")
                singbox_hy2 "$inbound"
                ;;
            *)
                ;;
        esac
    done
}

show_info() {
    echo -e "--------------------------------------------------------------------"
    echo -e "--------------------------------------------------------------------"
    echo -e "--------------------------------------------------------------------"
    echo -e "${Green}协议:${Font} ${type}"
    echo -e "${Green}地址:${Font} ${ip}"
    if [ -n "$ipv6" ]; then
        echo -e "${Green}地址IPv6:${Font} ${ipv6}"
    fi
    echo -e "${Green}密码:${Font} ${password}"
    echo -e "${Green}端口:${Font} ${port}"
    # echo -e "${Green}混淆:${Font} ${XRAY_OBFS}"
    # echo -e "${Green}混淆路径:${Font} ${OBFS_PATH}"
    # echo -e "${Green}PubKey(REALITY):${Font} ${XRAY_KEY}"
    if [ -n "$link" ]; then
        echo -e "${Green}分享链接:${Font} ${link}"
    fi
    if [ -n "$qx_cfg" ]; then
        echo -e "--------------------------------------------------------------------"
        echo -e "${Green}QuantumultX配置:${Font}"
        echo -e "${qx_cfg}"
    fi
    if [ -n "$xray_outbound" ]; then
        echo -e "-------------------------------------------------------------------"
        echo -e "${Green}Xray Outbounds配置:${Font}"
        echo -e "${xray_outbound}"
    fi
    if [ -n "$singbox_outbound" ]; then
        echo -e "------------------------------------------------"
        echo -e "${Green}Singbox Outbounds配置:${Font}"
        echo -e "${singbox_outbound}"
    fi
    if [ -n "$clash_cfg" ]; then
        echo -e "--------------------------------------------------------------------"
        echo -e "${Green}Clash配置:${Font}"
        echo -e "${clash_cfg}"
    fi
    echo -e "--------------------------------------------------------------------"
}

xray_run() {
    xray_range
}

singbox_run() {
    singbox_range
}

case $1 in
    singbox)
        singbox_run
        ;;
    xray)
        xray_run
        ;;
    *)
        singbox_run
        ;;
esac