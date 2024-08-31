#!/usr/bin/env bash

singbox_cfg="/etc/sing-box/config.json"
xray_cfg="/usr/local/etc/xray/config.json"

xray_outbound=""
singbox_outbound=""

#vmess() {}

singbox_shadowsocket() {
    local item="$1"
    type=$(echo "$item" | jq -r '.type')
    port=$(echo "$item" | jq -r '.listen_port')
    method=$(echo "$item" | jq -r '.method')
    password=$(echo "$item" | jq -r '.password')
    shadowsocket_info
}

shadowsocket_info() {
    ip=$(curl -s https://ip.me)
    ipv6=$(curl -s6 https://ip.me)
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
    clash_cfg="  - name: $ip
    type: ss
    server: '$ip'
    port: $port
    cipher: $method
    password: $password
    udp: true"
    tmp="${ss_method}:${password}"
    tmp=$(base64 <<< $tmp)
    link="ss://$tmp@${ip}:${port}"
    
    show_info
}


xray_range() {

    if [ ! -e "$xray_cfg" ]; then
        echo "Xray Config does not exist. Exiting."
        exit 1  # 非零的退出状态表示异常退出
    fi

    # 遍历 JSON 数组并调用相应函数
    jq -c '.inbounds[]' $xray_cfg | while read -r inbound; do
        type=$(echo "$inbound" | jq -r '.protocol')

        case "$type" in
            "shadowsocks")
                process_apple "$inbound"
                ;;
            "banana")
                process_banana "$inbound"
                ;;
            "cherry")
                process_cherry "$inbound"
                ;;
            *)
                echo "Unknown item: $inbound"
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
            "banana")
                process_banana "$inbound"
                ;;
            "cherry")
                process_cherry "$inbound"
                ;;
            *)
                echo "Unknown item: $inbound"
                ;;
        esac
    done
}

show_info() {
    echo -e "------------------------------------------------"
    echo -e "------------------------------------------------"
    echo -e "------------------------------------------------"
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
        echo -e "------------------------------------------------"
        echo -e "${Green}QuantumultX配置:${Font}"
        echo -e "${qx_cfg}"
    fi
    if [ -n "$xray_outbound" ]; then
        echo -e "------------------------------------------------"
        echo -e "${Green}Xray Outbounds配置:${Font}"
        echo -e "${xray_outbound}"
    fi
    if [ -n "$singbox_outbound" ]; then
        echo -e "------------------------------------------------"
        echo -e "${Green}Singbox Outbounds配置:${Font}"
        echo -e "${singbox_outbound}"
    fi
    if [ -n "$clash_cfg" ]; then
        echo -e "------------------------------------------------"
        echo -e "${Green}Clash配置:${Font}"
        echo -e "${clash_cfg}"
    fi
    echo -e "------------------------------------------------"
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
