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

# vmess start
xray_vmess() {
    local item="$1"
    local type=$(echo "$item" | jq -r '.protocol')
    local password=$(echo "$item" | jq -r '.settings.clients[0].id')
    local method=$(echo "$item" | jq -r '.streamSettings.network')
    local port=443
    local path=$(echo "$item" | jq -r '.streamSettings.wsSettings.path')
    local domain=$ip
    local hq_ip="cloudflare.182682.xyz"

    local tmp="{\"v\":\"2\",\"ps\":\"${domain}\",\"add\":\"${domain}\",\"port\":\"443\",\"id\":\"${password}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${domain}\",\"path\":\"${path}\",\"tls\":\"tls\",\"sni\":\"${domain}\",\"alpn\":\"\",\"fp\":\"safari\"}"
    local encode_link=$(openssl base64 <<< $tmp)
    local link="vmess://$encode_link"

    local clash_cfg="  - name: $domain\n    type: vmess\n    server: '$domain'\n    port: 443\n    uuid: $password\n    alterId: 0\n    cipher: auto\n    udp: true\n    tls: true\n    network: ws\n    ws-opts:\n      path: \"${path}\"\n      headers:\n        Host: $domain"

    local qx_cfg="vmess=$domain:443, method=chacha20-poly1305, password=$password, obfs=wss, obfs-host=$domain, obfs-uri=${path}, tls13=true, fast-open=false, udp-relay=false, tag=$domain"

    
    vmess_info
    show_info
}

singbox_vmess() {
    local item="$1"
    local type=$(echo "$item" | jq -r '.type')
    local port=$(echo "$item" | jq -r '.listen_port')
    local password=$(echo "$item" | jq -r '.users[0].uuid')
    local domain=$(echo "$item" | jq -r '.tls.server_name')
    local method=$(echo "$item" | jq -r '.transport.type')
    local path=$(echo "$item" | jq -r '.transport.path')
    local hq_ip="cloudflare.182682.xyz"

    local tmp="{\"v\":\"2\",\"ps\":\"${domain}\",\"add\":\"${domain}\",\"port\":\"443\",\"id\":\"${password}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${domain}\",\"path\":\"${path}\",\"tls\":\"tls\",\"sni\":\"${domain}\",\"alpn\":\"\",\"fp\":\"safari\"}"
    local encode_link=$(openssl base64 <<< $tmp)
    local link="vmess://$encode_link"

    local clash_cfg="  - name: $domain\n    type: vmess\n    server: '$domain'\n    port: 443\n    uuid: $password\n    alterId: 0\n    cipher: auto\n    udp: true\n    tls: true\n    network: ws\n    ws-opts:\n      path: \"${path}\"\n      headers:\n        Host: $domain"

    local qx_cfg="vmess=$domain:443, method=chacha20-poly1305, password=$password, obfs=wss, obfs-host=$domain, obfs-uri=${path}, tls13=true, fast-open=false, udp-relay=false, tag=$domain"

    vmess_info
    show_info
}

vmess_info() {
    xray_outbound="{
    \"protocol\": \"vmess\",
    \"settings\": {
      \"vnext\": [
        {
          \"address\": \"${domain}\",
          \"port\": 443,
          \"users\": [
            {
              \"id\": \"${password}\",
              \"alterId\": 0,
              \"level\": 0,
              \"security\": \"auto\",
              \"email\": \"b@your.domain\"
            }
          ]
        }
      ]
    },
    \"streamSettings\": {
      \"network\": \"ws\",
      \"security\": \"tls\",
      \"tlsSettings\": {
        \"allowInsecure\": false,
        \"serverName\": \"${domain}\"
      },
      \"wsSettings\": {
        \"path\": \"${path}\",
        \"headers\": {
          \"Host\":\"${domain}\"
        }
      }
    }\n}"

    singbox_outbound="{
	\"type\": \"vmess\",
	\"server\": \"${domain}\",
	\"server_port\": 443,
	\"uuid\": \"${password}\",
	\"security\": \"auto\",
	\"alter_id\": 0,
	\"global_padding\": false,
	\"authenticated_length\": true,
	\"tls\": {
		\"enabled\": true,
		\"disable_sni\": false,
		\"server_name\": \"${domain}\",
		\"insecure\": false,
		\"alpn\": [
			\"http/1.1\"
		]
	},
	\"multiplex\": {
		\"enabled\": true,
		\"protocol\": \"smux\",
		\"max_connections\": 5,
		\"min_streams\": 4,
		\"max_streams\": 0
	},
	\"transport\": {
		\"type\": \"ws\",
		\"path\": \"${path}\",
		\"max_early_data\": 0,
		\"early_data_header_name\": \"Sec-WebSocket-Protocol\"
	},
	\"connect_timeout\": \"5s\"\n}"
}

# vmess end

# trojan start
singbox_trojan() {
    local item="$1"
    local type=$(echo "$item" | jq -r '.type')
    local password=$(echo "$item" | jq -r '.users[0].password')
    local port=$(echo "$item" | jq -r '.listen_port')
    local domain=$(echo "$item" | jq -r '.tls.server_name')

    local link="trojan://${password}@${domain}:${port}?security=tls&type=tcp&headerType=none#${domain}"

    local clash_cfg="  - name: $domain\n    type: trojan\n    server: '$domain'\n    port: $port\n    password: $password\n    alpn:\n      - h2\n      - http/1.1"

    local qx_cfg="trojan=$domain:$port, password=$password, over-tls=true, tls-host=$domain, tls-verification=true, tls13=true, fast-open=false, udp-relay=false, tag=$domain"

    show_info
}
# trojan end

# shadowsocket start
xray_shadowsocket() {
    local item="$1"
    local type=$(echo "$item" | jq -r '.protocol')
    local port=$(echo "$item" | jq -r '.port')
    local method=$(echo "$item" | jq -r '.settings.method')
    local password=$(echo "$item" | jq -r '.settings.password')
    
    shadowsocket_info
}

singbox_shadowsocket() {
    local item="$1"
    local type=$(echo "$item" | jq -r '.type')
    local port=$(echo "$item" | jq -r '.listen_port')
    local method=$(echo "$item" | jq -r '.method')
    local password=$(echo "$item" | jq -r '.password')
    
    shadowsocket_info
}

shadowsocket_info() {
    local xray_outbound="{
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
    local singbox_outbound="{
    \"type\": \"shadowsocks\",
    \"server\": \"${ip}\",
    \"server_port\": ${port},
    \"method\": \"${method}\",
    \"password\": \"${password}\"\n}"
    local qx_cfg="shadowsocks=$ip:$port, method=$method, password=$password, tag=$ip"
    local clash_cfg="  - name: $ip\n    type: ss\n    server: '$ip'\n    port: $port\n    cipher: $method\n    password: $password\n    udp: true"
    local tmp="${method}:${password}"
    tmp=$(openssl base64 <<< $tmp)
    local link="ss://$tmp@${ip}:${port}"
    
    show_info
}

# shadowsocket end

# vless start
singbox_vless() {
    local item="$1"
    local type=$(echo "$item" | jq -r '.type')
    local port=$(echo "$item" | jq -r '.listen_port')
    local password=$(echo "$item" | jq -r '.users[0].uuid')
    local reality=$(echo "$item" | jq -r '.tls.reality')
    if [ -n "$reality" ]; then
        local protocol=$(echo "$item" | jq -r '.transport.type')
        local pubkey=$(echo "$item" | jq -r '.users[0].name')
        local domain=$(echo "$item" | jq -r '.tls.server_name')
        local shortId=$(echo "$reality" | jq -r '.short_id[0]')
        if [ "$protocol" = "grpc" ]; then
            # reality+grpc
            local servName=$(echo "$item" | jq -r '.transport.service_name')
            local link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&sid=$shortId&fp=safari&pbk=$pubkey&type=$protocol&peer=$domain&allowInsecure=1&serviceName=$servName&mode=multi#$ip"
            local clash_cfg="  - name: $ip\n    type: vless\n    server: '$ip'\n    port: $port\n    uuid: $password\n    network: $protocol\n    tls: true\n    udp: true\n    # skip-cert-verify: true\n    servername: $domain\n    grpc-opts:\n      grpc-service-name: \"${servName}\"\n    reality-opts:\n      public-key: $pubkey\n      short-id: $shortId\n    client-fingerprint: safari"
            vless_reality_grpc_outbound_config
        elif [ "$protocol" = "http" ]; then
            # reality+h2
            local link="vless://$password@$ip:$port?encryption=none&security=reality&sid=$shortId&sni=$domain&fp=safari&pbk=$pubkey&type=http#$ip"
            local clash_cfg="  - name: $ip\n    type: vless\n    server: '$ip'\n    port: $port\n    uuid: $password\n    tls: true\n    udp: true\n    network: h2\n    flow: ''\n    servername: $domain\n    reality-opts:\n      public-key: $pubkey\n      short-id: $shortId\n    client-fingerprint: safari"
            vless_reality_h2_outbound_config
        else
            # reality+tcp
            local link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&fp=safari&sid=$shortId&pbk=$pubkey&type=tcp&headerType=none#$ip"
            local clash_cfg="  - name: $ip\n    type: vless\n    server: '$ip'\n    port: $port\n    uuid: $password\n    network: tcp\n    tls: true\n    udp: true\n    servername: $domain\n    reality-opts:\n      public-key: $pubkey\n      short-id: $shortId\n    client-fingerprint: safari"
            vless_reality_tcp_outbound_config
        fi
    else
        echo ""
    fi
}

xray_vless() {
    local item="$1"
    local type=$(echo "$item" | jq -r '.protocol')
    local port=$(echo "$item" | jq -r '.port')
    local password=$(echo "$item" | jq -r '.settings.clients[0].id')
    local reality=$(echo "$item" | jq -r '.streamSettings.security')
    if [ "$reality" = "reality" ]; then
        local protocol=$(echo "$item" | jq -r '.streamSettings.network')
        local pubkey=$(echo "$item" | jq -r '.key')
        local domain=$(echo "$item" | jq -r '.streamSettings.realitySettings.serverNames[0]')
        local shortId=$(echo "$item" | jq -r '.streamSettings.realitySettings.shortIds[0]')
        if [ "$protocol" = "grpc" ]; then
            local servName=$(echo "$item" | jq -r '.streamSettings.grpcSettings.serviceName')
            local link="vless://$password@$ip:$port?encryption=none&security=$reality&sni=$domain&sid=$shortId&fp=safari&pbk=$pubkey&type=$protocol&peer=$domain&allowInsecure=1&serviceName=$servName&mode=multi#$ip"
            local clash_cfg="  - name: $ip\n    type: vless\n    server: '$ip'\n    port: $port\n    uuid: $password\n    network: $protocol\n    tls: true\n    udp: true\n    # skip-cert-verify: true\n    servername: $domain\n    grpc-opts:\n      grpc-service-name: \"${servName}\"\n    reality-opts:\n      public-key: $pubkey\n      short-id: $shortId\n    client-fingerprint: safari"
            vless_reality_grpc_outbound_config
        elif [ "$protocol" = "h2" ]; then
            local link="vless://$password@$ip:$port?encryption=none&security=$reality&sid=$shortId&sni=$domain&fp=safari&pbk=$pubkey&type=http#$ip"
            local clash_cfg="  - name: $ip\n    type: vless\n    server: '$ip'\n    port: $port\n    uuid: $password\n    tls: true\n    udp: true\n    network: h2\n    flow: ''\n    servername: $domain\n    reality-opts:\n      public-key: $pubkey\n      short-id: $shortId\n    client-fingerprint: safari"        
            vless_reality_h2_outbound_config
        else
            # reality+tcp
            local link="vless://$password@$ip:$port?encryption=none&security=$reality&sni=$domain&fp=safari&sid=$shortId&pbk=$pubkey&type=tcp&headerType=none#$ip"
            local clash_cfg="  - name: $ip\n    type: vless\n    server: '$ip'\n    port: $port\n    uuid: $password\n    network: tcp\n    tls: true\n    udp: true\n    servername: $domain\n    reality-opts:\n      public-key: $pubkey\n      short-id: $shortId\n    client-fingerprint: safari"
            vless_reality_tcp_outbound_config
        fi
    else
        echo ""
    fi
}

vless_reality_h2_outbound_config() {
    local xray_outbound="{
    \"protocol\": \"vless\",
    \"settings\": {
        \"vnext\": [
            {
                \"address\": \"${ip}\",
                \"port\": ${port},
                \"users\": [
                    {
                        \"id\": \"${password}\",
                        \"encryption\": \"none\"
                    }
                ]
            }
        ]
    },
    \"streamSettings\": {
        \"network\": \"h2\",
        \"security\": \"reality\",
        \"realitySettings\": {
            \"show\": false,
            \"fingerprint\": \"safari\",
            \"serverName\": \"${domain}\",
            \"publicKey\": \"${pubkey}\",
            \"shortId\": \"${shortId}\",
            \"spiderX\": \"/\"
        }
    }\n}"

    show_info
}

vless_reality_tcp_outbound_config() {
    local xray_outbound="{
    \"protocol\": \"vless\",
    \"settings\": {
        \"vnext\": [
            {
                \"address\": \"${ip}\",
                \"port\": ${port},
                \"users\": [
                    {
                        \"id\": \"${password}\",
                        \"encryption\": \"none\"
                    }
                ]
            }\
        ]
    },
    \"streamSettings\": {
        \"network\": \"tcp\",
        \"security\": \"reality\",
        \"realitySettings\": {
            \"show\": false,
            \"fingerprint\": \"safari\",
            \"serverName\": \"${domain}\",
            \"publicKey\": \"${pubkey}\",
            \"shortId\": \"${shortId}\",
            \"spiderX\": \"/\"
        }
    }\n}"

    show_info
}

vless_reality_grpc_outbound_config() {
    local xray_outbound="{
    \"protocol\": \"vless\",
    \"settings\": {
        \"vnext\": [
            {
                \"address\": \"${ip}\",
                \"port\": ${port},
                \"users\": [
                    {
                        \"id\": \"${password}\",
                        \"encryption\": \"none\"
                    }
                ]
            }
        ]
    },
    \"streamSettings\": {
        \"network\": \"grpc\",
        \"security\": \"reality\",
        \"realitySettings\": {
            \"fingerprint\": \"safari\",
            \"serverName\": \"${domain}\",
            \"publicKey\": \"${pubkey}\",
            \"shortId\": \"${shortId}\"
        },
        \"grpcSettings\": {
            \"serviceName\": \"${servName}\",
            \"multiMode\": true,
            \"idle_timeout\": 60,
            \"health_check_timeout\": 20
        }
    }\n}"

    local singbox_outbound="{
      \"type\": \"vless\",
      \"server\": \"${ip}\",
      \"server_port\": ${port},
      \"uuid\": \"${password}\",
      \"network\": \"tcp\",
      \"tls\": {
        \"enabled\": true,
        \"server_name\": \"${domain}\",
        \"utls\": {
          \"enabled\": true,
          \"fingerprint\": \"chrome\"
        },
        \"reality\": {
          \"enabled\": true,
          \"public_key\": \"${pubkey}\",
          \"short_id\": \"${shortId}\"
        }
      },
      \"transport\": {
        \"type\": \"grpc\",
        \"service_name\": \"${servName}\"
      }\n}"

    show_info
}
# vless end

# hysteria2 start
singbox_hy2() {
    local item="$1"
    local type=$(echo "$item" | jq -r '.type')
    local port=$(echo "$item" | jq -r '.listen_port')
    local up=$(echo "$item" | jq -r '.up_mbps')
    local down=$(echo "$item" | jq -r '.down_mbps')
    local password=$(echo "$item" | jq -r '.users[0].password')
    
    local link="hysteria2://${password}@${ip}:${port}?peer=https://live.qq.com&insecure=1&obfs=none#${ip}"

    local clash_cfg="  - name: $ip\n    type: hysteria2\n    server: '$ip'\n    port: $port\n    up: $down Mbps\n    down: $up Mbps\n    password: $password\n    sni: https://live.qq.com\n    skip-cert-verify: true\n    alpn:\n      - h3"

    singbox_hy2_outbound_config
}

singbox_hy2_outbound_config() {
    local singbox_outbound="  {
    \"type\": \"hysteria2\",
    \"server\": \"${ip}\",
    \"server_port\": ${port},
    \"network\": \"tcp\",
    \"tls\": {
      \"enabled\": true,
      \"disable_sni\": false,
      \"server_name\": \"https://live.qq.com\",
      \"insecure\": true,
      \"utls\": {
        \"enabled\": false,
        \"fingerprint\": \"chrome\"
      }
    },
    \"password\": \"${password}\"\n  }"
    
    show_info
}

# hysteria2 end
xray_range() {

    if [ ! -e "$xray_cfg" ]; then
        echo "Xray Config does not exist. Exiting."
        exit 1  # 非零的退出状态表示异常退出
    fi

    ip=$(curl -s4 --connect-timeout 4 https://ip.me)
    ipv6=$(curl -s6 --connect-timeout 4 https://ip.me)
    if [ ! -n "$ip" ]; then
        ip=$ipv6
    fi
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
            "vmess")
                xray_vmess "$inbound"
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

    ip=$(curl -s4 --connect-timeout 4 https://ip.me)
    ipv6=$(curl -s6 --connect-timeout 4 https://ip.me)
    if [ ! -n "$ip" ]; then
        ip=$ipv6
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
            "vmess")
                singbox_vmess "$inbound"
                ;;
            "trojan")
                singbox_trojan "$inbound"
                ;;
            *)
                ;;
        esac
    done
}

show_info() {
    echo -e "${Cyan}------------------------------------------------------------${Font}"
    echo -e "${Cyan}--------------------------配置开始--------------------------${Font}"
    echo -e "${Cyan}------------------------------------------------------------${Font}"
    echo -e "${Green}协议:${Font} ${type}"
    echo -e "${Green}地址:${Font} ${ip}"
    if [ -n "$ipv6" ]; then
        echo -e "${Green}地址IPv6:${Font} ${ipv6}"
    fi
    if [ -n "$hq_ip" ]; then
        echo -e "${Green}cloudflare优选地址:${Font} ${hq_ip}"
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
        echo -e "------------------------------------------------------------"
        echo -e "${Green}QuantumultX配置:${Font}"
        echo -e "${qx_cfg}"
    fi
    if [ -n "$xray_outbound" ]; then
        echo -e "------------------------------------------------------------"
        echo -e "${Green}Xray Outbounds配置:${Font}"
        echo -e "${xray_outbound}"
    fi
    if [ -n "$singbox_outbound" ]; then
        echo -e "------------------------------------------------------------"
        echo -e "${Green}Singbox Outbounds配置:${Font}"
        echo -e "${singbox_outbound}"
    fi
    if [ -n "$clash_cfg" ]; then
        echo -e "------------------------------------------------------------"
        echo -e "${Green}Clash配置:${Font}"
        echo -e "${clash_cfg}"
    fi
    echo -e "${Cyan}------------------------------------------------------------${Font}"
    echo -e "${Cyan}--------------------------配置结束--------------------------${Font}"
    echo -e "${Cyan}------------------------------------------------------------${Font}"
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
