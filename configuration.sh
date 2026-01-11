#!/bin/sh

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
mihomo_cfg="/etc/mihomo/config.yaml"

yq_install_url="https://github.com/uerax/taffy-onekey/raw/master/install-yq.sh"

xray_outbound=""
singbox_outbound=""

yq_install() {
    if ! command -v yq >/dev/null 2>&1; then
        if command -v apk >/dev/null 2>&1; then
            printf "Alpine 环境：直接通过 apk 安装 yq...\n"
            apk add --no-cache yq
        else
            # 其他系统（Ubuntu/CentOS）再跑你的远程脚本
            printf "正在通过远程脚本安装 yq ...\n"
            curl -fsSL "$yq_install_url" | bash || curl -fsSL "$yq_install_url" | sh
        fi
    else
        printf "yq 已安装\n"
    fi
}

# vmess start
xray_vmess() {
    local item="$1"
    local type=$(printf "%s" "$item" | jq -r '.protocol')
    local password=$(printf "%s" "$item" | jq -r '.settings.clients[0].id')
    local method=$(printf "%s" "$item" | jq -r '.streamSettings.network')
    local port=443
    local path=$(printf "%s" "$item" | jq -r '.streamSettings.wsSettings.path')
    local domain=$ip
    local hq_ip="cloudflare.182682.xyz"

    local tmp="{\"v\":\"2\",\"ps\":\"${domain}\",\"add\":\"${domain}\",\"port\":\"443\",\"id\":\"${password}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${domain}\",\"path\":\"${path}\",\"tls\":\"tls\",\"sni\":\"${domain}\",\"alpn\":\"\",\"fp\":\"safari\"}"
    #local encode_link=$(openssl base64 <<< $tmp)
    local encode_link=$(printf "%s" "$tmp" | openssl base64 | tr -d '\n')
    local link="vmess://$encode_link"

    local clash_cfg="  - name: $domain\n    type: vmess\n    server: '$domain'\n    port: 443\n    uuid: $password\n    alterId: 0\n    cipher: auto\n    udp: true\n    tls: true\n    network: ws\n    ws-opts:\n      path: \"${path}\"\n      headers:\n        Host: $domain"

    local qx_cfg="vmess=$domain:443, method=chacha20-poly1305, password=$password, obfs=wss, obfs-host=$domain, obfs-uri=${path}, tls13=true, fast-open=false, udp-relay=false, tag=$domain"

    
    vmess_info
    show_info
}

singbox_vmess() {
    local item="$1"
    local type=$(printf "%s" "$item" | jq -r '.type')
    local port=$(printf "%s" "$item" | jq -r '.listen_port')
    local password=$(printf "%s" "$item" | jq -r '.users[0].uuid')
    local domain=$(printf "%s" "$item" | jq -r '.tls.server_name')
    local method=$(printf "%s" "$item" | jq -r '.transport.type')
    local path=$(printf "%s" "$item" | jq -r '.transport.path')
    local hq_ip="cloudflare.182682.xyz"

    local tmp="{\"v\":\"2\",\"ps\":\"${domain}\",\"add\":\"${domain}\",\"port\":\"443\",\"id\":\"${password}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${domain}\",\"path\":\"${path}\",\"tls\":\"tls\",\"sni\":\"${domain}\",\"alpn\":\"\",\"fp\":\"safari\"}"
    #local encode_link=$(openssl base64 <<< $tmp)
    local encode_link=$(printf "%s" "$tmp" | openssl base64 | tr -d '\n')
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
    local type=$(printf "%s" "$item" | jq -r '.type')
    local password=$(printf "%s" "$item" | jq -r '.users[0].password')
    local port=$(printf "%s" "$item" | jq -r '.listen_port')
    local domain=$(printf "%s" "$item" | jq -r '.tls.server_name')

    local link="trojan://${password}@${domain}:${port}?security=tls&type=tcp&headerType=none#${domain}"

    local clash_cfg="  - name: $domain\n    type: trojan\n    server: '$domain'\n    port: $port\n    password: $password\n    alpn:\n      - h2\n      - http/1.1"

    local qx_cfg="trojan=$domain:$port, password=$password, over-tls=true, tls-host=$domain, tls-verification=true, tls13=true, fast-open=false, udp-relay=false, tag=$domain"

    show_info
}
# trojan end

# shadowsocket start
xray_shadowsocket() {
    local item="$1"
    local type=$(printf "%s" "$item" | jq -r '.protocol')
    local port=$(printf "%s" "$item" | jq -r '.port')
    local method=$(printf "%s" "$item" | jq -r '.settings.method')
    local password=$(printf "%s" "$item" | jq -r '.settings.password')
    
    shadowsocket_info
}

singbox_shadowsocket() {
    local item="$1"
    local type=$(printf "%s" "$item" | jq -r '.type')
    local port=$(printf "%s" "$item" | jq -r '.listen_port')
    local method=$(printf "%s" "$item" | jq -r '.method')
    local password=$(printf "%s" "$item" | jq -r '.password')
    
    shadowsocket_info
}

mihomo_shadowsocket() {
    local item="$1"
    local type=$(yq -r ".listeners[$item].type" $mihomo_cfg)
    local port=$(yq -r ".listeners[$item].port" $mihomo_cfg)
    local method=$(yq -r ".listeners[$item].cipher" $mihomo_cfg)
    local password=$(yq -r ".listeners[$item].password" $mihomo_cfg)

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
    #tmp=$(openssl base64 <<< $tmp)
    tmp=$(printf "%s" "$tmp" | openssl base64 | tr -d '\n')
    local link="ss://$tmp@${ip}:${port}"
    
    show_info
}

# shadowsocket end

# vless start
singbox_vless() {
    local item="$1"
    local type=$(printf "%s" "$item" | jq -r '.type')
    local port=$(printf "%s" "$item" | jq -r '.listen_port')
    local password=$(printf "%s" "$item" | jq -r '.users[0].uuid')
    local reality=$(printf "%s" "$item" | jq -r '.tls.reality')
    if [ -n "$reality" ]; then
        local protocol=$(printf "%s" "$item" | jq -r '.transport.type')
        local pubkey=$(printf "%s" "$item" | jq -r '.users[0].name')
        local domain=$(printf "%s" "$item" | jq -r '.tls.server_name')
        local shortId=$(printf "%s" "$reality" | jq -r '.short_id[0]')
        if [ "$protocol" = "grpc" ]; then
            # reality+grpc
            local servName=$(printf "%s" "$item" | jq -r '.transport.service_name')
            local link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&sid=$shortId&fp=safari&pbk=$pubkey&type=$protocol&peer=$domain&allowInsecure=1&serviceName=$servName&mode=multi#$ip"
            local clash_cfg="  - name: $ip\n    type: vless\n    server: '$ip'\n    port: $port\n    uuid: $password\n    network: $protocol\n    tls: true\n    udp: true\n    packet-encoding: xudp\n    # skip-cert-verify: true\n    servername: $domain\n    grpc-opts:\n      grpc-service-name: \"${servName}\"\n    reality-opts:\n      public-key: $pubkey\n      short-id: $shortId\n    client-fingerprint: safari"
            vless_reality_grpc_outbound_config
        elif [ "$protocol" = "http" ]; then
            # reality+h2
            local link="vless://$password@$ip:$port?encryption=none&security=reality&sid=$shortId&sni=$domain&fp=safari&pbk=$pubkey&type=http#$ip"
            local clash_cfg="  - name: $ip\n    type: vless\n    server: '$ip'\n    port: $port\n    uuid: $password\n    tls: true\n    udp: true\n    packet-encoding: xudp\n    network: h2\n    flow: ''\n    servername: $domain\n    reality-opts:\n      public-key: $pubkey\n      short-id: $shortId\n    client-fingerprint: safari"
            vless_reality_h2_outbound_config
        else
            # reality+tcp
            local link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&fp=safari&sid=$shortId&pbk=$pubkey&type=tcp&headerType=none#$ip"
            local clash_cfg="  - name: $ip\n    type: vless\n    server: '$ip'\n    port: $port\n    uuid: $password\n    network: tcp\n    tls: true\n    udp: true\n    packet-encoding: xudp\n    servername: $domain\n    reality-opts:\n      public-key: $pubkey\n      short-id: $shortId\n    client-fingerprint: safari"
            vless_reality_tcp_outbound_config
        fi
    else
        printf "%s" ""
    fi
}

xray_vless() {
    local item="$1"
    local type=$(printf "%s" "$item" | jq -r '.protocol')
    local port=$(printf "%s" "$item" | jq -r '.port')
    local password=$(printf "%s" "$item" | jq -r '.settings.clients[0].id')
    local reality=$(printf "%s" "$item" | jq -r '.streamSettings.security')
    if [ "$reality" = "reality" ]; then
        local protocol=$(printf "%s" "$item" | jq -r '.streamSettings.network')
        local pubkey=$(printf "%s" "$item" | jq -r '.key')
        local domain=$(printf "%s" "$item" | jq -r '.streamSettings.realitySettings.serverNames[0]')
        local shortId=$(printf "%s" "$item" | jq -r '.streamSettings.realitySettings.shortIds[0]')
        if [ "$protocol" = "grpc" ]; then
            local servName=$(printf "%s" "$item" | jq -r '.streamSettings.grpcSettings.serviceName')
            local link="vless://$password@$ip:$port?encryption=none&security=$reality&sni=$domain&sid=$shortId&fp=safari&pbk=$pubkey&type=$protocol&peer=$domain&allowInsecure=1&serviceName=$servName&mode=multi#$ip"
            local clash_cfg="  - name: $ip\n    type: vless\n    server: '$ip'\n    port: $port\n    uuid: $password\n    network: $protocol\n    tls: true\n    udp: true\n    packet-encoding: xudp\n    # skip-cert-verify: true\n    servername: $domain\n    grpc-opts:\n      grpc-service-name: \"${servName}\"\n    reality-opts:\n      public-key: $pubkey\n      short-id: $shortId\n    client-fingerprint: safari"
            vless_reality_grpc_outbound_config
        elif [ "$protocol" = "h2" ]; then
            local link="vless://$password@$ip:$port?encryption=none&security=$reality&sid=$shortId&sni=$domain&fp=safari&pbk=$pubkey&type=http#$ip"
            local clash_cfg="  - name: $ip\n    type: vless\n    server: '$ip'\n    port: $port\n    uuid: $password\n    tls: true\n    udp: true\n    packet-encoding: xudp\n    network: h2\n    flow: ''\n    servername: $domain\n    reality-opts:\n      public-key: $pubkey\n      short-id: $shortId\n    client-fingerprint: safari"        
            vless_reality_h2_outbound_config
        else
            # reality+tcp
            local link="vless://$password@$ip:$port?encryption=none&security=$reality&sni=$domain&fp=safari&sid=$shortId&pbk=$pubkey&type=tcp&headerType=none#$ip"
            local clash_cfg="  - name: $ip\n    type: vless\n    server: '$ip'\n    port: $port\n    uuid: $password\n    network: tcp\n    tls: true\n    udp: true\n    packet-encoding: xudp\n    servername: $domain\n    reality-opts:\n      public-key: $pubkey\n      short-id: $shortId\n    client-fingerprint: safari"
            vless_reality_tcp_outbound_config
        fi
    else
        printf "%s" ""
    fi
}

mihomo_vless() {
    local i="$1"
    local type=$(yq -r ".listeners[$i].type" $mihomo_cfg)
    local port=$(yq -r ".listeners[$i].port" $mihomo_cfg)
    local password=$(yq -r ".listeners[$i].users[0].uuid" $mihomo_cfg)
    local reality=$(yq -r ".listeners[$i].reality-config" $mihomo_cfg)
    if [ -n "$reality" ]; then
        local grpc=$(yq -r ".listeners[$i].grpc-service-name" $mihomo_cfg)
        local pubkey=$(yq -r ".listeners[$i].users[0].username" $mihomo_cfg)
        local domain=$(yq -r ".listeners[$i].reality-config.server-names[0]" $mihomo_cfg)
        local shortId=$(yq -r ".listeners[$i].reality-config.short-id[0]" $mihomo_cfg)
        if [ -n "$grpc" ]; then
            # reality+grpc
            local servName=$(yq -r ".listeners[$i].grpc-service-name" $mihomo_cfg)
            local link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&sid=$shortId&fp=safari&pbk=$pubkey&type=grpc&peer=$domain&allowInsecure=1&serviceName=$servName&mode=multi#$ip"
            local clash_cfg="  - name: $ip\n    type: vless\n    server: '$ip'\n    port: $port\n    uuid: $password\n    network: grpc\n    tls: true\n    udp: true\n    packet-encoding: xudp\n    # skip-cert-verify: true\n    servername: $domain\n    grpc-opts:\n      grpc-service-name: \"${servName}\"\n    reality-opts:\n      public-key: $pubkey\n      short-id: $shortId\n    client-fingerprint: safari"
            vless_reality_grpc_outbound_config
        else 
            # reality+tcp
            local link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&fp=safari&sid=$shortId&pbk=$pubkey&type=tcp&headerType=none#$ip"
            local clash_cfg="  - name: $ip\n    type: vless\n    server: '$ip'\n    port: $port\n    uuid: $password\n    network: tcp\n    tls: true\n    udp: true\n    packet-encoding: xudp\n    servername: $domain\n    reality-opts:\n      public-key: $pubkey\n      short-id: $shortId\n    client-fingerprint: safari"
            vless_reality_tcp_outbound_config
        fi
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
      \"packet_encoding\": \"xudp\",
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
    local type=$(printf "%s" "$item" | jq -r '.type')
    local port=$(printf "%s" "$item" | jq -r '.listen_port')
    local up=$(printf "%s" "$item" | jq -r '.up_mbps')
    local down=$(printf "%s" "$item" | jq -r '.down_mbps')
    local password=$(printf "%s" "$item" | jq -r '.users[0].password')
    
    local link="hysteria2://${password}@${ip}:${port}?peer=https://www.python.org&insecure=1&obfs=none#${ip}"

    local clash_cfg="  - name: $ip\n    type: hysteria2\n    server: '$ip'\n    port: $port\n    up: $down Mbps\n    down: $up Mbps\n    password: $password\n    sni: https://www.python.org\n    skip-cert-verify: true\n    alpn:\n      - h3"

    singbox_hy2_outbound_config
}

mihomo_hy2() {
    local item="$1"
    local type=$(yq -r ".listeners[$i].type" $mihomo_cfg)
    local port=$(yq -r ".listeners[$i].port" $mihomo_cfg)
    local up=$(yq -r ".listeners[$i].up" $mihomo_cfg)
    local down=$(yq -r ".listeners[$i].down" $mihomo_cfg)
    local password=$(yq -r ".listeners[$i].users.user1" $mihomo_cfg)

    local link="hysteria2://${password}@${ip}:${port}?peer=https://www.python.org&insecure=1&obfs=none#${ip}"

    local clash_cfg="  - name: $ip\n    type: hysteria2\n    server: '$ip'\n    port: $port\n    up: $down Mbps\n    down: $up Mbps\n    password: $password\n    sni: https://www.python.org\n    skip-cert-verify: true\n    alpn:\n      - h3"

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
      \"server_name\": \"https://www.python.org\",
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
        printf "%s" "Xray Config does not exist. Exiting."
        exit 1  # 非零的退出状态表示异常退出
    fi

    ip=$(curl -s4 --connect-timeout 4 https://ip.me)
    ipv6=$(curl -s6 --connect-timeout 4 https://ip.me)
    if [ ! -n "$ip" ]; then
        ip=$ipv6
    fi
    # 遍历 JSON 数组并调用相应函数
    jq -c '.inbounds[]' $xray_cfg | while read -r inbound; do
        type=$(printf "%s" "$inbound" | jq -r '.protocol')
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
        printf "%s" "Singbox Config does not exist. Exiting."
        exit 1  # 非零的退出状态表示异常退出
    fi

    ip=$(curl -s4 --connect-timeout 4 https://ip.me)
    ipv6=$(curl -s6 --connect-timeout 4 https://ip.me)
    if [ ! -n "$ip" ]; then
        ip=$ipv6
    fi
    # 遍历 JSON 数组并调用相应函数
    jq -c '.inbounds[]' $singbox_cfg | while read -r inbound; do
        type=$(printf "%s" "$inbound" | jq -r '.type')

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

mihomo_range() {
    if [ ! -e "$mihomo_cfg" ]; then
        printf "Mihomo Config does not exist. Exiting."
        exit 1  # 非零的退出状态表示异常退出
    fi

    if ! command -v yq >/dev/null 2>&1; then
        yq_install
    fi

    ip=$(curl -s4 --connect-timeout 4 https://ip.me)
    ipv6=$(curl -s6 --connect-timeout 4 https://ip.me)
    if [ ! -n "$ip" ]; then
        ip=$ipv6
    fi

    for i in $(yq '.listeners | keys | .[]' $mihomo_cfg); do
        type=$(yq -r ".listeners[$i].type" $mihomo_cfg)
        case "$type" in
            "shadowsocks")
                mihomo_shadowsocket "$i"
                ;;
            "vless")
                mihomo_vless "$i"
                ;;
            "hysteria2")
                mihomo_hy2 "$i"
                ;;
            *)
                ;;
        esac

    done
}

show_info() {
    # 使用 %b 解析颜色变量，确保在所有 Shell 环境下颜色生效
    # 分隔符统一，%s 引用变量确保安全
    printf "%b------------------------------------------------------------%b\n" "${Cyan}" "${Font}"
    printf "%b--------------------------配置开始--------------------------%b\n" "${Cyan}" "${Font}"
    printf "%b------------------------------------------------------------%b\n" "${Cyan}" "${Font}"
    
    printf "%b协议:%b %s\n" "${Green}" "${Font}" "${type}"
    printf "%b地址:%b %s\n" "${Green}" "${Font}" "${ip}"
    
    [ -n "$ipv6" ] && printf "%b地址IPv6:%b %s\n" "${Green}" "${Font}" "${ipv6}"
    [ -n "$hq_ip" ] && printf "%b优选地址:%b %s\n" "${Green}" "${Font}" "${hq_ip}"
    
    printf "%b密码:%b %s\n" "${Green}" "${Font}" "${password}"
    printf "%b端口:%b %s\n" "${Green}" "${Font}" "${port}"

    # 处理分享链接
    if [ -n "$link" ]; then
        printf "%b分享链接:%b\n%s\n" "${Green}" "${Font}" "${link}"
    fi

    # 处理复杂的多行配置信息
    # 使用 %s 打印变量，防止配置里的特殊字符（如 \n, \t）被 printf 再次解析
    if [ -n "$qx_cfg" ]; then
        printf "------------------------------------------------------------\n"
        printf "%bQuantumultX配置:%b\n%s\n" "${Green}" "${Font}" "${qx_cfg}"
    fi

    if [ -n "$xray_outbound" ]; then
        printf "------------------------------------------------------------\n"
        printf "%bXray Outbounds配置:%b\n%s\n" "${Green}" "${Font}" "${xray_outbound}"
    fi

    if [ -n "$singbox_outbound" ]; then
        printf "------------------------------------------------------------\n"
        printf "%bSingbox Outbounds配置:%b\n%s\n" "${Green}" "${Font}" "${singbox_outbound}"
    fi

    if [ -n "$clash_cfg" ]; then
        printf "------------------------------------------------------------\n"
        printf "%bClash配置:%b\n%s\n" "${Green}" "${Font}" "${clash_cfg}"
    fi

    printf "%b------------------------------------------------------------%b\n" "${Cyan}" "${Font}"
    printf "%b--------------------------配置结束--------------------------%b\n" "${Cyan}" "${Font}"
    printf "%b------------------------------------------------------------%b\n" "${Cyan}" "${Font}"
}

xray_run() {
    xray_range
}

singbox_run() {
    singbox_range
}

mihomo_run() {
    mihomo_range
}

case $1 in
    singbox)
        singbox_run
        ;;
    xray)
        xray_run
        ;;
    mihomo)
        mihomo_range
        ;;
    *)
        singbox_run
        ;;
esac
