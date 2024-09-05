#!/usr/bin/env bash

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
stty erase ^?

version="v2.0.5"

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

#notification information
Info="${Green}[信息]${Font}"
Warn="${Yellow}[警告]${Font}"
OK="${Green}[OK]${Font}"
Error="${Red}[错误]${Font}"

website_url="https://github.com/bakasine/bakasine.github.io/archive/refs/heads/master.zip"
website_git="https://github.com/bakasine/bakasine.github.io.git"
xray_install_url="https://github.com/uerax/taffy-onekey/raw/master/install-xray.sh"
ukonw_url="https://raw.githubusercontent.com/bakasine/rules/master/xray/uknow.txt"

socks5_append_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Socks5/append.json"

ss_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Shadowsocket/config.json"
ss_append_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Shadowsocket/append.json"

bbr_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/BBR/sysctl.conf"

trojan_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Trojan/config.json"
trojan_append_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Trojan/append.json"

trojan_grpc_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Trojan-GRPC/config.json"
trojan_grpc_nginx_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Trojan-GRPC/nginx.conf"

trojan_tcp_tls_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Trojan-TCP-TLS/config.json"
trojan_tcp_tls_nginx_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Trojan-TCP-TLS/nginx.conf"

vmess_ws_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/VMESS-WS-TLS/config.json"
vmess_ws_nginx_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/VMESS-WS-TLS/nginx.conf"

vless_ws_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/VLESS-WS-TLS/config.json"
vless_ws_nginx_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/VLESS-WS-TLS/nginx.conf"

vless_grpc_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/VLESS-GRPC/config.json"
vless_grpc_nginx_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/VLESS-GRPC/nginx.conf"

vless_vision_nginx_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/VLESS-TCP-XTLS-VISION/nginx.conf"
vless_vision_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/VLESS-TCP-XTLS-VISION/config.json"

vless_reality_tcp_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/REALITY-TCP/config.json"
vless_reality_tcp_append_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/REALITY-TCP/append.json"

vless_reality_grpc_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/REALITY-GRPC/config.json"
vless_reality_grpc_append_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/REALITY-GRPC/append.json"

vless_reality_h2_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/REALITY-H2/config.json"
vless_reality_h2_append_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/REALITY-H2/append.json"

# SINGBOX URL START
singbox_install_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/install-singbox.sh"
tcp_brutal_install_url="https://tcp.hy2.sh/"
singbox_cfg_path="/etc/sing-box"
singbox_cfg="${singbox_cfg_path}/config.json"
singbox_path="/opt/singbox/"

singbox_outbound=""

singbox_ss_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Shadowsocket/singbox.json"
singbox_ss_append_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Shadowsocket/singbox_ap.json"

singbox_hysteria2_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Hysteria2/singbox.json"
singbox_vless_reality_h2_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/REALITY-H2/singbox.json"
singbox_vless_reality_grpc_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/REALITY-GRPC/singbox.json"
singbox_vless_reality_tcp_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/REALITY-TCP/singbox.json"
singbox_vmess_ws_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/VMESS-WS-TLS/singbox.json"
singbox_trojan_tls_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Trojan-TCP-TLS/singbox.json"
singbox_trojan_tls_nginx_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Trojan-TCP-TLS/taffy.conf"

singbox_route_url="https://raw.githubusercontent.com/bakasine/rules/master/singbox/singbox.txt"
# SINGBOX URL END

xray_cfg="/usr/local/etc/xray/config.json"
xray_path="/opt/xray/"
xray_log="${xray_path}xray_log"
nginx_cfg="/etc/nginx/conf.d/taffy.conf"
web_dir="blog"
xray_type=""
web_path="/opt/web"
ca_path="/opt/cert"
ca_crt="${ca_path}/taffy.crt"
ca_key="${ca_path}/taffy.key"
ws_path="crayfish"
ss_method=""

outbound_method=""
outbound=""

INS="apt install -y"
password=""
domain=""
link=""
port="1991"

install() {
    is_root
    get_system
    if ! command -v xray >/dev/null 2>&1; then
        # adjust_date
        env_install
        # increase_max_handle
        close_firewall
        xray_install
    fi
    if ! command -v xray >/dev/null 2>&1; then
        echo -e "${Red}Xray 安装失败!!!${Font}"
        exit 1
    fi
    xray_configure
    select_type
}

is_root() {
    if [ $(id -u) == 0 ]; then
        ok "进入安装流程"
        apt purge needrestart -y
        sleep 3
    else
        error "请切使用root用户执行脚本"
        info "切换root用户命令: sudo su"
        exit 1
    fi
}

get_system() {
    source '/etc/os-release'
    if [[ "${ID}" == "debian" ]]; then
        info "检测系统为 debian"
    elif [[ "${ID}"=="ubuntu" ]]; then
        info "检测系统为 ubuntu"
    elif [[ "${ID}"=="centos" ]]; then
        error "centos fuck out!"
        exit 1
    else
        error "当前系统为 ${ID} ${VERSION_ID} 不在支持的系统列表内"
        exit 1
    fi
}

adjust_date() {
  info "正在调整时区"
  apt install -y locales
  echo "Asia/Shanghai" > /etc/timezone && \
  dpkg-reconfigure -f noninteractive tzdata && \
  sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
  echo 'LANG="en_US.UTF-8"'>/etc/default/locale && \
  dpkg-reconfigure --frontend=noninteractive locales && \
  update-locale LANG=en_US.UTF-8
  echo "Asia/Shanghai" > /etc/timezone
  judge "时区调整"
}

env_install() {

    ${INS} wget lsof curl jq
    judge "git wget lsof curl jq 安装"
}

env_install_singbox() {

    ${INS} wget lsof curl jq
    judge "wget lsof curl jq 安装"
}

increase_max_handle() {
    # 最大文件打开数
    sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    echo '* soft nofile 65536' >>/etc/security/limits.conf
    echo '* hard nofile 65536' >>/etc/security/limits.conf
}

port_check() {
    if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
        ok "$1 端口未被占用"
        sleep 1
    else
        error "检测到 $1 端口被占用，以下为 $1 端口占用信息"
        lsof -i:"$1"
        error "2s 后将尝试自动 kill 占用进程"
        sleep 2
        lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
        ok "kill 完成"
        sleep 1
    fi
}

close_firewall() {
    if command -v iptables >/dev/null 2>&1; then
        # 主要针对oracle vps
        apt purge netfilter-persistent -y
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        iptables -F
        ok "关闭防火墙"
    fi
}

nginx_install() {
    # 判断是否有 nginx 命令
    if ! command -v nginx >/dev/null 2>&1; then
        ${INS} nginx cron
        judge "Nginx 安装"
    else
        ok "Nginx 已存在"
    fi

    mkdir -p ${web_path} && cd ${web_path}

    git clone ${website_git} ${web_dir}
}

update_web() {
    git clone ${website_git} ${web_path}/${web_dir}
}

domain_handle() {
    echo -e "------------------------------------------"
    read -rp "输入你的域名(eg: example.com): " domain
}

apply_certificate() {
    ipv6=''
    echo -e "========================================"
    read -rp "是否纯IPv6域名(Y/N): " is_v6
    case $is_v6 in
    [yY])
    ipv6='--listen-v6'
    ;;
    *)
    ;;
    esac
    sed -i '/\/etc\/nginx\/sites-enabled\//d' /etc/nginx/nginx.conf

    cat>${nginx_cfg}<<EOF
server {
    listen 80;
    server_name ${domain};
    root ${web_path}/${web_dir};
    index index.html;
}
EOF

    service nginx restart

    if ! command -v /root/.acme.sh/acme.sh >/dev/null 2>&1; then
        wget -O - https://get.acme.sh | sh
        judge "安装 Acme"
    else
        ok "Acme 已安装"
    fi
    cd ~ && . .bashrc
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    echo ${domain}

    if /root/.acme.sh/acme.sh --issue -d ${domain} -w ${web_path}/${web_dir} --keylength ec-256 --force ${ipv6}; then
        ok "SSL 证书生成成功"
        sleep 2
        mkdir -p ${ca_path}
        if /root/.acme.sh/acme.sh --install-cert -d ${domain} --ecc --fullchain-file ${ca_crt} --key-file ${ca_key}; then
            chmod +r ${ca_key}
            ok "SSL 证书配置成功"
            sleep 2
        fi
    else
        error "证书生成失败"
        exit 1
    fi
}

flush_certificate() {
    cat > ${ca_path}/xray-cert-renew.sh <<EOF
#!/bin/bash

git clone ${website_git} ${web_path}/${web_dir}
if /root/.acme.sh/acme.sh --issue -d ${domain} -w ${web_path}/${web_dir} --keylength ec-256 --force ${ipv6}; then
  sleep 2
  mkdir -p ${ca_path}
  /root/.acme.sh/acme.sh --install-cert -d ${domain} --ecc --fullchain-file ${ca_crt} --key-file ${ca_key} --reloadcmd "nginx -s reload"
else
  exit 1
fi

echo "Xray Certificates Renewed"

chmod +r ${ca_key}
echo "Read Permission Granted for Private Key"

systemctl restart xray
systemctl restart sing-box
echo "Xray Restarted"
EOF

    chmod +x ${ca_path}/xray-cert-renew.sh

    (
        crontab -l | grep -v "bash ${ca_path}/xray-cert-renew.sh"
        echo "0 7 1 */2 *   bash ${ca_path}/xray-cert-renew.sh"
    ) | crontab -

}

xray_install() {

    if ! command -v xray >/dev/null 2>&1; then
        wget --no-check-certificate ${xray_install_url}
        judge "Xray安装脚本 下载"
        bash install-release.sh install
        judge "Xray 安装"
        rm install-release.sh
    else
        ok "Xray 已安装"
    fi
    
}

xray_configure() {
    mkdir -p ${xray_log} && touch ${xray_log}/access.log && touch ${xray_log}/error.log && chmod a+w ${xray_log}/*.log
}

clash_config() {
    case $xray_type in
    "hysteria2_nodomain")
    clash_cfg="  - name: $domain
    type: hysteria2
    server: '$domain'
    port: $port
    up: 50 Mbps
    down: 200 Mbps
    password: $password
    sni: https://live.qq.com
    skip-cert-verify: true
    alpn:
    - h3"
    ;;    
    "hysteria2")
    clash_cfg="  - name: $domain
    type: hysteria2
    server: '$domain'
    port: $port
    up: 50 Mbps
    down: 200 Mbps
    password: $password
    alpn:
    - h3"
    ;;
    "reality_tcp")
    clash_cfg="  - name: $ip
    type: vless
    server: '$ip'
    port: $port
    uuid: $password
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    servername: www.fate-go.com.tw
    reality-opts:
      public-key: $public_key
      short-id: 8eb7bab5a41eb27d
    client-fingerprint: safari"
    ;;
    "reality_grpc")
    clash_cfg="  - name: $ip
    type: vless
    server: '$ip'
    port: $port
    uuid: $password
    network: grpc
    tls: true
    udp: true
    # skip-cert-verify: true
    servername: www.fate-go.com.tw
    grpc-opts:
      grpc-service-name: \"${ws_path}\"
    reality-opts:
      public-key: $public_key
      short-id: 8eb7bab5a41eb27d
    client-fingerprint: safari"
    ;;
    "trojan_grpc")
    clash_cfg="  - name: $domain
    server: '$domain'
    port: $port
    type: trojan
    password: $password
    network: grpc
    alpn:
      - h2
    sni: $domain
    skip-cert-verify: false
    udp: true
    grpc-opts:
      grpc-service-name: \"${ws_path}\""
    ;;
    "trojan")
    clash_cfg="  - name: $ip
    type: trojan
    server: '$ip'
    port: $port
    password: $password"
    ;;
    "trojan_tcp")
    clash_cfg="  - name: $domain
    type: trojan
    server: '$domain'
    port: $port
    password: $password
    alpn:
      - h2
      - http/1.1"
    ;;
    "vmess_ws")
    clash_cfg="  - name: $domain
    type: vmess
    server: '$domain'
    port: 443
    uuid: $password
    alterId: 0
    cipher: auto
    udp: true
    tls: true
    network: ws
    ws-opts:
      path: \"/${ws_path}\"
      headers:
        Host: $domain"
    ;;
    "vless_ws")
    clash_cfg="  - name: $domain
    type: vless
    server: '$domain'
    port: 443
    uuid: $password
    udp: true
    tls: true
    network: ws
    servername: $domain
    # skip-cert-verify: true
    ws-opts:
      path: \"/${ws_path}\"
      headers:
        Host: $password"
    ;;
    "vless_vison")
    clash_cfg="  - name: $domain
    type: vless
    server: '$domain'
    port: 443
    uuid: $password
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision 
    client-fingerprint: safari"
    ;;
    "reality_h2")
    clash_cfg="  - name: $ip
    type: vless
    server: '$ip'
    port: $port
    uuid: $password
    tls: true
    udp: true
    network: h2
    flow: ''
    servername: www.fate-go.com.tw
    reality-opts:
      public-key: $public_key
      short-id: 8eb7bab5a41eb27d
    client-fingerprint: safari"
    ;;
    "shadowsocket")
    clash_cfg="  - name: $domain
    type: ss
    server: '$domain'
    port: $port
    cipher: $ss_method
    password: $password
    udp: true"
    ;;
    esac
    
}

qx_config() {
    case $xray_type in
    "vmess_ws")
    qx_cfg="vmess=$domain:443, method=chacha20-poly1305, password=$password, obfs=wss, obfs-host=$domain, obfs-uri=/${ws_path}, tls13=true, fast-open=false, udp-relay=false, tag=$domain"
    ;;
    "trojan_tcp")
    qx_cfg="trojan=$domain:443, password=$password, over-tls=true, tls-host=$domain, tls-verification=true, tls13=true, fast-open=false, udp-relay=false, tag=$domain"
    ;;
    "trojan")
    qx_cfg="trojan=$ip:$port, password=$password, tag=$ip"
    ;;
    "shadowsocket")
    qx_cfg="shadowsocks=$domain:$port, method=$ss_method, password=$password, tag=$domain"
    ;;
    esac
}

vless_reality_h2() {
    password=$(xray uuid)
    set_port
    port_check $port

    domain="www.fate-go.com.tw"
    xray_type="reality_h2"
    keys=$(xray x25519)
    private_key=$(echo $keys | awk -F " " '{print $3}')
    public_key=$(echo $keys | awk -F " " '{print $6}')
    # short_id=$(openssl rand -hex 8)
    ip=$(curl ipinfo.io/ip)
    ipv6=$(curl -6 ip.me)

    wget -N ${vless_reality_h2_url} -O ${xray_cfg}

    sed -i "s~\${password}~$password~" ${xray_cfg}
    sed -i "s~\${privateKey}~$private_key~" ${xray_cfg}
    sed -i "s~\${port}~$port~" ${xray_cfg}
    
    routing_set
    vless_reality_h2_outbound_config
    systemctl restart xray 

    systemctl enable xray

    link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&fp=safari&pbk=$public_key&type=http#$ip"
    clash_config
}

vless_reality_h2_append() {
    password=$(xray uuid)
    set_port
    port_check $port

    domain="www.fate-go.com.tw"
    xray_type="reality_h2"
    keys=$(xray x25519)
    private_key=$(echo $keys | awk -F " " '{print $3}')
    public_key=$(echo $keys | awk -F " " '{print $6}')
    # short_id=$(openssl rand -hex 8)
    ip=$(curl ipinfo.io/ip)

    wget -Nq ${vless_reality_h2_append_url} -O append.tmp

    sed -i "s~\${password}~$password~" append.tmp
    sed -i "s~\${privateKey}~$private_key~" append.tmp
    sed -i "s~\${port}~$port~" append.tmp
    echo "," >> append.tmp

    sed -i '/inbounds/ r append.tmp' ${xray_cfg}
    rm append.tmp

    vless_reality_h2_outbound_config
    systemctl restart xray 
    link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&fp=safari&pbk=$public_key&type=http#$ip"
    clash_config
}

vless_reality_tcp() {
    password=$(xray uuid)
    set_port
    port_check $port

    domain="www.fate-go.com.tw"
    xray_type="reality_tcp"
    keys=$(xray x25519)
    private_key=$(echo $keys | awk -F " " '{print $3}')
    public_key=$(echo $keys | awk -F " " '{print $6}')
    # short_id=$(openssl rand -hex 8)
    ip=$(curl ipinfo.io/ip)
    ipv6=$(curl -6 ip.me)

    wget -N ${vless_reality_tcp_url} -O ${xray_cfg}

    sed -i "s~\${password}~$password~" ${xray_cfg}
    sed -i "s~\${privateKey}~$private_key~" ${xray_cfg}
    sed -i "s~\${port}~$port~" ${xray_cfg}

    routing_set
    vless_reality_tcp_outbound_config

    systemctl restart xray 

    systemctl enable xray

    service nginx stop

    link="vless://$password@$ip:$port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$domain&fp=safari&pbk=$public_key&type=tcp&headerType=none#$ip"
    clash_config
}

vless_reality_tcp_append() {
    password=$(xray uuid)
    set_port
    port_check $port

    domain="www.fate-go.com.tw"
    xray_type="reality_tcp"
    keys=$(xray x25519)
    private_key=$(echo $keys | awk -F " " '{print $3}')
    public_key=$(echo $keys | awk -F " " '{print $6}')
    # short_id=$(openssl rand -hex 8)
    ip=$(curl ipinfo.io/ip)

    wget -Nq ${vless_reality_tcp_append_url} -O append.tmp

    sed -i "s~\${password}~$password~" append.tmp
    sed -i "s~\${privateKey}~$private_key~" append.tmp
    sed -i "s~\${port}~$port~" append.tmp
    echo "," >> append.tmp

    sed -i '/inbounds/ r append.tmp' ${xray_cfg}
    rm append.tmp

    vless_reality_tcp_outbound_config
    systemctl restart xray 
    link="vless://$password@$ip:$port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$domain&fp=safari&pbk=$public_key&type=tcp&headerType=none#$ip"
    clash_config
}

vless_reality_grpc() {
    password=$(xray uuid)
    set_port
    port_check $port

    xray_type="reality_grpc"
    keys=$(xray x25519)
    private_key=$(echo $keys | awk -F " " '{print $3}')
    public_key=$(echo $keys | awk -F " " '{print $6}')
    # short_id=$(openssl rand -hex 8)
    ip=$(curl ipinfo.io/ip)
    ipv6=$(curl -6 ip.me)

    wget -N ${vless_reality_grpc_url} -O ${xray_cfg}

    sed -i "s~\${password}~$password~" ${xray_cfg}
    sed -i "s~\${privateKey}~$private_key~" ${xray_cfg}
    sed -i "s~\${ws_path}~$ws_path~" ${xray_cfg}
    sed -i "s~\${port}~$port~" ${xray_cfg}

    routing_set
    vless_reality_grpc_outbound_config

    systemctl restart xray 

    systemctl enable xray

    clash_config
    link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&sid=8eb7bab5a41eb27d&fp=safari&peer=$domain&allowInsecure=1&pbk=$public_key&type=grpc&serviceName=$ws_path&mode=multi#$ip"
}

vless_reality_grpc_append() {
    password=$(xray uuid)
    set_port
    port_check $port

    domain="www.fate-go.com.tw"
    xray_type="reality_grpc"
    keys=$(xray x25519)
    private_key=$(echo $keys | awk -F " " '{print $3}')
    public_key=$(echo $keys | awk -F " " '{print $6}')
    # short_id=$(openssl rand -hex 8)
    ip=$(curl ipinfo.io/ip)

    wget -Nq ${vless_reality_grpc_append_url} -O append.tmp

    sed -i "s~\${password}~$password~" append.tmp
    sed -i "s~\${privateKey}~$private_key~" append.tmp
    sed -i "s~\${ws_path}~$ws_path~" append.tmp
    sed -i "s~\${port}~$port~" append.tmp
    echo "," >> append.tmp

    sed -i '/inbounds/ r append.tmp' ${xray_cfg}
    rm append.tmp

    vless_reality_grpc_outbound_config
    systemctl restart xray 
    link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&sid=8eb7bab5a41eb27d&fp=safari&peer=$domain&allowInsecure=1&pbk=$public_key&type=grpc&serviceName=$ws_path&mode=multi#$ip"
    clash_config
}

trojan_grpc() {
    port_check 80
    port_check 443
    nginx_install
    domain_handle
    apply_certificate
    flush_certificate
    
    xray_type="trojan_grpc"
    password=$(xray uuid)
    port=443
    
    wget -N ${trojan_grpc_config_url} -O ${xray_cfg}

    sed -i "s~\${password}~$password~" ${xray_cfg}
    sed -i "s~\${ws_path}~$ws_path~" ${xray_cfg}

    routing_set

    systemctl restart xray 

    systemctl enable xray

    sleep 3

    wget -N ${trojan_grpc_nginx_url} -O ${nginx_cfg}

    sed -i "s~\${domain}~$domain~" ${nginx_cfg}
    sed -i "s~\${web_path}~$web_path~" ${nginx_cfg}
    sed -i "s~\${web_dir}~$web_dir~" ${nginx_cfg}
    sed -i "s~\${ca_crt}~$ca_crt~" ${nginx_cfg}
    sed -i "s~\${ca_key}~$ca_key~" ${nginx_cfg}
    sed -i "s~\${ws_path}~$ca_key~" ${nginx_cfg}

    service nginx restart

    link="trojan://${password}@${domain}:${port}?security=tls&type=grpc&serviceName=${ws_path}&mode=gun#${domain}"

    clash_config
}

trojan_tcp_tls() {
    port_check 80
    port_check 443
    nginx_install
    domain_handle
    apply_certificate
    flush_certificate
    
    xray_type="trojan_tcp"
    password=$(xray uuid)
    set_port
    
    wget -N ${trojan_tcp_tls_config_url} -O ${xray_cfg}

    sed -i "s~${port}~$port~" ${xray_cfg}
    sed -i "s~\${password}~$password~" ${xray_cfg}
    sed -i "s~\${ca_crt}~$ca_crt~" ${xray_cfg}
    sed -i "s~\${ca_key}~$ca_key~" ${xray_cfg}

    routing_set
    trojan_tcp_tls_outbound_config

    systemctl restart xray

    systemctl enable xray

    sleep 3

    wget -N ${trojan_tcp_tls_nginx_url} -O ${nginx_cfg}

    sed -i "s~\${domain}~$domain~" ${nginx_cfg}
    sed -i "s~\${web_path}~$web_path~" ${nginx_cfg}
    sed -i "s~\${web_dir}~$web_dir~" ${nginx_cfg}

    service nginx restart

    link="trojan://${password}@${domain}:${port}?security=tls&type=tcp&headerType=none#${domain}"

    clash_config
    qx_config
}

vmess_ws_tls() {
    port_check 80
    port_check 443
    nginx_install
    domain_handle
    apply_certificate
    flush_certificate

    xray_type="vmess_ws"
    password=$(xray uuid)

    wget -N ${vmess_ws_config_url} -O ${xray_cfg}

    sed -i "s~19191~$port~" ${xray_cfg}
    sed -i "s~\${password}~$password~" ${xray_cfg}
    sed -i "s~\${ws_path}~$ws_path~" ${xray_cfg}

    routing_set

    systemctl restart xray
    
    systemctl enable xray

    sleep 3

    wget -N ${vmess_ws_nginx_url} -O ${nginx_cfg}

    sed -i "s~\${domain}~$domain~" ${nginx_cfg}
    sed -i "s~\${web_path}~$web_path~" ${nginx_cfg}
    sed -i "s~\${web_dir}~$web_dir~" ${nginx_cfg}
    sed -i "s~\${ca_crt}~$ca_crt~" ${nginx_cfg}
    sed -i "s~\${ca_key}~$ca_key~" ${nginx_cfg}
    sed -i "s~\${ws_path}~$ws_path~" ${nginx_cfg}
    sed -i "s~\${port}~$port~" ${nginx_cfg}

    service nginx restart

    tmp="{\"v\":\"2\",\"ps\":\"${domain}\",\"add\":\"${domain}\",\"port\":\"443\",\"id\":\"${password}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${domain}\",\"path\":\"/${ws_path}\",\"tls\":\"tls\",\"sni\":\"${domain}\",\"alpn\":\"\",\"fp\":\"safari\"}"
    encode_link=$(base64 <<< $tmp)
    link="vmess://$encode_link"

    clash_config
    qx_config
    vmess_ws_tls_outbound_config
}

vless_ws_tls() {
    port_check 80
    port_check 443
    nginx_install
    domain_handle
    apply_certificate
    flush_certificate

    xray_type="vless_ws"
    password=$(xray uuid)

    wget -N ${vless_ws_config_url} -O ${xray_cfg}

    sed -i "s~\${ws_path}~$ws_path~" ${xray_cfg}
    sed -i "s~\${password}~$password~" ${xray_cfg}

    routing_set

    systemctl restart xray && systemctl enable xray

    sleep 3

    wget -N ${vless_ws_nginx_url} -O ${nginx_cfg}

    sed -i "s~\${domain}~$domain~" ${nginx_cfg}
    sed -i "s~\${web_path}~$web_path~" ${nginx_cfg}
    sed -i "s~\${web_dir}~$web_dir~" ${nginx_cfg}
    sed -i "s~\${ca_crt}~$ca_crt~" ${nginx_cfg}
    sed -i "s~\${ca_key}~$ca_key~" ${nginx_cfg}
    sed -i "s~\${ws_path}~$ws_path~" ${nginx_cfg}

    service nginx restart

    parts="auto:${password}@${domain}:443"
    encode_parts=$(base64 <<< $parts)
    link="vless://${encode_parts}?encryption=none&security=tls&sni=${domain}&type=ws&host=${domain}&path=%2F${ws_path}#${domain}"

    clash_config
}

vless_grpc() {
    port_check 80
    port_check 443
    nginx_install
    domain_handle
    apply_certificate
    flush_certificate

    xray_type="vless_grpc"
    password=$(xray uuid)

    wget -N ${vless_grpc_config_url} -O ${xray_cfg}
    sed -i "s~\${password}~$password~" ${xray_cfg}
    sed -i "s~\${ws_path}~$ws_path~" ${xray_cfg}

    routing_set

    systemctl restart xray && systemctl enable xray

    sleep 3

    wget -N ${vless_grpc_nginx_url} -O ${nginx_cfg}

    sed -i "s~\${domain}~$domain~" ${nginx_cfg}
    sed -i "s~\${web_path}~$web_path~" ${nginx_cfg}
    sed -i "s~\${ws_path}~$ws_path~" ${nginx_cfg}
    sed -i "s~\${ws_path}~$ws_path~" ${nginx_cfg}
    sed -i "s~\${web_dir}~$web_dir~" ${nginx_cfg}
    sed -i "s~\${ca_crt}~$ca_crt~" ${nginx_cfg}
    sed -i "s~\${ca_key}~$ca_key~" ${nginx_cfg}

    service nginx restart

    parts="auto:${password}@${domain}:443"
    encode_parts=$(base64 <<< $parts)
    link="vless://${encode_parts}?encryption=none&security=tls&sni=${domain}&type=grpc&host=${domain}&path=%2F${ws_path}#${domain}"
}

vless_tcp_xtls_vision() {
    port_check 80
    port_check 443
    nginx_install
    domain_handle
    apply_certificate
    flush_certificate

    xray_type="vless_vison"
    password=$(xray uuid)
    vless_tcp_xtls_vision_xray_cfg
    systemctl restart xray && systemctl enable xray
    sleep 3
    vless_tcp_xtls_vision_nginx_cfg

    service nginx restart

    parts="auto:${password}@${domain}:443"
    encode_parts=$(base64 <<< $parts)
    link="vless://${encode_parts}?encryption=none&flow=xtls-rprx-vision&security=tls&type=tcp&headerType=none#${domain}"

    clash_config
}

vless_tcp_xtls_vision_nginx_cfg() {
    cd /etc/nginx/ && wget -N ${vless_vision_nginx_url} -O /etc/nginx/nginx.conf
}

vless_tcp_xtls_vision_xray_cfg() {
    wget -N ${vless_vision_config_url} -O config.json
    sed -i "s/\${password}/$password/" config.json
    sed -i "s~\${ca_crt}~$ca_crt~" config.json
    sed -i "s~\${ca_key}~$ca_key~" config.json

    routing_set

    mv config.json ${xray_cfg}
}

trojan() {
    xray_type="trojan"
    ip=`curl ipinfo.io/ip`
    info "trojan基础不需要Nginx, 可以通过脚本一键卸载"
    close_nginx()
    if ! command -v openssl >/dev/null 2>&1; then
          ${INS} openssl
          judge "openssl 安装"
    fi
    set_port
    password=$(openssl rand -base64 16)
    trojan_config

    link="trojan://${password}@${ip}:${port}#${domain}"

    trojan_outbound_config
    clash_config
    qx_config

}

trojan_config() {
    wget -N ${trojan_config_url} -O config.json
    sed -i "s~\${port}~$port~" config.json
    sed -i "s~\${password}~$password~" config.json
    
    mv config.json ${xray_cfg}
    systemctl restart xray && systemctl enable xray
}

trojan_append() {
    xray_type="trojan"
    ip=`curl ipinfo.io/ip`
    if ! command -v openssl >/dev/null 2>&1; then
          ${INS} openssl
          judge "openssl 安装"
    fi
    set_port
    password=$(openssl rand -base64 16)

    wget -Nq ${trojan_append_config_url} -O append.tmp

    sed -i "s~\${password}~$password~" append.tmp
    sed -i "s~\${port}~$port~" append.tmp
    echo "," >> append.tmp

    sed -i '/inbounds/ r append.tmp' ${xray_cfg}
    rm append.tmp

    systemctl restart xray

    link="trojan://${password}@${ip}:${port}#${domain}"

    trojan_outbound_config
    clash_config
    qx_config
}

shadowsocket() {
    
    info "Shadowsocket不需要Nginx, 可以通过脚本一键卸载"
    close_nginx()
    if ! command -v openssl >/dev/null 2>&1; then
          ${INS} openssl
          judge "openssl 安装"
    fi
    encrypt=1
    ss_method="2022-blake3-aes-128-gcm"
    set_port
    echo -e "选择加密方法"
    echo -e "${Green}1) 2022-blake3-aes-128-gcm ${Font}"
    echo -e "${Cyan}2) 2022-blake3-aes-256-gcm	${Font}"
    echo -e "${Cyan}3) 2022-blake3-chacha20-poly1305 ${Font}"
    echo -e "${Cyan}4) aes-128-gcm ${Font}"
    echo -e "${Cyan}5) chacha20-ietf-poly1305 ${Font}"
    echo -e "${Cyan}6) xchacha20-ietf-poly1305 ${Font}"
    echo -e ""
    read -rp "选择加密方法(默认为1)：" encrypt
    case $encrypt in
    1)
      password=$(openssl rand -base64 16)
      ;;
    2)
      password=$(openssl rand -base64 32)
      ss_method="2022-blake3-aes-256-gcm"
      ;;
    3)
      password=$(openssl rand -base64 32)
      ss_method="2022-blake3-chacha20-poly1305"
      ;;
    4)
      password=$(openssl rand -base64 16)
      ss_method="aes-128-gcm"
      ;;
    5)
      password=$(openssl rand -base64 16)
      ss_method="chacha20-ietf-poly1305"
      ;;
    5)
      password=$(openssl rand -base64 16)
      ss_method="xchacha20-ietf-poly1305"
      ;;
    *)
      password=$(openssl rand -base64 16)
      ;;
    esac

    shadowsocket_config
    systemctl restart xray && systemctl enable xray

    tmp="${ss_method}:${password}"
    tmp=$( base64 <<< $tmp)
    domain=`curl ipinfo.io/ip`
    ipv6=`curl -6 ip.me`
    link="ss://$tmp@${domain}:${port}"

    xray_type="shadowsocket"
    shadowsocket_outbound_config
    clash_config
    qx_config

}

shadowsocket_config() {
    wget -N ${ss_config_url} -O config.json
    sed -i "s~\${method}~$ss_method~" config.json
    sed -i "s~\${password}~$password~" config.json
    sed -i "s~\${port}~$port~" config.json
    mv config.json ${xray_cfg}
}

shadowsocket_append() {
    if ! command -v openssl >/dev/null 2>&1; then
          ${INS} openssl
          judge "openssl 安装"
    fi
    encrypt=1
    ss_method="2022-blake3-aes-128-gcm"
    set_port
    echo -e "选择加密方法"
    echo -e "${Green}1) 2022-blake3-aes-128-gcm ${Font}"
    echo -e "${Cyan}2) 2022-blake3-aes-256-gcm	${Font}"
    echo -e "${Cyan}3) 2022-blake3-chacha20-poly1305 ${Font}"
    echo -e "${Cyan}4) aes-128-gcm ${Font}"
    echo -e "${Cyan}5) chacha20-ietf-poly1305 ${Font}"
    echo -e "${Cyan}6) xchacha20-ietf-poly1305 ${Font}"
    echo -e ""
    read -rp "选择加密方法(默认为1)：" encrypt
    case $encrypt in
    1)
      password=$(openssl rand -base64 16)
      ;;
    2)
      password=$(openssl rand -base64 32)
      ss_method="2022-blake3-aes-256-gcm"
      ;;
    3)
      password=$(openssl rand -base64 32)
      ss_method="2022-blake3-chacha20-poly1305"
      ;;
    4)
      password=$(openssl rand -base64 16)
      ss_method="aes-128-gcm"
      ;;
    5)
      password=$(openssl rand -base64 16)
      ss_method="chacha20-ietf-poly1305"
      ;;
    5)
      password=$(openssl rand -base64 16)
      ss_method="xchacha20-ietf-poly1305"
      ;;
    *)
      password=$(openssl rand -base64 16)
      ;;
    esac

    wget -Nq ${ss_append_config_url} -O append.tmp

    sed -i "s~\${password}~$password~" append.tmp
    sed -i "s~\${method}~$ss_method~" append.tmp
    sed -i "s~\${port}~$port~" append.tmp
    echo "," >> append.tmp

    sed -i '/inbounds/ r append.tmp' ${xray_cfg}
    rm append.tmp


    tmp="${ss_method}:${password}"
    tmp=$( base64 <<< $tmp)
    domain=`curl ipinfo.io/ip`
    ipv6=`curl -6 ip.me`
    link="ss://$tmp@${domain}:${port}"

    xray_type="shadowsocket"
    shadowsocket_outbound_config
    clash_config
    qx_config
}

# outbound start

vmess_ws_tls_outbound_config() {
    outbound="{
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
            \"path\": \"/${ws_path}\",
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
		\"path\": \"/${ws_path}\",
		\"max_early_data\": 0,
		\"early_data_header_name\": \"Sec-WebSocket-Protocol\"
	},
	\"connect_timeout\": \"5s\"\n}"
}

vless_reality_grpc_outbound_config() {
    outbound="{
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
            \"publicKey\": \"${public_key}\",
            \"shortId\": \"8eb7bab5a41eb27d\"
        },
        \"grpcSettings\": {
            \"serviceName\": \"${ws_path}\",
            \"multiMode\": true,
            \"idle_timeout\": 60,
            \"health_check_timeout\": 20
        }
    }\n}"
}

vless_reality_tcp_outbound_config() {
    outbound="{
    \"protocol\": \"vless\",
    \"settings\": {
        \"vnext\": [
            {
                \"address\": \"${ip}\",
                \"port\": ${port},
                \"users\": [
                    {
                        \"id\": \"${password}\",
                        \"flow\": \"xtls-rprx-vision\",
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
            \"show\": false,\
            \"fingerprint\": \"safari\",
            \"serverName\": \"${domain}\",
            \"publicKey\": \"${public_key}\",
            \"shortId\": \"8eb7bab5a41eb27d\",
            \"spiderX\": \"/\"
        }
    }\n}"
}

trojan_tcp_tls_outbound_config() {
    outbound="{
    \"sendThrough\": \"0.0.0.0\",
    \"protocol\": \"trojan\",
    \"settings\": {
        \"servers\": [
            {
                \"address\": \"${domain}\",
                \"password\": \"${password}\",
                \"port\": ${port}
            }
        ]
    },
    \"streamSettings\": {
        \"network\": \"tcp\",
        \"security\": \"tls\",
        \"tlsSettings\": {
            \"serverName\": \"${domain}\"
        }
    }\n}"
}

vless_reality_h2_outbound_config() {
    outbound="{
    \"protocol\": \"vless\",
    \"settings\": {
        \"vnext\": [
            {
                \"address\": \"${ip}\",
                \"port\": ${port},
                \"users\": [
                    {
                        \"id\": \"${password}\",
                        \"flow\": \"xtls-rprx-vision\",
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
            \"publicKey\": \"${public_key}\",
            \"shortId\": \"8eb7bab5a41eb27d\",
            \"spiderX\": \"/\"
        }
    }\n}"
}

trojan_outbound_config() {
    outbound="{
    \"protocol\": \"trojan\",
    \"settings\": {
        \"servers\": [
            {
                \"address\": \"${ip}\",
                \"port\": ${port},
                \"password\": \"${password}\"
            }
        ]
    }\n}"
    singbox_outbound="{
    \"type\": \"trojan\",
    \"server\": \"${ip}\",
    \"server_port\": ${port},
    \"password\": \"${password}\"\n}"
}

shadowsocket_outbound_config() {
    outbound="{
    \"protocol\": \"shadowsocks\",
    \"settings\": {
        \"servers\": [
            {
                \"address\": \"${domain}\",
                \"port\": ${port},
                \"method\": \"${ss_method}\",
                \"password\": \"${password}\"
            }
        ]
    }
}"
    singbox_outbound="{
    \"type\": \"shadowsocks\",
    \"server\": \"${domain}\",
    \"server_port\": ${port},
    \"method\": \"${ss_method}\",
    \"password\": \"${password}\"
}"
}

socks5_append() {
    xray_type="socks5"
    ip=`curl ipinfo.io/ip`
    if ! command -v openssl >/dev/null 2>&1; then
          ${INS} openssl
          judge "openssl 安装"
    fi
    set_port
    echo -e "------------------------------------------"
    read -rp "设置你的用户名: " user
    echo -e "------------------------------------------"
    read -rp "设置你的密码: " password

    wget -Nq ${socks5_append_config_url} -O append.tmp

    sed -i "s~\${password}~$password~" append.tmp
    sed -i "s~\${user}~$user~" append.tmp
    sed -i "s~\${port}~$port~" append.tmp
    echo "," >> append.tmp

    sed -i '/inbounds/ r append.tmp' ${xray_cfg}
    rm append.tmp

    systemctl restart xray

    #link="trojan://${password}@${ip}:${port}#${domain}"

    #clash_config
    #qx_config
}

# outbound end

routing_set() {
    echo -e "是否配置Routing路由"
    read -rp "请输入(y/n): " set_routing
    case $set_routing in
    [yY])
      wget -Nq ${ukonw_url} -O uknow.tmp

      sed -i '4 r uknow.tmp' ${xray_cfg}

      rm uknow.tmp
      ;;
    [nN])
      ;;
    *)
      ;;
    esac

}

set_port() {
    echo -e "------------------------------------------"
    read -rp "设置你的端口(默认443): " input
    if [[ $input =~ ^[0-9]+$ && $input -ge 0 && $input -le 65535 ]]; then
        port=$(echo "$input")
    else
        port="443"
    fi
}

# XRAY END

# SINGBOX START
singbox_onekey_install() {
    is_root
    get_system
    if ! command -v sing-box >/dev/null 2>&1; then
        # adjust_date
        env_install_singbox
        close_firewall
        singbox_install
    fi
    if ! command -v sing-box >/dev/null 2>&1; then
        echo -e "${Red}sing-box 安装失败!!!${Font}"
        exit 1
    fi
    singbox_select
}

singbox_install() {
    bash <(curl -fsSL $singbox_install_url)
}

uninstall_singbox() {
    systemctl stop sing-box
    apt remove sing-box -y
    systemctl daemon-reload
}

singbox_routing_set() {
    echo -e "是否配置sing-box Route路由"
    read -rp "请输入(y/n): " set_routing
    case $set_routing in
    [yY])
      wget -Nq ${singbox_route_url} -O uknow.tmp

      sed -i '2 r uknow.tmp' ${singbox_cfg}

      rm uknow.tmp
      ;;
    [nN])
      ;;
    *)
      ;;
    esac
}

singbox_hy2() {
    set_port
    ${INS} openssl
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) -keyout ${singbox_cfg_path}/server.key -out ${singbox_cfg_path}/server.crt -subj "/CN=live.qq.com" -days 36500 && chmod +775 ${singbox_cfg_path}/server*

    password=`tr -cd '0-9A-Za-z' < /dev/urandom | fold -w50 | head -n1`
    domain=$(curl -s https://ip.me)
    ipv6=$(curl -6 ip.me)

    wget -N ${singbox_hysteria2_url} -O config.yaml

    sed -i "s/\${password}/$password/" config.yaml
    sed -i "s/\${domain}/$domain/" config.yaml
    sed -i "s~114514~$port~" config.yaml

    mv config.yaml ${singbox_cfg}

    singbox_routing_set

    systemctl restart sing-box
    
    xray_type="hysteria2_nodomain"
    link="hysteria2://${password}@${domain}:${port}?peer=https://live.qq.com&insecure=1&obfs=none#${domain}"

    clash_config

    mkdir -p ${singbox_path}

    info_return
}

singbox_vless_reality_h2() {
    password=$(sing-box generate uuid)
    set_port
    port_check $port

    domain="www.fate-go.com.tw"
    xray_type="reality_h2"
    keys=$(sing-box generate reality-keypair)
    private_key=$(echo $keys | awk -F " " '{print $2}')
    public_key=$(echo $keys | awk -F " " '{print $4}')
    # short_id=$(openssl rand -hex 8)
    ip=$(curl ipinfo.io/ip)
    ipv6=$(curl -6 ip.me)

    wget -N ${singbox_vless_reality_h2_url} -O ${singbox_cfg}

    sed -i "s~\${password}~$password~" ${singbox_cfg}
    sed -i "s~\${privateKey}~$private_key~" ${singbox_cfg}
    sed -i "s~\${pubicKey}~$public_key~" ${singbox_cfg}
    sed -i "s~114514~$port~" ${singbox_cfg}

    systemctl restart sing-box

    systemctl enable sing-box

    link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&fp=safari&pbk=$public_key&type=http#$ip"

    clash_config
}

singbox_vless_reality_grpc() {
    password=$(sing-box generate uuid)
    set_port
    port_check $port

    xray_type="reality_grpc"
    domain="www.fate-go.com.tw"
    keys=$(sing-box generate reality-keypair)
    private_key=$(echo $keys | awk -F " " '{print $2}')
    public_key=$(echo $keys | awk -F " " '{print $4}')
    # short_id=$(openssl rand -hex 8)
    ip=$(curl ipinfo.io/ip)
    ipv6=$(curl -6 ip.me)

    wget -N ${singbox_vless_reality_grpc_url} -O ${singbox_cfg}

    sed -i "s~\${password}~$password~" ${singbox_cfg}
    sed -i "s~\${privateKey}~$private_key~" ${singbox_cfg}
    sed -i "s~\${pubicKey}~$public_key~" ${singbox_cfg}
    sed -i "s~\${ws_path}~$ws_path~" ${singbox_cfg}
    sed -i "s~114514~$port~" ${singbox_cfg}

    systemctl restart sing-box

    systemctl enable sing-box

    link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&sid=8eb7bab5a41eb27d&fp=safari&pbk=$public_key&type=grpc&peer=$domain&allowInsecure=1&serviceName=$ws_path&mode=multi#$ip"

    clash_config
}

singbox_vless_reality_tcp() {
    password=$(sing-box generate uuid)
    set_port
    port_check $port

    domain="www.fate-go.com.tw"
    xray_type="reality_tcp"
    keys=$(sing-box generate reality-keypair)
    private_key=$(echo $keys | awk -F " " '{print $2}')
    public_key=$(echo $keys | awk -F " " '{print $4}')
    # short_id=$(openssl rand -hex 8)
    ip=$(curl ipinfo.io/ip)
    ipv6=$(curl -6 ip.me)

    wget -N ${singbox_vless_reality_tcp_url} -O ${singbox_cfg}

    sed -i "s~\${password}~$password~" ${singbox_cfg}
    sed -i "s~\${privateKey}~$private_key~" ${singbox_cfg}
    sed -i "s~\${pubicKey}~$public_key~" ${singbox_cfg}
    sed -i "s~114514~$port~" ${singbox_cfg}

    systemctl restart sing-box 

    systemctl enable sing-box

    link="vless://$password@$ip:$port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$domain&fp=safari&pbk=$public_key&type=tcp&headerType=none#$ip"

    clash_config

}

singbox_vmess_ws_tls() {
    port_check 443
    domain_handle

    xray_type="vmess_ws"
    password=$(sing-box generate uuid)

    wget -N ${singbox_vmess_ws_config_url} -O ${singbox_cfg}

    sed -i "s~114514~443~" ${singbox_cfg}
    sed -i "s~\${password}~$password~" ${singbox_cfg}
    sed -i "s~\${ws_path}~$ws_path~" ${singbox_cfg}
    sed -i "s~\${domain}~$domain~" ${singbox_cfg}

    systemctl restart sing-box
    
    systemctl enable sing-box

    tmp="{\"v\":\"2\",\"ps\":\"${domain}\",\"add\":\"${domain}\",\"port\":\"443\",\"id\":\"${password}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${domain}\",\"path\":\"/${ws_path}\",\"tls\":\"tls\",\"sni\":\"${domain}\",\"alpn\":\"\",\"fp\":\"safari\"}"
    encode_link=$(base64 <<< $tmp)
    link="vmess://$encode_link"

    clash_config
    qx_config
    vmess_ws_tls_outbound_config

}

singbox_trojan_tls_tcp() {
    port_check 443
    domain_handle

    xray_type="trojan_tcp"
    password=$(sing-box generate uuid)

    wget -N ${singbox_trojan_tls_config_url} -O ${singbox_cfg}

    sed -i "s~\${password}~$password~" ${singbox_cfg}
    sed -i "s~\${domain}~$domain~" ${singbox_cfg}

    systemctl restart sing-box
    
    systemctl enable sing-box

    port=443

    link="trojan://${password}@${domain}:${port}?security=tls&type=tcp&headerType=none#${domain}"

    clash_config
    qx_config
}


singbox_shadowsocket() {
    
    encrypt=4
    ss_method="aes-128-gcm"
    set_port
    echo -e "选择加密方法"
    echo -e "${Green}1) 2022-blake3-aes-128-gcm ${Font}"
    echo -e "${Cyan}2) 2022-blake3-aes-256-gcm	${Font}"
    echo -e "${Cyan}3) 2022-blake3-chacha20-poly1305 ${Font}"
    echo -e "${Cyan}4) aes-128-gcm ${Font}"
    echo -e "${Cyan}5) chacha20-ietf-poly1305 ${Font}"
    echo -e "${Cyan}6) xchacha20-ietf-poly1305 ${Font}"
    echo -e ""
    read -rp "选择加密方法(默认为4)：" encrypt
    case $encrypt in
    1)
      password=$(sing-box generate rand 16 --base64)
      ;;
    2)
      password=$(sing-box generate rand 32 --base64)
      ss_method="2022-blake3-aes-256-gcm"
      ;;
    3)
      password=$(sing-box generate rand 32 --base64)
      ss_method="2022-blake3-chacha20-poly1305"
      ;;
    4)
      password=$(sing-box generate rand 16 --base64)
      ss_method="aes-128-gcm"
      ;;
    5)
      password=$(sing-box generate rand 16 --base64)
      ss_method="chacha20-ietf-poly1305"
      ;;
    5)
      password=$(sing-box generate rand 16 --base64)
      ss_method="xchacha20-ietf-poly1305"
      ;;
    *)
      password=$(sing-box generate rand 16 --base64)
      ;;
    esac

    wget -N ${singbox_ss_config_url} -O config.json
    sed -i "s~\${method}~$ss_method~" config.json
    sed -i "s~\${password}~$password~" config.json
    sed -i "s~114514~$port~" config.json
    mv config.json ${singbox_cfg}
    systemctl restart sing-box && systemctl enable sing-box

    tmp="${ss_method}:${password}"
    tmp=$( base64 <<< $tmp)
    domain=`curl ipinfo.io/ip`
    ipv6=$(curl -6 ip.me)
    link="ss://$tmp@${domain}:${port}"

    xray_type="shadowsocket"
    shadowsocket_outbound_config
    clash_config
    qx_config
}

singbox_hy2_append() {
    set_port
    ${INS} openssl
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) -keyout ${singbox_cfg_path}/server.key -out ${singbox_cfg_path}/server.crt -subj "/CN=live.qq.com" -days 36500 && chmod +775 ${singbox_cfg_path}/server*

    password=`tr -cd '0-9A-Za-z' < /dev/urandom | fold -w50 | head -n1`
    domain=$(curl -s https://ip.me)

    wget -N ${singbox_hysteria2_url} -O append.json

    sed -i "s/\${password}/$password/" append.json
    sed -i "s/\${domain}/$domain/" append.json
    sed -i "s~114514~$port~" append.json

    systemctl stop sing-box

    sing-box merge ${singbox_cfg_path}/tmp.json -c ${singbox_cfg_path}/config.json -c  append.json

    rm append.json

    mv ${singbox_cfg_path}/config.json ${singbox_cfg_path}/config.json.bak

    mv ${singbox_cfg_path}/tmp.json ${singbox_cfg_path}/config.json

    systemctl restart sing-box
    
    xray_type="hysteria2_nodomain"

    clash_config
}

singbox_reality_append() {
    password=$(sing-box generate uuid)
    set_port
    port_check $port

    xray_type="reality_grpc"
    domain="www.fate-go.com.tw"
    keys=$(sing-box generate reality-keypair)
    private_key=$(echo $keys | awk -F " " '{print $2}')
    public_key=$(echo $keys | awk -F " " '{print $4}')
    # short_id=$(openssl rand -hex 8)
    ip=$(curl ipinfo.io/ip)

    wget -N ${singbox_vless_reality_grpc_url} -O append.json

    sed -i "s~\${password}~$password~" append.json
    sed -i "s~\${privateKey}~$private_key~" append.json
    sed -i "s~\${ws_path}~$ws_path~" append.json
    sed -i "s~114514~$port~" append.json

    systemctl stop sing-box

    sing-box merge ${singbox_cfg_path}/tmp.json -c ${singbox_cfg_path}/config.json -c  append.json

    rm append.json

    mv ${singbox_cfg_path}/config.json ${singbox_cfg_path}/config.json.bak

    mv ${singbox_cfg_path}/tmp.json ${singbox_cfg_path}/config.json

    systemctl restart sing-box

    vless_reality_grpc_outbound_config
    clash_config
    qx_config
}

singbox_shadowsocket_append() {
    encrypt=4
    ss_method="aes-128-gcm"
    set_port
    echo -e "选择加密方法"
    echo -e "${Green}1) 2022-blake3-aes-128-gcm ${Font}"
    echo -e "${Cyan}2) 2022-blake3-aes-256-gcm	${Font}"
    echo -e "${Cyan}3) 2022-blake3-chacha20-poly1305 ${Font}"
    echo -e "${Cyan}4) aes-128-gcm ${Font}"
    echo -e "${Cyan}5) chacha20-ietf-poly1305 ${Font}"
    echo -e "${Cyan}6) xchacha20-ietf-poly1305 ${Font}"
    echo -e ""
    read -rp "选择加密方法(默认为4)：" encrypt
    case $encrypt in
    1)
      password=$(sing-box generate rand 16 --base64)
      ;;
    2)
      password=$(sing-box generate rand 32 --base64)
      ss_method="2022-blake3-aes-256-gcm"
      ;;
    3)
      password=$(sing-box generate rand 32 --base64)
      ss_method="2022-blake3-chacha20-poly1305"
      ;;
    4)
      password=$(sing-box generate rand 16 --base64)
      ss_method="aes-128-gcm"
      ;;
    5)
      password=$(sing-box generate rand 16 --base64)
      ss_method="chacha20-ietf-poly1305"
      ;;
    5)
      password=$(sing-box generate rand 16 --base64)
      ss_method="xchacha20-ietf-poly1305"
      ;;
    *)
      password=$(sing-box generate rand 16 --base64)
      ;;
    esac

    wget -Nq ${singbox_ss_append_config_url} -O append.json

    sed -i "s~\${password}~$password~" append.json
    sed -i "s~\${method}~$ss_method~" append.json
    sed -i "s~114514~$port~" append.json
    
    systemctl stop sing-box

    sing-box merge ${singbox_cfg_path}/tmp.json -c ${singbox_cfg_path}/config.json -c  append.json

    rm append.json

    mv ${singbox_cfg_path}/config.json ${singbox_cfg_path}/config.json.bak

    mv ${singbox_cfg_path}/tmp.json ${singbox_cfg_path}/config.json

    systemctl restart sing-box

    tmp="${ss_method}:${password}"
    tmp=$( base64 <<< $tmp)
    domain=`curl ipinfo.io/ip`
    link="ss://$tmp@${domain}:${port}"

    xray_type="shadowsocket"
    shadowsocket_outbound_config
    clash_config
    qx_config
}

# SINGBOX END

info() {
    echo -e "${Info} ${Green} $1 ${Font}"
}
ok() {
    echo -e "${OK} ${Green} $1 ${Font}"
}
error() {
    echo -e "${Error} ${RedBG} $1 ${Font}"
}
warn() {
    echo -e "${Warn} ${Yellow} $1 ${Font}"
}

judge() {
    # $? 上一次命令成功为0 失败为随机值
    if [[ 0 -eq $? ]]; then
        ok "$1 完成"
        sleep 1
    else
        error "$1 失败"
        exit 1
    fi
}

open_bbr() {
    is_root
    source '/etc/os-release'
    info "过于老的系统版本会导致开启失败"
    if [[ "${ID}" == "debian" && ${VERSION_ID} -ge 9 ]]; then
        info "检测系统为 debian"
        #echo 'deb http://deb.debian.org/debian buster-backports main' >> /etc/apt/sources.list
        #apt update && apt -t buster-backports install linux-image-amd64
        wget -N ${bbr_config_url} -O /etc/sysctl.conf && sysctl -p
        info "输入一下命令检测是否成功安装"
        info "lsmod | grep bbr"
    elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 18 ]]; then
        info "检测系统为 ubuntu"
        wget -N ${bbr_config_url} -O /etc/sysctl.conf && sysctl -p
        info "输入一下命令检测是否成功安装"
        info "lsmod | grep bbr"
    elif [[ "${ID}"=="centos" ]]; then
        error "centos fuck out!"
        exit 1
    #    INS = "yum install -y"
    # RedHat 系发行版关闭 SELinux
    #if [[ "${ID}" == "centos" || "${ID}" == "ol" ]]; then
    #  sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
    #  setenforce 0
    #fi
    #    env_install
    else
        error "当前系统为 ${ID} ${VERSION_ID} 不在支持的系统列表内"
        exit 1
    fi
}

show_path() {
    echo -e "${Green}xray 配置文件地址:${Font} ${xray_cfg}"
    echo -e "${Green}singbox 配置文件地址:${Font} ${singbox_cfg}"
    echo -e "${Green}hysteria 配置文件地址:${Font} ${hysteria_cfg}"
    echo -e "${Green}nginx配置文件地址:${Font} ${nginx_cfg}"
    echo -e "${Green}分享链接文件地址:${Font} ${xray_info}"
}

info_return() {
    echo -e "------------------------------------------------"
    echo -e "${Green}安装成功!!!!!!!!${Font}"
    echo -e "------------------------------------------------"
    echo -e "${Green}密码为:${Font} ${password}"
    echo -e "${Green}端口为:${Font} ${port}"
    echo -e "${Green}链接:${Font} ${link}"
    if [ -n "$qx_cfg" ]; then
        echo -e "------------------------------------------------"
        echo -e "${Green}QuantumultX配置: ${Font}"
        echo -e "${qx_cfg}"
    fi
    if [ -n "$outbound" ]; then
        echo -e "------------------------------------------------"
        echo -e "${Green}Outbounds配置:${Font}"
        echo -e "${outbound}"
    fi
    if [ -n "$singbox_outbound" ]; then
        echo -e "------------------------------------------------"
        echo -e "${Green}Singbox Outbounds配置:${Font}"
        echo -e "${singbox_outbound}"
    fi
    if [ -n "$clash_cfg" ]; then
        echo -e "------------------------------------------------"
        echo -e "${Green}Clash配置: ${Font}"
        echo -e "${clash_cfg}"
    fi
    echo -e "------------------------------------------------"
    if [ "$xray_type" = "vmess_ws" ]; then
        echo -e "${Yellow}注: 如果套CF需要在SSL/TLS encryption mode 改为 Full ${Font}"
    fi
    
}

show_info() {
    bash -c "$(curl -sL https://raw.githubusercontent.com/uerax/taffy-onekey/master/configuration.sh)" @ xray
}

show_singbox_info() {
    bash -c "$(curl -sL https://raw.githubusercontent.com/uerax/taffy-onekey/master/configuration.sh)" @ singbox
}

server_check() {

    info "开始检测 Xray 服务"

    xray_active=`systemctl is-active xray`

    # result: active or inactive
    if [[ $xray_active = "active" ]]; then
        ok "Xray 服务正常"
    else
        error "Xray 服务异常"
    fi

    info "开始检测 Nginx 服务"

    nginx_active=`systemctl is-active nginx`

    # result: active or inactive
    if [[ $nginx_active = "active" ]]; then
        ok "Nginx 服务正常"
    else
        error "Nginx 服务异常"
    fi

}

update_script() {
    script_path=$(cd `dirname $0`; pwd)
    wget --no-check-certificate -q -O $( readlink -f -- "$0"; ) "https://raw.githubusercontent.com/uerax/taffy-onekey/master/taffy.sh"
    exit
}

xray_upgrade() {
    echo -e "------------------------------------------"
    read -rp "是否安装指定版本(Y/N): " input
    case $input in
    [yY])
      read -rp "输入指定版本(eq: 1.7.5): " version
      bash -c "$(curl -L ${xray_install_url})" @ install --version ${version}
      judge "Xray 更新"
      ;;
    [nN])
      bash -c "$(curl -L ${xray_install_url})" @ install
      judge "Xray 更新"
      ;;
    *)
      bash -c "$(curl -L ${xray_install_url})" @ install
      judge "Xray 更新"
      ;;
    esac
    
}

nginx_select() {
    echo -e "${Purple}-------------------------------- ${Font}"
    echo -e "${Green}1)  安装 Nginx${Font}"
    echo -e "${Yellow}2)  卸载 Nginx${Font}"
    echo -e "${Red}q)  退出${Font}\n"
    echo -e "${Purple}-------------------------------- ${Font}"
    read -rp "输入数字(回车确认): " opt_num
    echo -e ""
    case $opt_num in
    1)
    nginx_install
    ;;
    2)
    uninstall_nginx
    ;;
    q)
    ;;
    *)
    error "请输入正确的数字"
    ;;
    esac
}

uninstall_nginx() {
    info "Nginx 卸载"
    apt purge -y nginx nginx-common nginx-core
    apt autoremove -y
}

uninstall_xray() {
    info "Xray 卸载"
    bash -c "$(curl -L ${xray_install_url})" @ remove --purge
    # rm -rf /home/xray
    rm -rf ${xray_path}
}

uninstall_acme() {
    info "Acme 卸载"
    /root/.acme.sh/acme.sh --uninstall
    rm -r  ~/.acme.sh
    (
        crontab -l | grep -v "bash ${ca_path}/xray-cert-renew.sh"
    ) | crontab -
}

uninstall() {
    echo -e "------------------------------------------"
    read -rp "是否确定要完全卸载(Y/N): " input
    case $input in
    [yY])
      uninstall_xray
      uninstall_nginx
      uninstall_acme
      uninstall_singbox
      echo -e "全部卸载已完成"
    ;;
    *)
    ;;
    esac
}

restart_nginx() {
    info "开始启动 Nginx 服务"
    service nginx restart
    judge "Nginx 启动"
}

close_nginx() {
    info "开始关闭 Nginx 服务"
    service nginx stop
    judge "Nginx 关闭"
}

restart_xray() {
    info "开始启动 Xray 服务"
    systemctl restart xray
    judge "Xray 启动"
}

close_xray() {
    info "开始关闭 Xray 服务"
    systemctl stop xray
    judge "Xray 关闭"
}

renew_ca() {
    read -rp "输入新的域名: " domain
    apply_certificate
    flush_certificate
}

singbox_operation() {
    echo -e "${Purple}-------------------------------- ${Font}"
    echo -e "${Green}1)  启动 Singbox${Font}"
    echo -e "${Yellow}2)  关闭 Singbox${Font}"
    echo -e "${Green}3)  重启 Singbox${Font}"
    echo -e "${Green}4)  查看 Singbox 状态${Font}"
    echo -e "${Green}9)  查看 Singbox 日志${Font}"
    echo -e "${Green}10) 升级 Singbox ${Font}"
    echo -e "${Yellow}99) 卸载 Singbox ${Font}"
    echo -e "${Red}q)  退出${Font}\n"
    echo -e "${Purple}-------------------------------- ${Font}"
    read -rp "输入数字(回车确认): " opt_num
    echo -e ""
      case $opt_num in
      1)
          systemctl start sing-box
          ;;
      2)
          systemctl stop sing-box
          ;;
      3)
          systemctl restart sing-box
          ;;
      4)
          systemctl status sing-box
          ;;
      9)
          journalctl -u sing-box --output cat -f
          ;;
      10)
          bash <(curl -fsSL $singbox_install_url)
          ;;
      99)
          uninstall_singbox
          ;;
      q)
          exit
          ;;
      *)
          error "请输入正确的数字"
          ;;
      esac
}

server_operation() {
    echo -e "${Purple}-------------------------------- ${Font}"
    echo -e "${Green}1)  重启/启动 Nginx${Font}"
    echo -e "${Yellow}2)  关闭 Nginx${Font}"
    echo -e "${Green}3)  重启/启动 Xray${Font}"
    echo -e "${Yellow}4)  关闭 Xray${Font}"
    echo -e "${Gree}5)  操作 Hysteria${Font}"
    echo -e "${Red}q)  结束操作${Font}\n"
    echo -e "${Purple}-------------------------------- ${Font}"
    read -rp "输入数字(回车确认): " opt_num
    echo -e ""
      case $opt_num in
      1)
          restart_nginx
          ;;
      2)
          close_nginx
          ;;
      3)
          restart_xray
          ;;
      4)
          close_xray
          ;;
      5)
          hysteria_operation
          ;;
      q)
          exit
          ;;
      *)
          error "请输入正确的数字"
          ;;
      esac
      server_operation
}

question_answer() {
    echo -e "${Red}1.我啥都不懂${Font}"
    echo -e "${Green}https://github.com/uerax/taffy-onekey/issues 去 New Issue 问${Font}"
    echo -e "${Yellow} ------------------------------------------------ ${Font}"
    echo -e "${Red}2.Nginx 启动失败${Font}"
    echo -e "${Green}执行\"service nginx status\"查看日志${Font}"
    echo -e "${Yellow} ------------------------------------------------ ${Font}"
    echo -e "${Red}3.Xray 启动失败${Font}"
    echo -e "${Green}执行\"systemctl status xray\"查看日志${Font}"
    echo -e "${Yellow} ------------------------------------------------ ${Font}"
    echo -e "${Red}4.一键安装失败${Font}"
    echo -e "${Green}一般是证书获取失败,检查你的域名输入是否正确,还有域名是否绑定了当前机器的 IP ${Font}"
    echo -e "${Yellow} ------------------------------------------------ ${Font}"
    echo -e "${Red}5.ChatGPT访问不了${Font}"
    echo -e "${Green}可能性1): 你的VPS是大陆、香港或美国LA地区  ${Font}"
    echo -e "${Green}可能性2): key失效前往 https://fscarmen.cloudflare.now.cc/ 重新获取 ${Font}"
}

select_append_type() {
    echo -e "${Green}选择要插入的协议 ${Font}"
    echo -e "${Purple}-------------------------------- ${Font}"
    echo -e "${Green}1)  shadowsocket${Font}"
    echo -e "${Green}2)  trojan${Font}"
    echo -e "${Green}3)  socks5${Font}"
    echo -e "${Cyan}4)  vless-reality-tcp${Font}"
    echo -e "${Cyan}5)  vless-reality-grpc${Font}"
    echo -e "${Red}q)  不装了${Font}"
    echo -e "${Purple}-------------------------------- ${Font}\n"
    read -rp "输入数字(回车确认): " menu_num
    echo -e ""
    mkdir -p ${xray_path}
    case $menu_num in
    1)
        shadowsocket_append
        ;;
    2)
        trojan_append
        ;;
    3)
        socks5_append
        ;;
    4)
        vless_reality_tcp_append
        ;;
    5)
        vless_reality_grpc_append
        ;;
    q)
        exit
        ;;
    *)
        error "请输入正确的数字"
        ;;
    esac
    info_return
}

select_singbox_append_type() {
    echo -e "${Green}选择要插入的协议 ${Font}"
    echo -e "${Purple}-------------------------------- ${Font}"
    echo -e "${Green}1)  shadowsocket${Font}"
    echo -e "${Green}2)  hysteria2${Font}"
    echo -e "${Green}3)  vless-reality-grpc${Font}"
    echo -e "${Red}q)  不装了${Font}"
    echo -e "${Purple}-------------------------------- ${Font}\n"
    read -rp "输入数字(回车确认): " menu_num
    echo -e ""
    mkdir -p ${singbox_path}
    case $menu_num in
    1)
        singbox_shadowsocket_append
        ;;
    2)
        singbox_hy2_append
        ;;
    3)
        singbox_reality_append
        ;;
    q)
        exit
        ;;
    *)
        error "请输入正确的数字"
        ;;
    esac
    info_return
}

singbox_select() {
    echo -e "${Green}选择安装的协议 ${Font}"
    echo -e "${Purple}-------------------------------- ${Font}"
    echo -e "${Green}1)  hysteria2${Font}"
    echo -e "${Green}2)  vless-reality-tcp${Font}"
    echo -e "${Green}3)  vless-reality-grpc${Font}"
    echo -e "${Green}4)  vless-reality-h2${Font}"
    echo -e "${Green}5)  shadowsocket${Font}"
    echo -e "${Green}6)  vmess-tls-ws${Font}"
    echo -e "${Green}7)  trojan-tls-tcp${Font}"
    echo -e "${Red}q)  不装了${Font}"
    echo -e "${Purple}-------------------------------- ${Font}\n"
    read -rp "输入数字(回车确认): " menu_num
    echo -e ""
    mkdir -p ${singbox_path}
    case $menu_num in
    1)
        singbox_hy2
        ;;
    2)
        singbox_vless_reality_tcp
        ;;
    3)
        singbox_vless_reality_grpc
        ;;
    4)
        singbox_vless_reality_h2
        ;;
    5)
        singbox_shadowsocket
        ;;
    6)
        singbox_vmess_ws_tls
        ;;
    7)
        singbox_trojan_tls_tcp
        ;;
    q)
        exit
        ;;
    *)
        error "请输入正确的数字"
        exit
        ;;
    esac
    info_return
}

select_type() {
    echo -e "${Green}选择安装的协议 ${Font}"
    echo -e "${Purple}-------------------------------- ${Font}"
    echo -e "${Green}1)  vless-reality-tcp(推荐)${Font}"
    echo -e "${Cyan}2)  vless-reality-grpc(推荐)${Font}"
    echo -e "${Green}3)  vless-reality-h2${Font}"
    echo -e "${Green}11)  trojan-tcp-tls(推荐)${Font}"
    echo -e "${Cyan}21)  vmess-ws-tls${Font}"
    echo -e "${Cyan}31)  shadowsocket${Font}"
    echo -e "${Red}q)  不装了${Font}"
    echo -e "${Purple}-------------------------------- ${Font}\n"
    read -rp "输入数字(回车确认): " menu_num
    echo -e ""
    mkdir -p ${xray_path}
    case $menu_num in
    1)
        vless_reality_tcp
        ;;
    2)
        vless_reality_grpc
        ;;
    3)
        vless_reality_h2
        ;;
    11)
        trojan_tcp_tls
        ;;
    21)
        vmess_ws_tls
        ;;
    31)
        shadowsocket
        ;;
    q)
        exit
        ;;
    *)
        error "请输入正确的数字"
        ;;
    esac
    info_return
}

menu() {
    echo -e "${Cyan}———————————————— 脚本信息 ————————————————${Font}"
    echo -e "\t\t${Yellow}Taffy 脚本${Font}"
    echo -e "\t${Yellow}---Authored By uerax---${Font}"
    echo -e "   ${Yellow}https://github.com/uerax/taffy-onekey${Font}"
    echo -e "\t      ${Yellow}版本号：${version}${Font}"
    echo -e "${Cyan}———————————————— 安装向导 ————————————————${Font}"
    echo -e "${Green}1)   一键安装 Xray${Font}"
    echo -e "${Blue}2)   更新脚本${Font}"
    echo -e "${Green}3)   一键安装 Singbox${Font}"
    echo -e "${Cyan}5)   插入 Singbox 其他协议${Font}"
    echo -e "${Cyan}6)   插入 Xray 其他协议${Font}"
    echo -e "${Cyan}7)   Singbox 协议更换${Font}"
    echo -e "${Cyan}8)   Xray 协议更换${Font}"
    echo -e "${Purple}10)  配置文件路径${Font}"
    echo -e "${Purple}11)  查看 Xray 配置链接${Font}"
    echo -e "${Purple}12)  查看 Singbox 配置链接${Font}"
    echo -e "${Blue}20)  更新伪装站${Font}"
    echo -e "${Cyan}21)  更换域名证书${Font}"
    echo -e "${Purple}31)  安装 / 更新 / 回退 Xray${Font}"
    echo -e "${Yellow}32)  卸载 Xray${Font}"
    echo -e "${Purple}33)  Singbox 操作面板${Font}"
    echo -e "${Green}34)  安装 / 卸载 Nginx${Font}"
    echo -e "${Purple}40)  启动 / 关闭 / 重启服务${Font}"
    echo -e "${Yellow}99)  常见问题${Font}"
    echo -e "${Green}100) 开启bbr${Font}"
    echo -e "${Red}999) 完全卸载${Font}"
    echo -e "${Red}q)   退出${Font}"
    echo -e "${Cyan}————————————————————————————————————————${Font}\n"

    read -rp "输入数字(回车确认)：" menu_num
    echo -e ""
    case $menu_num in
    1)
    install
    ;;
    2)
    update_script
    ;;
    3)
    singbox_onekey_install
    ;;
    5)
    select_singbox_append_type
    ;;
    6)
    select_append_type
    ;;
    7)
    singbox_select 
    ;;
    8)
    select_type
    ;;
    10)
    show_path
    ;;
    11)
    show_info
    ;;
    12)
    show_singbox_info
    ;;
    20)
    update_web
    ;;
    21)
    renew_ca
    ;;
    31)
    xray_upgrade
    ;;
    32)
    uninstall_xray
    ;;
    33)
    singbox_operation
    ;;
    34)
    nginx_select
    ;;
    40)
    server_operation
    ;;
    99)
    question_answer
    ;;
    100)
    open_bbr
    ;;
    999)
    uninstall
    ;;
    q)
    ;;
    *)
    error "请输入正确的数字"
    ;;
    esac
}

case $1 in
    install)
        install
        ;;
    singbox)
        singbox_onekey_install
        ;;
    uninstall)
        uninstall
        ;;
    *)
        menu
        ;;
esac
