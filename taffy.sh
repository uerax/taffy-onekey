#!/usr/bin/env bash

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
stty erase ^?

version="v1.8.2"

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
xray_install_url="https://github.com/uerax/taffy-onekey/raw/master/install-release.sh"
ukonw_url="https://raw.githubusercontent.com/bakasine/rules/master/xray/uknow.txt"

socks5_append_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Socks5/append.json"

ss_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Shadowsocket2022/config.json"
ss_append_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Shadowsocket2022/append.json"

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

hysteria2_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Hysteria2/config.yaml"
hysteria2_nodomain_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Hysteria2/config_nodomain.yaml"

# SINGBOX URL START
singbox_install_url="https://sing-box.app/deb-install.sh"
tcp_brutal_install_url="https://tcp.hy2.sh/"
singbox_cfg="/etc/sing-box/config.json"
singbox_path="/opt/singbox/"

singbox_vless_reality_h2_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/REALITY-H2/singbox.json"
singbox_vless_reality_grpc_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/REALITY-GRPC/singbox.json"
# SINGBOX URL END

xray_cfg="/usr/local/etc/xray/config.json"
xray_path="/opt/xray/"
xray_info="${xray_path}xray_info"
xray_log="${xray_path}xray_log"
nginx_cfg="/etc/nginx/conf.d/xray.conf"
web_path="${xray_path}webpage"
web_dir="blog-main"
xray_type=""
ca_path="${xray_path}xray_cert"
ca_crt="${xray_path}xray_cert/xray.crt"
ca_key="${xray_path}xray_cert/xray.key"
ws_path="crayfish"
ss_method=""

outbound_method=""
outbound='{"protocol": "freedom"}\n'

INS="apt install -y"
password=""
domain=""
link=""
port="1919"

install() {
    is_root
    get_system
    adjust_date
    env_install
    # increase_max_handle
    close_firewall
    xray_install
    xray_configure
    select_type
    info_return
}

is_root() {
    if [ $(id -u) == 0 ]; then
        ok "进入安装流程"
        sleep 3
    else
        error "请切使用root用户执行脚本"
        info "切换root用户命令: sudo su"
        exit 1
    fi
}

get_system() {
    source '/etc/os-release'
    if [[ "${ID}" == "debian" && ${VERSION_ID} -ge 9 ]]; then
        info "检测系统为 debian"
        apt update
    elif [[ "${ID}"=="ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 18 ]]; then
        info "检测系统为 ubuntu"
        apt update
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

function env_install() {

    ${INS} wget
    judge "wget 安装"
    ${INS} unzip
    judge "unzip 安装"
    ${INS} lsof
    judge "lsof 安装"
    ${INS} curl
    judge "curl 安装"
    ${INS} jq
    judge "jq 安装"
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
        ${INS} nginx
        judge "Nginx 安装"
    else
        ok "Nginx 已存在"
    fi

    mkdir -p ${web_path} && cd ${web_path}

    wget -O web.zip --no-check-certificate ${website_url}
    judge "伪装站 下载"
    unzip web.zip && mv -f bakasine.github.io-master ${web_dir} && rm web.zip
}

update_web() {
    cd ${web_path}
    wget -O web.zip --no-check-certificate ${website_url}
    judge "伪装站 下载"
    unzip web.zip
    rm -rf ./${web_dir}
    mv -f bakasine.github.io-master ${web_dir}
    rm web.zip
}

domain_handle() {
    echo -e "------------------------------------------"
    read -rp "输入你的域名(eg: example.com): " domain
    ok "正在获取 IP 地址信息"
    parse_ipv4=$(curl -sm8 ipget.net/?"${domain}")
    local_ipv4=$(curl -s4m8 https://ifconfig.co)
    if [[ ${parse_ipv4} == "${local_ipv4}" ]]; then
        ok "域名ip解析通过"
        sleep 2
    else
        error "域名解析ip: ${parse_ipv4} 与本机不符, 请检测是否有误"
    fi
}

apply_certificate() {
    sed -i '/\/etc\/nginx\/sites-enabled\//d' /etc/nginx/nginx.conf

    cat > ${nginx_cfg} << EOF
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

    if /root/.acme.sh/acme.sh --issue -d ${domain} -w ${web_path}/${web_dir} --keylength ec-256 --force; then
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

if /root/.acme.sh/acme.sh --issue -d ${domain} -w ${web_path}/${web_dir} --keylength ec-256 --force; then
  sleep 2
  mkdir -p ${ca_path}
  /root/.acme.sh/acme.sh --install-cert -d ${domain} --ecc --fullchain-file ${ca_crt} --key-file ${ca_key}
else
  exit 1
fi

echo "Xray Certificates Renewed"

chmod +r ${ca_key}
echo "Read Permission Granted for Private Key"

sudo systemctl restart xray
sudo service nginx restart
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
    up: 30 Mbps
    down: 100 Mbps
    password: $password
    sni: https://live.qq.com
    skip-cert-verify: true"
    ;;    
    "hysteria2")
    clash_cfg="  - name: $domain
    type: hysteria2
    server: '$domain'
    port: $port
    up: 30 Mbps
    down: 100 Mbps
    password: $password"
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
    client-fingerprint: chrome"
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
    client-fingerprint: chrome"
    ;;
    "reality_grpc_brutal")
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
    client-fingerprint: chrome
    smux:
      enabled: true
      protocol: h2mux
      max-connections: 1
      min-streams: 4
      padding: true
      brutal-opts:
        enabled: true
        up: 30
        down: 100"
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
    client-fingerprint: chrome"
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
    client-fingerprint: chrome"
    ;;
    "reality_h2_brutal")
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
    client-fingerprint: chrome
    smux:
      enabled: true
      protocol: h2mux
      max-connections: 1
      min-streams: 4
      padding: true
      brutal-opts:
        enabled: true
        up: 30
        down: 100"
    ;;
    "shadowsocket2022")
    clash_cfg="  - name: $domain
    type: ss
    server: '$domain'
    port: $port
    cipher: $ss_method
    password: "$password"
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
    "shadowsocket2022")
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

    wget -N ${vless_reality_h2_url} -O ${xray_cfg}

    sed -i "s~\${password}~$password~" ${xray_cfg}
    sed -i "s~\${privateKey}~$private_key~" ${xray_cfg}
    sed -i "s~\${port}~$port~" ${xray_cfg}
    
    routing_set
    vless-reality-h2-outbound-config
    systemctl restart xray 

    systemctl enable xray

    link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&fp=chrome&pbk=$public_key&type=http#$ip"
    clash_config

    cat>${xray_info}<<EOF
XRAY_TYPE="${xray_type}"
XRAY_ADDR="${ip}"
XRAY_PWORD="${password}"
XRAY_PORT="${port}"
XRAY_KEY="${public_key}"
XRAY_LINK="${link}"
CLASH_CONFIG="${clash_cfg}"
XRAY_OUTBOUND="${outbound}"
EOF
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

    vless-reality-h2-outbound-config
    systemctl restart xray 
    link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&fp=chrome&pbk=$public_key&type=http#$ip"
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

    wget -N ${vless_reality_tcp_url} -O ${xray_cfg}

    sed -i "s~\${password}~$password~" ${xray_cfg}
    sed -i "s~\${privateKey}~$private_key~" ${xray_cfg}
    sed -i "s~\${port}~$port~" ${xray_cfg}

    routing_set
    vless-reality-tcp-outbound-config

    systemctl restart xray 

    systemctl enable xray

    service nginx stop

    link="vless://$password@$ip:$port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$domain&fp=chrome&pbk=$public_key&type=tcp&headerType=none#$ip"
    clash_config

    cat>${xray_info}<<EOF
XRAY_TYPE="${xray_type}"
XRAY_ADDR="${ip}"
XRAY_PWORD="${password}"
XRAY_PORT="${port}"
XRAY_KEY="${public_key}"
XRAY_LINK="${link}"
CLASH_CONFIG="${clash_cfg}"
XRAY_OUTBOUND="${outbound}"
EOF
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

    vless-reality-tcp-outbound-config
    systemctl restart xray 
    link="vless://$password@$ip:$port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$domain&fp=chrome&pbk=$public_key&type=tcp&headerType=none#$ip"
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

    wget -N ${vless_reality_grpc_url} -O ${xray_cfg}

    sed -i "s~\${password}~$password~" ${xray_cfg}
    sed -i "s~\${privateKey}~$private_key~" ${xray_cfg}
    sed -i "s~\${ws_path}~$ws_path~" ${xray_cfg}
    sed -i "s~\${port}~$port~" ${xray_cfg}

    routing_set
    vless-reality-grpc-outbound-config

    systemctl restart xray 

    systemctl enable xray

    clash_config
    link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&sid=8eb7bab5a41eb27d&fp=chrome&pbk=$public_key&type=grpc&serviceName=$ws_path&mode=multi#$ip"

    cat>${xray_info}<<EOF
XRAY_TYPE="${xray_type}"
XRAY_ADDR="${ip}"
XRAY_PWORD="${password}"
XRAY_PORT="${port}"
XRAY_OBFS="grpc"
OBFS_PATH="${ws_path}"
XRAY_KEY="${public_key}"
XRAY_LINK="${link}"
CLASH_CONFIG="${clash_cfg}"
XRAY_OUTBOUND="${outbound}"
EOF
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

    vless-reality-grpc-outbound-config
    systemctl restart xray 
    link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&sid=8eb7bab5a41eb27d&fp=chrome&pbk=$public_key&type=grpc&serviceName=$ws_path&mode=multi#$ip"
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

    cat>${xray_info}<<EOF
XRAY_TYPE="${xray_type}"
XRAY_ADDR="${domain}"
XRAY_PWORD="${password}"
XRAY_PORT="${port}"
XRAY_OBFS="grpc"
OBFS_PATH="${ws_path}"
XRAY_LINK="${link}"
CLASH_CONFIG="${clash_cfg}"
XRAY_OUTBOUND="${outbound}"
EOF
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
    trojan-tcp-tls-outbound-config

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

    cat>${xray_info}<<EOF
XRAY_TYPE="${xray_type}"
XRAY_ADDR="${domain}"
XRAY_PWORD="${password}"
XRAY_PORT="${port}"
XRAY_LINK="${link}"
CLASH_CONFIG="${clash_cfg}"
QX_CONFIG="${qx_cfg}"
XRAY_OUTBOUND="${outbound}"
EOF
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

    tmp="{\"v\":\"2\",\"ps\":\"${domain}\",\"add\":\"${domain}\",\"port\":\"443\",\"id\":\"${password}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${domain}\",\"path\":\"/${ws_path}\",\"tls\":\"tls\",\"sni\":\"${domain}\",\"alpn\":\"\",\"fp\":\"chrome\"}"
    encode_link=$(base64 <<< $tmp)
    link="vmess://$encode_link"

    clash_config
    qx_config

    cat>${xray_info}<<EOF
XRAY_TYPE="${xray_type}"
XRAY_ADDR="${domain}"
XRAY_PWORD="${password}"
XRAY_PORT="443"
XRAY_OBFS="websocket"
OBFS_PATH="${ws_path}"
XRAY_LINK="${link}"
CLASH_CONFIG="${clash_cfg}"
QX_CONFIG="${qx_cfg}"
XRAY_OUTBOUND="${outbound}"
EOF
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

    cat>${xray_info}<<EOF
XRAY_TYPE="${xray_type}"
XRAY_ADDR="${domain}"
XRAY_PWORD="${password}"
XRAY_PORT="443"
XRAY_OBFS="websocket"
OBFS_PATH="${ws_path}"
XRAY_LINK="${link}"
CLASH_CONFIG="${clash_cfg}"
XRAY_OUTBOUND="${outbound}"
EOF
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
    sed -i "s/\${password}/$password/" ${xray_cfg}
    sed -i "s~\${ws_path}~$ws_path~" ${xray_cfg}

    routing_set

    systemctl restart xray && systemctl enable xray

    sleep 3

    wget -N ${vless_grpc_nginx_url} -O ${nginx_cfg}

    sed -i "s/\${domain}/$domain/" ${nginx_cfg}
    sed -i "s/\${web_path}/$web_path/" ${nginx_cfg}
    sed -i "s/\${web_dir}/$web_dir/" ${nginx_cfg}
    sed -i "s~\${ca_crt}~$ca_crt~" ${nginx_cfg}
    sed -i "s~\${ca_key}~$ca_key~" ${nginx_cfg}

    service nginx restart

    parts="auto:${password}@${domain}:443"
    encode_parts=$(base64 <<< $parts)
    link="vless://${encode_parts}?encryption=none&security=tls&sni=${domain}&type=grpc&host=${domain}&path=%2F${ws_path}#${domain}"

    cat>${xray_info}<<EOF
XRAY_TYPE="${xray_type}"
XRAY_ADDR="${domain}"
XRAY_PWORD="${password}"
XRAY_PORT="443"
XRAY_OBFS="grpc"
OBFS_PATH="${ws_path}"
XRAY_LINK="${link}"
CLASH_CONFIG="${clash_cfg}"
XRAY_OUTBOUND="${outbound}"
EOF
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

    cat>${xray_info}<<EOF
XRAY_TYPE="${xray_type}"
XRAY_ADDR="${domain}"
XRAY_PWORD="${password}"
XRAY_PORT="443"
XRAY_FLOW="xtls-rprx-vision"
XRAY_LINK="${link}"
CLASH_CONFIG="${clash_cfg}"
XRAY_OUTBOUND="${outbound}"
EOF
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
    trojan-config

    link="trojan://${password}@${ip}:${port}#${domain}"

    trojan-outbound-config
    clash_config
    qx_config

    cat>${xray_info}<<EOF
XRAY_TYPE="${xray_type}"
XRAY_ADDR="${ip}"
XRAY_PWORD="${password}"
XRAY_PORT="${port}"
XRAY_LINK="${link}"
CLASH_CONFIG="${clash_cfg}"
QX_CONFIG="${qx_cfg}"
XRAY_OUTBOUND="${outbound}"
EOF
}

trojan-config() {
    wget -N ${trojan_config_url} -O config.json
    sed -i "s~\${port}~$port~" config.json
    sed -i "s~\${password}~$password~" config.json
    
    mv config.json ${xray_cfg}
    systemctl restart xray && systemctl enable xray
}

trojan-append() {
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

    trojan-outbound-config
    clash_config
    qx_config
}

shadowsocket-2022() {
    
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

    shadowsocket-2022-config
    systemctl restart xray && systemctl enable xray

    tmp="${ss_method}:${password}"
    tmp=$( base64 <<< $tmp)
    domain=`curl ipinfo.io/ip`
    link="ss://$tmp@${domain}:${port}"

    xray_type="shadowsocket2022"
    shadowsocket-2022-outbound-config
    clash_config
    qx_config

    cat>${xray_info}<<EOF
XRAY_TYPE="${xray_type}"
XRAY_ADDR="${domain}"
XRAT_METHOD="${ss_method}"
XRAY_PWORD="${password}"
XRAY_PORT="${port}"
XRAY_LINK="${link}"
CLASH_CONFIG="${clash_cfg}"
QX_CONFIG="${qx_config}"
XRAY_OUTBOUND="${outbound}"
EOF
}

shadowsocket-2022-config() {
    wget -N ${ss_config_url} -O config.json
    sed -i "s~\${method}~$ss_method~" config.json
    sed -i "s~\${password}~$password~" config.json
    sed -i "s~\${port}~$port~" config.json
    mv config.json ${xray_cfg}
}

shadowsocket-2022-append() {
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
    link="ss://$tmp@${domain}:${port}"

    xray_type="shadowsocket2022"
    shadowsocket-2022-outbound-config
    clash_config
    qx_config
}

# outbound start

vless-reality-grpc-outbound-config() {
    outbound=" {
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
            \"fingerprint\": \"chrome\",
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
    }
}"
}

vless-reality-tcp-outbound-config() {
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
            \"fingerprint\": \"chrome\",
            \"serverName\": \"${domain}\",
            \"publicKey\": \"${public_key}\",
            \"shortId\": \"8eb7bab5a41eb27d\",
            \"spiderX\": \"/\"
        }
    }
}"
}

trojan-tcp-tls-outbound-config() {
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
    }
}"
}

vless-reality-h2-outbound-config() {
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
            \"fingerprint\": \"chrome\",
            \"serverName\": \"${domain}\",
            \"publicKey\": \"${public_key}\",
            \"shortId\": \"8eb7bab5a41eb27d\",
            \"spiderX\": \"/\"
        }
    }
}"
}

trojan-outbound-config() {
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
    }
}"
}

shadowsocket-2022-outbound-config() {
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
}

socks5-append() {
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

hysteria_install() {
    echo -e "------------------------------------------"
    read -rp "是否安装指定版本(Y/N): " input
    case $input in
    [yY])
      read -rp "输入指定版本(eq: 2.2.2): " version
      bash <(curl -fsSL https://get.hy2.sh/)  --version v${version}
      ;;
    *)
      bash <(curl -fsSL https://get.hy2.sh/)
      ;;
    esac
}

hysteria2() {
    is_root
    get_system
    adjust_date
    ${INS} curl
    judge "curl 安装"

    hysteria_install

    echo -e "------------------------------------------"
    read -rp "是否使用域名(Y/N): " hasDmain
    case $hasDmain in
    [yY])
      hysteria2_domain
      ;;
    [nN])
      hysteria2_without_domain
      ;;
    *)
      hysteria2_without_domain
      ;;
    esac
    
}

hysteria2_without_domain() {
    set_port
    ${INS} openssl
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) -keyout /etc/hysteria/server.key -out /etc/hysteria/server.crt -subj "/CN=live.qq.com" -days 36500 && chown hysteria /etc/hysteria/server.key &&  chown hysteria /etc/hysteria/server.crt && chmod +775 /etc/hysteria/server*

    password=`tr -cd '0-9A-Za-z' < /dev/urandom | fold -w50 | head -n1`
    domain=$(curl -s https://ip.me)

    wget -N ${hysteria2_nodomain_config_url} -O config.yaml

    sed -i "s/\${password}/$password/" config.yaml
    sed -i "s/\${domain}/$domain/" config.yaml
    sed -i "s/\${port}/$port/" config.yaml

    mv config.yaml /etc/hysteria/config.yaml

    systemctl start hysteria-server.service
    systemctl enable hysteria-server.service
    
    xray_type="hysteria2_nodomain"

    clash_config
    mkdir -p ${xray_path}
    cat>${xray_info}<<EOF
XRAY_TYPE="${xray_type}"
XRAY_ADDR="${domain}"
XRAY_PWORD="${password}"
XRAY_PORT="${port}"
CLASH_CONFIG="${clash_cfg}"
EOF
    info_return
}

hysteria2_domain() {
    domain_handle
    set_port
    password=`tr -cd '0-9A-Za-z' < /dev/urandom | fold -w50 | head -n1`
    wget -N ${hysteria2_config_url} -O config.yaml

    sed -i "s/\${password}/$password/" config.yaml
    sed -i "s/\${port}/$port/" config.yaml
    sed -i "s/\${domain}/$domain/" config.yaml

    mv config.yaml /etc/hysteria/config.yaml

    systemctl start hysteria-server.service
    systemctl enable hysteria-server.service
    xray_type="hysteria2"

    clash_config

    mkdir -p ${xray_path}
    cat>${xray_info}<<EOF
XRAY_TYPE="${xray_type}"
XRAY_ADDR="${domain}"
XRAY_PWORD="${password}"
XRAY_PORT="${port}"
CLASH_CONFIG="${clash_cfg}"
EOF
    info_return
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
    adjust_date
    env_install
    close_firewall
    singbox_install
    singbox_select
    info_return
}

singbox_install() {
    bash <(curl -fsSL $singbox_install_url)
    bash <(curl -fsSL $tcp_brutal_install_url)
}

singbox_vless_reality_h2() {
    password=$(xray uuid)
    set_port
    port_check $port

    domain="www.fate-go.com.tw"
    xray_type="reality_h2_brutal"
    keys=$(xray x25519)
    private_key=$(echo $keys | awk -F " " '{print $3}')
    public_key=$(echo $keys | awk -F " " '{print $6}')
    # short_id=$(openssl rand -hex 8)
    ip=$(curl ipinfo.io/ip)

    wget -N ${singbox_vless_reality_h2_url} -O ${singbox_cfg}

    sed -i "s~\${password}~$password~" ${singbox_cfg}
    sed -i "s~\${privateKey}~$private_key~" ${singbox_cfg}
    sed -i "s~\${port}~$port~" ${singbox_cfg}

    systemctl restart singbox

    systemctl enable singbox

    clash_config

    cat>${xray_info}<<EOF
XRAY_TYPE="${xray_type}"
XRAY_ADDR="${ip}"
XRAY_PWORD="${password}"
XRAY_PORT="${port}"
XRAY_KEY="${public_key}"
XRAY_LINK="${link}"
CLASH_CONFIG="${clash_cfg}"
EOF
}

singbox_vless_reality_grpc() {
    password=$(xray uuid)
    set_port
    port_check $port

    xray_type="reality_grpc_brutal"
    keys=$(xray x25519)
    private_key=$(echo $keys | awk -F " " '{print $3}')
    public_key=$(echo $keys | awk -F " " '{print $6}')
    # short_id=$(openssl rand -hex 8)
    ip=$(curl ipinfo.io/ip)

    wget -N ${singbox_vless_reality_grpc_url} -O ${singbox_cfg}

    sed -i "s~\${password}~$password~" ${singbox_cfg}
    sed -i "s~\${privateKey}~$private_key~" ${singbox_cfg}
    sed -i "s~\${ws_path}~$ws_path~" ${singbox_cfg}
    sed -i "s~\${port}~$port~" ${singbox_cfg}

    systemctl restart singbox

    systemctl enable singbox

    clash_config

    cat>${xray_info}<<EOF
XRAY_TYPE="${xray_type}"
XRAY_ADDR="${ip}"
XRAY_PWORD="${password}"
XRAY_PORT="${port}"
XRAY_KEY="${public_key}"
XRAY_LINK="${link}"
CLASH_CONFIG="${clash_cfg}"
EOF
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
    echo -e "${Green}xray配置文件地址:${Font} ${xray_cfg}"
    echo -e "${Green}nginx配置文件地址:${Font} ${nginx_cfg}"
    echo -e "${Green}分享链接文件地址:${Font} ${xray_info}"
}

info_return() {
    echo -e "${Green}安装成功!${Font}"
    echo -e "${Green}链接:${Font} ${link}"
    echo -e "${Red}分享链接可能不可用,建议手动填写客户端参数${Font}"
    echo -e "${Green}密码为:${Font} ${password}"
    echo -e "${Green}端口为:${Font} ${port}"
    echo -e "------------------------------------------------"
    echo -e "${Green}Clash配置: ${Font}"
    echo -e "${clash_cfg}"
    echo -e "------------------------------------------------"
    echo -e "${Green}QuantumultX配置: ${Font}"
    echo -e "${qx_cfg}"
    echo -e "------------------------------------------------"
    echo -e "${Green}Outbounds配置:${Font}"
    echo -e "${outbound}"
    echo -e "------------------------------------------------"

    echo -e "${Yellow}注: 如果套CF需要在SSL/TLS encryption mode 改为 Full ${Font}"
}

show_info() {
    source ${xray_info}
    judge "查看配置"
    echo -e "${Green}协议:${Font} ${XRAY_TYPE}"
    echo -e "${Green}地址:${Font} ${XRAY_ADDR}"
    echo -e "${Green}密码:${Font} ${XRAY_PWORD}"
    echo -e "${Green}端口:${Font} ${XRAY_PORT}"
    echo -e "${Green}混淆:${Font} ${XRAY_OBFS}"
    echo -e "${Green}混淆路径:${Font} ${OBFS_PATH}"
    echo -e "${Green}PubKey(REALITY):${Font} ${XRAY_KEY}"
    echo -e "${Green}分享链接:${Font} ${XRAY_LINK}"
    echo -e "${Red}分享链接可能不可用,建议手动填写客户端参数${Font}"
    echo -e "${Green}Clash配置:${Font}"
    echo -e "${CLASH_CONFIG}"
    echo -e "------------------------------------------------"
    echo -e "${Green}QuantumultX配置:${Font}"
    echo -e "${QX_CONFIG}"
    echo -e "------------------------------------------------"
    echo -e "${Green}Outbounds配置:${Font}"
    echo -e "${XRAY_OUTBOUND}"
    echo -e "------------------------------------------------"
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

uninstall_hysteria2() {
    bash <(curl -fsSL https://get.hy2.sh/) --remove
}

uninstall() {
    echo -e "------------------------------------------"
    read -rp "是否确定要完全卸载(Y/N): " input
    case $input in
    [yY])
      uninstall_xray
      uninstall_nginx
      uninstall_acme
      uninstall_hysteria2
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

hysteria_operation() {
    echo -e "${Purple}-------------------------------- ${Font}"
    echo -e "${Green}1)  启动 Hysteria${Font}"
    echo -e "${Yellow}2)  关闭 Hysteria${Font}"
    echo -e "${Green}3)  重启 Hysteria${Font}"
    echo -e "${Green}4)  查看 Hysteria 状态${Font}"
    echo -e "${Green}9)  安装 / 升级 Hysteria${Font}"
    echo -e "${Red}q)  退出${Font}\n"
    echo -e "${Purple}-------------------------------- ${Font}"
    read -rp "输入数字(回车确认): " opt_num
    echo -e ""
      case $opt_num in
      1)
          systemctl start hysteria-server.service
          ;;
      2)
          systemctl stop hysteria-server.service
          ;;
      3)
          systemctl restart hysteria-server.service
          ;;
      4)
          systemctl status hysteria-server.service
          ;;
      9)
          hysteria_install
          ;;
      q)
          exit
          ;;
      *)
          error "请输入正确的数字"
          ;;
      esac
      hysteria_operation
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
    echo -e "${Green}1)  shadowsocket-2022${Font}"
    echo -e "${Green}2)  trojan${Font}"
    echo -e "${Green}3)  socks5${Font}"
    echo -e "${Cyan}4)  vless-reality-tcp${Font}"
    echo -e "${Cyan}5)  vless-reality-grpc${Font}"
    echo -e "${Cyan}6)  vless-reality-h2${Font}"
    echo -e "${Red}q)  不装了${Font}"
    echo -e "${Purple}-------------------------------- ${Font}\n"
    read -rp "输入数字(回车确认): " menu_num
    echo -e ""
    mkdir -p ${xray_path}
    case $menu_num in
    1)
        shadowsocket-2022-append
        ;;
    2)
        trojan-append
        ;;
    3)
        socks5-append
        ;;
    4)
        vless_reality_tcp_append
        ;;
    5)
        vless_reality_grpc_append
        ;;
    6)
        vless_reality_h2_append
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
    echo -e "${Green}1)  vless-reality-h2-brutal${Font}"
    echo -e "${Cyan}2)  vless-reality-grpc-brutal${Font}"
    echo -e "${Red}q)  不装了${Font}"
    echo -e "${Purple}-------------------------------- ${Font}\n"
    read -rp "输入数字(回车确认): " menu_num
    echo -e ""
    mkdir -p ${singbox_path}
    case $menu_num in
    1)
        singbox_vless_reality_h2
        ;;
    2)
        singbox_vless_reality_grpc
        ;;
    q)
        exit
        ;;
    *)
        error "请输入正确的数字"
        ;;
    esac
}

select_type() {
    echo -e "${Green}选择安装的协议 ${Font}"
    echo -e "${Purple}-------------------------------- ${Font}"
    echo -e "${Green}1)  vless-reality-tcp(推荐)${Font}"
    echo -e "${Cyan}2)  vless-reality-grpc(推荐)${Font}"
    echo -e "${Green}3)  vless-reality-h2${Font}"
    echo -e "${Cyan}4)  vless-ws-tls${Font}"
    echo -e "${Cyan}5)  vless-grpc${Font}"
    echo -e "${Cyan}6)  vless-tcp-xtls-vision${Font}"
    echo -e "${Green}11)  trojan-tcp-tls(推荐)${Font}"
    echo -e "${Cyan}12)  trojan-grpc${Font}"
    echo -e "${Cyan}21)  vmess-ws-tls${Font}"
    echo -e "${Cyan}31)  shadowsocket-2022${Font}"
    echo -e "${Cyan}32)  trojan${Font}"
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
    4)
        vless_ws_tls
        ;;
    5)
        vless_grpc
        ;;
    6)
        vless_tcp_xtls_vision
        ;;
    11)
        trojan_tcp_tls
        ;;
    12)
        trojan_grpc
        ;;
    21)
        vmess_ws_tls
        ;;
    31)
        shadowsocket-2022
        ;;
    32)
        trojan
        ;;
    q)
        exit
        ;;
    *)
        error "请输入正确的数字"
        ;;
    esac
}

menu() {
    echo -e "${Cyan}——————————————— 脚本信息 ———————————————${Font}"
    echo -e "\t\t${Yellow}Taffy 脚本${Font}"
    echo -e "\t${Yellow}---authored by uerax---${Font}"
    echo -e "\t${Yellow}https://github.com/uerax${Font}"
    echo -e "\t\t${Yellow}版本号：${version}${Font}"
    echo -e "${Cyan}——————————————— 安装向导 ———————————————${Font}"
    echo -e "${Green}1)   一键安装 Xray${Font}"
    echo -e "${Blue}2)   更新脚本${Font}"
    echo -e "${Green}3)   一键安装 Singbox${Font}"
    echo -e "${Cyan}7)   插入 Xray 其他协议${Font}"
    echo -e "${Cyan}8)   Xray 协议更换${Font}"
    echo -e "${Yellow}9)   完全卸载${Font}"
    echo -e "${Purple}10)  配置文件路径${Font}"
    echo -e "${Purple}11)  查看配置链接${Font}"
    echo -e "${Green}12)  检测服务状态${Font}"
    echo -e "${Blue}20)  更新伪装站${Font}"
    echo -e "${Cyan}21)  更换域名证书${Font}"
    echo -e "${Green}30)  一键安装 Hysteria${Font}"
    echo -e "${Yellow}31)  卸载 Hysteria${Font}"
    echo -e "${Purple}32)  安装 / 更新 / 启动 Hysteria${Font}"
    echo -e "${Green}33)  安装 / 更新 / 回退 Xray${Font}"
    echo -e "${Yellow}34)  卸载 Xray${Font}"
    echo -e "${Green}35)  安装 Nginx${Font}"
    echo -e "${Yellow}36)  卸载 Nginx${Font}"
    echo -e "${Purple}40)  启动 / 关闭 / 重启服务${Font}"
    echo -e "${Red}99)  常见问题${Font}"
    echo -e "${Green}100) 开启bbr${Font}"
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
    7)
    select_append_type
    info_return 
    ;;
    8)
    select_type
    info_return 
    ;;
    39)
    uninstall
    ;;
    10)
    show_path
    ;;
    11)
    show_info
    ;;
    12)
    server_check
    ;;
    20)
    update_web
    ;;
    21)
    renew_ca
    ;;
    30)
    hysteria2
    ;;
    31)
    uninstall_hysteria2
    ;;
    32)
    hysteria_operation
    ;;
    33)
    xray_upgrade
    ;;
    34)
    uninstall_xray
    ;;
    35)
    nginx_install
    ;;
    36)
    uninstall_nginx
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
    hysteria)
        hysteria2
        ;;
    uninstall)
        uninstall
        ;;
    *)
        menu
        ;;
esac
