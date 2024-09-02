#!/usr/bin/env bash

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
stty erase ^?/

version="v2.0.0"

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

xray_install_url="https://gh-proxy.com/https://github.com/uerax/taffy-onekey/raw/master/install-xray-cn.sh"
ukonw_url="https://gh-proxy.com/https://raw.githubusercontent.com/bakasine/rules/master/xray/uknow.txt"

ss_config_url="https://gh-proxy.com/https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Shadowsocket2022/config.json"

bbr_config_url="https://gh-proxy.com/https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/BBR/sysctl.conf"

trojan_config_url="https://gh-proxy.com/https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Trojan/config.json"


xray_cfg="/usr/local/etc/xray/config.json"
xray_path="/opt/xray/"
xray_info="${xray_path}xray_info"
xray_log="${xray_path}xray_log"
xray_type=""

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
    env_install
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

env_install() {

    ${INS} wget
    judge "wget 安装"
    ${INS} zip
    judge "zip 安装"
    ${INS} lsof
    judge "lsof 安装"
    ${INS} curl
    judge "curl 安装"
    ${INS} jq
    judge "jq 安装"
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

    wget -O web.zip --no-check-certificate ${website_url}
    judge "伪装站 下载"
    unzip web.zip && mv -f bakasine.github.io-master ${web_dir} && rm web.zip
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

xray_install() {

    if ! command -v xray >/dev/null 2>&1; then
        bash <(curl -fsSL $xray_install_url)
        judge "Xray 安装"
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
}

trojan-config() {
    wget -N ${trojan_config_url} -O config.json
    sed -i "s~\${port}~$port~" config.json
    sed -i "s~\${password}~$password~" config.json
    
    mv config.json ${xray_cfg}
    systemctl restart xray && systemctl enable xray
}

shadowsocket-2022() {
    
    info "Shadowsocket不需要Nginx, 可以通过脚本一键卸载"
    close_nginx()
    if ! command -v openssl >/dev/null 2>&1; then
          ${INS} openssl
          judge "openssl 安装"
    fi
    encrypt=1
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
}

shadowsocket-2022-config() {
    wget -N ${ss_config_url} -O config.json
    sed -i "s~\${method}~$ss_method~" config.json
    sed -i "s~\${password}~$password~" config.json
    sed -i "s~\${port}~$port~" config.json
    mv config.json ${xray_cfg}
}

# outbound start

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

# outbound end

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
    bash -c "$(curl -sL https://gh-proxy.com/https://raw.githubusercontent.com/uerax/taffy-onekey/master/configuration.sh)" @ xray
}

update_script() {
    script_path=$(cd `dirname $0`; pwd)
    wget --no-check-certificate -q -O $( readlink -f -- "$0"; ) "https://gh-proxy.com/https://raw.githubusercontent.com/uerax/taffy-onekey/master/taffy-cn.sh"
    exit
}

xray_upgrade() {
    bash -c "$(curl -L ${xray_install_url})"
    judge "Xray 更新"
}

uninstall_xray() {
    info "Xray 卸载"
    systemctl stop xray
    rm /etc/systemd/system/xray.service
    rm /usr/local/bin/xray
}

select_type() {
    echo -e "${Green}选择安装的模式 ${Font}"
    echo -e "${Purple}-------------------------------- ${Font}"
    echo -e "${Cyan}1)  shadowsocket-2022${Font}"
    echo -e "${Cyan}2)  trojan${Font}"
    echo -e "${Red}q)  不装了${Font}"
    echo -e "${Purple}-------------------------------- ${Font}\n"
    read -rp "输入数字(回车确认): " menu_num
    echo -e ""
    mkdir -p ${xray_path}
    case $menu_num in
    1)
        shadowsocket-2022
        ;;
    2)
        trojan
        ;;
    q)
        exit
        ;;
    *)
        error "请输入正确的数字"
        select_type
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
    echo -e "${Green}3)   安装/更新 Xray${Font}"
    echo -e "${Cyan}4)   Xray 协议更换${Font}"
    echo -e "${Purple}11)  查看配置链接${Font}"
    echo -e "${Green}100) 开启bbr${Font}"
    echo -e "${Red}999) 卸载 Xray${Font}"
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
    xray_upgrade
    ;;
    4)
    select_type
    info_return
    ;;
    11)
    show_info
    ;;
    100)
    open_bbr
    ;;
    999)
    uninstall_xray
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
    *)
        menu
        ;;
esac
