#!/usr/bin/env bash

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
stty erase ^?

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

xray_install_url="https://github.com/uerax/xray-script/raw/master/install-release.sh"

version="v1.7.8"

xray_cfg="/usr/local/etc/xray/config.json"
xray_info="/home/xray/xray_info"
xray_log="/home/xray/xray_log"
nginx_cfg="/etc/nginx/conf.d/xray.conf"
web_path="/home/xray/webpage"
web_dir="blog-main"
ca_path="/home/xray/xray_cert"
ca_crt="/home/xray/xray_cert/xray.crt"
ca_key="/home/xray/xray_cert/xray.key"
ws_path="crayfish"
ss_method=""

outbound_method=""
outbound='{"protocol": "freedom"}\n'
routing=""

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
    port_check 80
    port_check 443
    close_firewall
    nginx_install
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
  rm -rf /etc/localtime
  ln -s /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
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

    wget -O web.zip --no-check-certificate https://github.com/bakasine/bakasine.github.io/archive/refs/heads/master.zip
    judge "伪装站 下载"
    unzip web.zip && mv -f bakasine.github.io-master ${web_dir} && rm web.zip
}

update_web() {
    cd ${web_path}
    wget -O web.zip --no-check-certificate https://github.com/bakasine/bakasine.github.io/archive/refs/heads/master.zip
    judge "伪装站 下载"
    unzip web.zip
    rm -rf ./${web_dir}
    mv -f bakasine.github.io-master ${web_dir}
    rm web.zip
}

domain_handle() {
    echo -e "------------------------------------------"
    read -rp "输入你的域名(eg: example.com):" domain
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

    systemctl restart nginx

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

/root/.acme.sh/acme.sh --install-cert -d ${domain} --ecc --fullchain-file ${ca_crt} --key-file ${ca_key}
echo "Xray Certificates Renewed"

chmod +r ${ca_key}
echo "Read Permission Granted for Private Key"

sudo systemctl restart xray
echo "Xray Restarted"
EOF

    chmod +x ${ca_path}/xray-cert-renew.sh

    (
        crontab -l | grep -v "0 1 1 * *   bash ${ca_path}/xray-cert-renew.sh"
        echo "0 1 1 * *   bash ${ca_path}/xray-cert-renew.sh"
    ) | crontab -

}

xray_install() {

    if ! command -v xray >/dev/null 2>&1; then
        wget --no-check-certificate ${xray_install_url}
        judge "Xray安装脚本 下载"
        bash install-release.sh
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
    case $XRAY_TYPE in
      "reality")
        clash_cfg="- name: $ip
  type: vless
  server: $ip
  port: $port
  uuid: $password
  network: tcp
  tls: true
  udp: true
  xudp: true
  flow: xtls-rprx-vision
  servername: ${domain}
  reality-opts:
    public-key: \"$key\"
    short-id: \"$short_id\"
  client-fingerprint: chrome"
      ;;
      esac
    
}

info_return() {
    echo -e "${Green}安装成功!${Font}"
    echo -e "${Green}链接:${Font} ${link}"
    echo -e "${Green}密码为:${Font} ${password}"
    echo -e "${Green}端口为:${Font} ${port}"
    
    echo -e "${Green}Clash配置:"

    echo -e "${Yellow}注: 如果套CF需要在SSL/TLS encryption mode 改为 Full ${Font}"
}

reality() {
    domain_handle
    password=$(xray uuid)
    port=443

    private_key=$(echo $keys | awk -F " " '{print $2}')
    public_key=$(echo $keys | awk -F " " '{print $4}')
    short_id=$(openssl rand -hex 8)
    ip=$(curl ipinfo.io/ip)

    sed -i "s~\"OutboundsPlaceholder\"~$outbound~" ${xray_cfg}
    routing_set

    cat>${xray_info}<<EOF
XRAY_TYPE="reality"
XRAY_ADDR="${ip}"
XRAY_PWORD="${password}"
XRAY_PORT="443"
XRAY_OBFS="tcp"
XRAY_KEY="${public_key}"
XRAY_SHORT_ID="${short_id}"
XRAY_LINK="${link}"
EOF
}

trojan_grpc() {
    domain_handle
    apply_certificate
    flush_certificate
    
    password=$(xray uuid)
    port=443
    
    wget -N https://raw.githubusercontent.com/uerax/xray-script/master/config/Trojan-GRPC/config.json -O ${xray_cfg}

    sed -i "s~\${password}~$password~" ${xray_cfg}
    sed -i "s~\${ws_path}~$ws_path~" ${xray_cfg}

    sed -i "s~\"OutboundsPlaceholder\"~$outbound~" ${xray_cfg}
    routing_set

    systemctl restart xray 

    systemctl enable xray

    sleep 3

    wget -N https://raw.githubusercontent.com/uerax/xray-script/master/config/Trojan-GRPC/nginx.conf -O ${nginx_cfg}

    sed -i "s~\${domain}~$domain~" ${nginx_cfg}
    sed -i "s~\${web_path}~$web_path~" ${nginx_cfg}
    sed -i "s~\${web_dir}~$web_dir~" ${nginx_cfg}
    sed -i "s~\${ca_crt}~$ca_crt~" ${nginx_cfg}
    sed -i "s~\${ca_key}~$ca_key~" ${nginx_cfg}
    sed -i "s~\${ws_path}~$ca_key~" ${nginx_cfg}

    systemctl restart nginx

    link="trojan://${password}@${domain}:${port}?security=tls&type=grpc&serviceName=${ws_path}&mode=gun#${domain}"

    cat>${xray_info}<<EOF
XRAY_TYPE="trojan"
XRAY_ADDR="${domain}"
XRAY_PWORD="${password}"
XRAY_PORT="443"
XRAY_OBFS="grpc"
OBFS_PATH="${ws_path}"
XRAY_LINK="${link}"
EOF
}

trojan_tcp_tls() {
    domain_handle
    apply_certificate
    flush_certificate
    
    password=$(xray uuid)
    port=443
    
    wget -N https://raw.githubusercontent.com/uerax/xray-script/master/config/Trojan-TCP-TLS/config.json -O ${xray_cfg}

    sed -i "s~19191~$port~" ${xray_cfg}
    sed -i "s~\${password}~$password~" ${xray_cfg}
    sed -i "s~\${ca_crt}~$ca_crt~" ${xray_cfg}
    sed -i "s~\${ca_key}~$ca_key~" ${xray_cfg}

    sed -i "s~\"OutboundsPlaceholder\"~$outbound~" ${xray_cfg}
    routing_set

    systemctl restart xray

    systemctl enable xray

    sleep 3

    wget -N https://raw.githubusercontent.com/uerax/xray-script/master/config/Trojan-TCP-TLS/nginx.conf -O ${nginx_cfg}

    sed -i "s~\${domain}~$domain~" ${nginx_cfg}
    sed -i "s~\${web_path}~$web_path~" ${nginx_cfg}
    sed -i "s~\${web_dir}~$web_dir~" ${nginx_cfg}

    systemctl restart nginx

    link="trojan://${password}@${domain}:${port}?security=tls&type=tcp&headerType=none#${domain}"

    cat>${xray_info}<<EOF
XRAY_TYPE="trojan"
XRAY_ADDR="${domain}"
XRAY_PWORD="${password}"
XRAY_PORT="443"
XRAY_OBFS=""
OBFS_PATH=""
XRAY_LINK="${link}"
EOF
}

vmess_ws_tls() {
    domain_handle
    apply_certificate
    flush_certificate

    password=$(xray uuid)

    wget -N https://raw.githubusercontent.com/uerax/xray-script/master/config/VMESS-WS-TLS/config.json -O ${xray_cfg}

    sed -i "s~19191~$port~" ${xray_cfg}
    sed -i "s~\${password}~$password~" ${xray_cfg}
    sed -i "s~\${ws_path}~$ws_path~" ${xray_cfg}

    sed -i "s~\"OutboundsPlaceholder\"~$outbound~" ${xray_cfg}
    routing_set

    systemctl restart xray
    
    systemctl enable xray

    sleep 3

    wget -N https://raw.githubusercontent.com/uerax/xray-script/master/config/VMESS-WS-TLS/nginx.conf -O ${nginx_cfg}

    sed -i "s~\${domain}~$domain~" ${nginx_cfg}
    sed -i "s~\${web_path}~$web_path~" ${nginx_cfg}
    sed -i "s~\${web_dir}~$web_dir~" ${nginx_cfg}
    sed -i "s~\${ca_crt}~$ca_crt~" ${nginx_cfg}
    sed -i "s~\${ca_key}~$ca_key~" ${nginx_cfg}
    sed -i "s~\${ws_path}~$ws_path~" ${nginx_cfg}
    sed -i "s~\${port}~$port~" ${nginx_cfg}

    systemctl restart nginx

    tmp="{\"v\":\"2\",\"ps\":\"${domain}\",\"add\":\"${domain}\",\"port\":\"443\",\"id\":\"${password}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${domain}\",\"path\":\"/${ws_path}\",\"tls\":\"tls\",\"sni\":\"${domain}\",\"alpn\":\"\",\"fp\":\"chrome\"}"
    encode_link=$(base64 <<< $tmp)
    link="vmess://$encode_link"

    cat>${xray_info}<<EOF
XRAY_TYPE="vmess"
XRAY_ADDR="${domain}"
XRAY_PWORD="${password}"
XRAY_PORT="443"
XRAY_OBFS="websocket"
OBFS_PATH="${ws_path}"
XRAY_LINK="${link}"
EOF

}

vless_ws_tls() {
    domain_handle
    apply_certificate
    flush_certificate

    password=$(xray uuid)

    wget -N https://raw.githubusercontent.com/uerax/xray-script/master/config/VLESS-WS-TLS/config.json -O ${xray_cfg}

    sed -i "s~\${ws_path}~$ws_path~" ${xray_cfg}
    sed -i "s~\${password}~$password~" ${xray_cfg}

    sed -i "s~\"OutboundsPlaceholder\"~$outbound~" ${xray_cfg}
    routing_set

    systemctl restart xray && systemctl enable xray

    sleep 3

    wget -N https://raw.githubusercontent.com/uerax/xray-script/master/config/VLESS-WS-TLS/nginx.conf -O ${nginx_cfg}

    sed -i "s~\${domain}~$domain~" ${nginx_cfg}
    sed -i "s~\${web_path}~$web_path~" ${nginx_cfg}
    sed -i "s~\${web_dir}~$web_dir~" ${nginx_cfg}
    sed -i "s~\${ca_crt}~$ca_crt~" ${nginx_cfg}
    sed -i "s~\${ca_key}~$ca_key~" ${nginx_cfg}
    sed -i "s~\${ws_path}~$ws_path~" ${nginx_cfg}

    systemctl restart nginx

    link="vless://${password}@${domain}:443?encryption=none&security=tls&sni=${domain}&type=ws&host=${domain}&path=%2F${ws_path}#${domain}"

    cat>${xray_info}<<EOF
XRAY_TYPE="vless"
XRAY_ADDR="${domain}"
XRAY_PWORD="${password}"
XRAY_PORT="443"
XRAY_OBFS="websocket"
OBFS_PATH="${ws_path}"
XRAY_LINK="${link}"
EOF
}

vless_grpc() {
    domain_handle
    apply_certificate
    flush_certificate

    password=$(xray uuid)

    wget -N https://raw.githubusercontent.com/uerax/xray-script/master/config/VLESS-GRPC/config.json -O ${xray_cfg}
    sed -i "s/\${password}/$password/" ${xray_cfg}
    sed -i "s~\${ws_path}~$ws_path~" ${xray_cfg}

    sed -i "s~\"OutboundsPlaceholder\"~$outbound~" ${xray_cfg}
    routing_set

    systemctl restart xray && systemctl enable xray

    sleep 3

    wget -N https://raw.githubusercontent.com/uerax/xray-script/master/config/VLESS-GRPC/nginx.conf -O ${nginx_cfg}

    sed -i "s/\${domain}/$domain/" ${nginx_cfg}
    sed -i "s/\${web_path}/$web_path/" ${nginx_cfg}
    sed -i "s/\${web_dir}/$web_dir/" ${nginx_cfg}
    sed -i "s~\${ca_crt}~$ca_crt~" ${nginx_cfg}
    sed -i "s~\${ca_key}~$ca_key~" ${nginx_cfg}

    systemctl restart nginx

    link="vless://${password}@${domain}:443?encryption=none&security=tls&sni=${domain}&type=grpc&host=${domain}&path=%2F${ws_path}#${domain}"

    cat>${xray_info}<<EOF
XRAY_TYPE="vless"
XRAY_ADDR="${domain}"
XRAY_PWORD="${password}"
XRAY_PORT="443"
XRAY_OBFS="grpc"
OBFS_PATH="${ws_path}"
XRAY_LINK="${link}"
EOF
}

vless_tcp_xtls_vision() {
    domain_handle
    apply_certificate
    flush_certificate

    password=$(xray uuid)
    vless_tcp_xtls_vision_xray_cfg
    systemctl restart xray && systemctl enable xray
    sleep 3
    vless_tcp_xtls_vision_nginx_cfg
    systemctl restart nginx

    link="vless://${password}@${domain}:443?encryption=none&flow=xtls-rprx-vision&security=tls&type=tcp&headerType=none#${domain}"

    cat>${xray_info}<<EOF
XRAY_TYPE="vless"
XRAY_ADDR="${domain}"
XRAY_PWORD="${password}"
XRAY_PORT="443"
XRAY_FLOW="xtls-rprx-vision"
XRAY_LINK="${link}"
EOF
}

vless_tcp_xtls_vision_nginx_cfg() {
    cd /etc/nginx/ && wget -N https://raw.githubusercontent.com/uerax/xray-script/master/config/VLESS-TCP-XTLS-VISION/nginx.conf -O /etc/nginx/nginx.conf
}

vless_tcp_xtls_vision_xray_cfg() {
    wget -N https://raw.githubusercontent.com/uerax/xray-script/master/config/VLESS-TCP-XTLS-VISION/config.json -O config.json
    sed -i "s/\${password}/$password/" config.json
    sed -i "s~\${ca_crt}~$ca_crt~" config.json
    sed -i "s~\${ca_key}~$ca_key~" config.json

    sed -i "s~\"OutboundsPlaceholder\"~$outbound~" config.json
    routing_set

    mv config.json ${xray_cfg}
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
    port=19191
    echo -e "选择加密方法"
    echo -e "${Green}1) 2022-blake3-aes-128-gcm ${Font}"
    echo -e "${Cyan}2) 2022-blake3-aes-256-gcm	${Font}"
    echo -e "${Cyan}3) 2022-blake3-chacha20-poly1305 ${Font}"
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

    cat>${xray_info}<<EOF
XRAY_TYPE="shadowsocket2022"
XRAY_ADDR="${domain}"
XRAT_METHOD="${ss_method}"
XRAY_PWORD="${password}"
XRAY_PORT="${port}"
XRAY_LINK="${link}"
EOF
}

shadowsocket-2022-config() {
    wget -N https://raw.githubusercontent.com/uerax/xray-script/master/config/Shadowsocket2022/config.json -O config.json
    sed -i "s~\${method}~$ss_method~" config.json
    sed -i "s~\${password}~$password~" config.json
    transfer="N"
    read -rp "是否作为中转添加落地(Y/N)" transfer
    case $transfer in
    "Y")
      outbound_choose
      ;;
    "y")
      outbound_choose
      ;;
    "n")
      sed -i "s~\"OutboundsPlaceholder\"~$outbound~" config.json
      ;;
    "N")
      sed -i "s~\"OutboundsPlaceholder\"~$outbound~" config.json
      ;;
    *)
      sed -i "s~\"OutboundsPlaceholder\"~$outbound~" config.json
      ;;
    esac
    
    sed -i "s~\"rules_placeholder\"~$routing~" config.json

    mv config.json ${xray_cfg}
}

routing_set() {
    echo -e "是否配置Routing路由"
    read -rp "请输入(y/n)" set_routing
    case $set_routing in
    y)
      wget -Nq https://raw.githubusercontent.com/bakasine/clash-rule/master/uknow.txt -O uknow.tmp
  
      uknow=$(cat uknow.tmp)

      rm uknow.tmp

      sed -i "s~\"rules_placeholder\"~$uknow~" ${xray_cfg}
      ;;
    Y)
      wget -Nq https://raw.githubusercontent.com/bakasine/clash-rule/master/uknow.txt -O uknow.tmp
  
      uknow=$(cat uknow.tmp)

      rm uknow.tmp

      sed -i "s~\"rules_placeholder\"~$uknow~" ${xray_cfg}
      ;;
    n)
      sed -i "s~\"rules_placeholder\"~$routing~" ${xray_cfg}
      ;;
    N)
      sed -i "s~\"rules_placeholder\"~$routing~" ${xray_cfg}
      ;;
    *)
      sed -i "s~\"rules_placeholder\"~$routing~" ${xray_cfg}
      ;;
    esac
    

}

outbound_choose() {
    transfer_type=1
    echo -e "选择你的落地协议"
    echo -e "${Cyan}1) Trojan ${Font}"
    echo -e "${Cyan}2) Shadowsocket ${Font}"
    echo -e "${Cyan}3) Vmess ${Font}"
    echo -e ""
    read -rp "请输入输字" transfer
    case $transfer in
    1)
      outbound_trojan
      ;;
    *)
      ;;
    esac

    sed -i "s~\"OutboundsPlaceholder\"~$outbound~" config.json
}

outbound_trojan() {
    wget -Nq https://raw.githubusercontent.com/uerax/xray-script/master/config/Outbounds/Trojan.txt -O outbound.tmp
    read -rp "请输入trojan域名: " address
    sed -i "s~\${address}~$address~" outbound.tmp
    read -rp "请输入trojan密码: " trojan_pw
    sed -i "s~\${password}~$trojan_pw~" outbound.tmp
    read -rp "请输入trojan传输协议(tcp/grpc): " trojan_net
    sed -i "s~\${network}~$trojan_net~" outbound.tmp
    outbound=$(cat outbound.tmp)
    rm outbound.tmp
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
        echo 'deb http://deb.debian.org/debian buster-backports main' >> /etc/apt/sources.list
        apt update && apt -t buster-backports install linux-image-amd64
        echo net.core.default_qdisc=fq >> /etc/sysctl.conf
        echo net.ipv4.tcp_congestion_control=bbr >> /etc/sysctl.conf
        sysctl -p
    elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 18 ]]; then
        info "检测系统为 ubuntu"
        echo net.core.default_qdisc=fq >> /etc/sysctl.conf
        echo net.ipv4.tcp_congestion_control=bbr >> /etc/sysctl.conf
        sysctl -p
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
    echo -e "${Green}分享链接:${Font} ${XRAY_LINK}"
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
    wget --no-check-certificate -q -O $( readlink -f -- "$0"; ) "https://raw.githubusercontent.com/uerax/xray-script/master/xray.sh"
    exit
}

xray_upgrade() {
    bash -c "$(curl -L ${xray_install_url})" @ install
    judge "Xray 更新"
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
    rm ${xray_info}
}

uninstall_acme() {
    info "Acme 卸载"
    /root/.acme.sh/acme.sh --uninstall
    rm -r  ~/.acme.sh
}

uninstall() {
    uninstall_xray
    uninstall_nginx
    uninstall_acme
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

server_operation() {
    echo -e "${Purple}-------------------------------- ${Font}"
    echo -e "${Green}1)  重启/启动 Nginx${Font}"
    echo -e "${Yellow}2)  关闭 Nginx${Font}"
    echo -e "${Green}3)  重启/启动 Xray${Font}"
    echo -e "${Yellow}4)  关闭 Xray${Font}"
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
    echo -e "${Green}https://github.com/uerax/xray-script/issues 去 New Issue 问${Font}"
    echo -e "${Yellow} ------------------------------------------------ ${Font}"
    echo -e "${Red}2.Nginx 启动失败${Font}"
    echo -e "${Green}执行\"service nginx status\"查看日志${Font}"
    echo -e "${Yellow} ------------------------------------------------ ${Font}"
    echo -e "${Red}3.Xray 启动失败${Font}"
    echo -e "${Green}执行\"systemctl status xray\"查看日志${Font}"
    echo -e "${Yellow} ------------------------------------------------ ${Font}"
    echo -e "${Red}4.一键安装失败${Font}"
    echo -e "${Green}一般是证书获取失败,检查你的域名输入是否正确,还有域名是否绑定了当前机器的 IP ${Font}"
}

select_type() {
    echo -e "${Green}选择安装的模式 ${Font}"
    echo -e "${Purple}-------------------------------- ${Font}"
    echo -e "${Green}1)  trojan-tcp-tls(推荐)${Font}"
    echo -e "${Cyan}2)  trojan-grpc${Font}"
    echo -e "${Cyan}3)  vmess-ws-tls${Font}"
    echo -e "${Cyan}4)  vless-ws-tls${Font}"
    echo -e "${Cyan}5)  vless-grpc${Font}"
    echo -e "${Cyan}6)  vless-tcp-xtls-vision${Font}"
    echo -e "${Cyan}7)  shadowsocket-2022${Font}"
    echo -e "${Red}q)  不装了${Font}"
    echo -e "${Purple}-------------------------------- ${Font}\n"
    read -rp "输入数字(回车确认): " menu_num
    echo -e ""
    case $menu_num in
    1)
        trojan_tcp_tls
        ;;
    2)
        trojan_grpc
        ;;
    3)
        vmess_ws_tls
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
    7)
        shadowsocket-2022
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
    echo -e "\t\t${Yellow}Xray 脚本${Font}"
    echo -e "\t${Yellow}---authored by uerax---${Font}"
    echo -e "\t${Yellow}https://github.com/uerax${Font}"
    echo -e "\t\t${Yellow}版本号：${version}${Font}"
    echo -e "${Cyan}——————————————— 安装向导 ———————————————${Font}"
    echo -e "${Green}1)   一键安装${Font}"
    echo -e "${Blue}2)   更新脚本${Font}"
    echo -e "${Green}3)   安装/更新 Xray${Font}"
    echo -e "${Yellow}4)   卸载 Xray${Font}"
    echo -e "${Green}5)   安装 Nginx${Font}"
    echo -e "${Yellow}6)   卸载 Nginx${Font}"
    echo -e "${Purple}7)   启动 / 关闭 / 重启服务${Font}"
    echo -e "${Cyan}8)   Xray 协议更换${Font}"
    echo -e "${Yellow}9)   完全卸载${Font}"
    echo -e "${Purple}10)  配置文件路径${Font}"
    echo -e "${Purple}11)  查看配置链接${Font}"
    echo -e "${Green}12)  检测服务状态${Font}"
    echo -e "${Blue}20)  更新伪装站${Font}"
    echo -e "${Cyan}21)  更换域名证书${Font}"
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
    xray_upgrade
    ;;
    4)
    uninstall_xray
    ;;
    5)
    nginx_install
    ;;
    6)
    uninstall_nginx
    ;;
    7)
    server_operation
    ;;
    8)
    select_type
    info_return 
    ;;
    9)
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

menu
