#!/usr/bin/env bash

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
stty erase ^?

# 伪装站位置 /home/xray/webpage/blog-main
# xray配置文件 /usr/local/etc/xray/config.json
# 

#fonts color
Green="\033[32m" 
Red="\033[31m" 
Yellow="\033[33m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
Font="\033[0m"

#notification information
Info="${Green}[信息]${Font}"
OK="${Green}[OK]${Font}"
Error="${Red}[错误]${Font}"


INS="apt install -y"
Pword=""
domain=""

function get_system() {
    source /etc/os-release
    if [[ "${ID}"=="debian" && ${VERSION_ID} -ge 9 ]]; then
        info "检测系统为 debian"
        apt update
    elif [[ "${ID}"=="ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 18 ]]; then
        info "检测系统为 ubuntu"
        apt update
    elif ["${ID}"=="centos"];then
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

is_root(){
    if [ `id -u` == 0 ]; then 
        ok "进入安装流程"
        sleep 3
    else
        error "请切使用root用户执行脚本"
        info "切换root用户命令: sudo su"
        exit 1
    fi
}

info() {
    echo -e "${Info} ${Green} $1 ${Font}" 
}
ok() {
    echo -e "${OK} ${Green} $1 ${Font}" 
}
error() {
    echo -e "${Error} ${RedBG} $1 ${Font}" 
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

function increase_max_handle() {
  # 最大文件打开数
  sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
  sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
  echo '* soft nofile 65536' >>/etc/security/limits.conf
  echo '* hard nofile 65536' >>/etc/security/limits.conf
}

function env_install(){
    
    ${INS} wget
    judge "wget 安装"
    ${INS} unzip
    judge "unzip 安装"
    ${INS} lsof
    judge "lsof 安装"
}

function nginx_install() {
    # 判断是否有 nginx 命令
    if ! command -v nginx >/dev/null 2>&1; then
        ${INS} nginx
        judge "Nginx 安装"
    else
        ok "Nginx 已存在"
    fi

    mkdir -p /home/xray/webpage/ && cd /home/xray/webpage/

    wget -O web.zip --no-check-certificate https://github.com/hentai121/hentai121.github.io/archive/refs/heads/master.zip
    judge "伪装站 下载"
    unzip web.zip && mv hentai121.github.io-master blog-main && rm web.zip
}

apply_certificate(){
    wget -O -  https://get.acme.sh | sh
    judge "安装acme"
    cd ~ && . .bashrc
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    echo ${domain}

    if /root/.acme.sh/acme.sh --issue -d ${domain} -w /home/xray/webpage/blog-main --keylength ec-256 --force; then
        ok "SSL 证书生成成功"
        sleep 2
        mkdir -p /home/xray/xray_cert
        if /root/.acme.sh/acme.sh --install-cert -d ${domain} --ecc --fullchain-file /home/xray/xray_cert/xray.crt --key-file /home/xray/xray_cert/xray.key; then
            chmod +r /home/xray/xray_cert/xray.key
            ok "SSL 证书配置成功"
            sleep 2
        fi
    else
        error "证书生成失败"
        exit 1
    fi
}

install(){
    is_root
    get_system
    env_install
    # increase_max_handle
    port_check 80
    port_check 443
    nginx_install
    domain_handle
    apply_certificate
    flush_certificate
    xray_install
    xray_configure
    # select_type
    trojan_tcp_xtls
    info_return
}

port_check(){
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

info_return(){
    echo -e "安装成功!"
    echo -e "你的密码为: ${Pword}"
}

# 暂时懒得加 TODO
select_type(){
    echo -e "${Green} 选择安装的模式 ${Font}"
    echo -e "${Green} 1:Trojan-TCP-XTLS ${Font}"
    read -rp "请输入数字: " menu_num
    case $menu_num in
    1)
        trojan_tcp_xtls
        ;;
    *)
        error "请输入正确的数字"
    ;;
    esac
}

trojan_tcp_xtls(){
    wget https://raw.githubusercontent.com/XTLS/Xray-examples/main/Trojan-TCP-XTLS/config_server.json -O /usr/local/etc/xray/config.json
    judge "Xray配置文件 下载"
    sed -i 's/\/path\/to\/cert/\/home\/xray\/xray_cert\/xray.crt/' /usr/local/etc/xray/config.json
    sed -i 's/\/path\/to\/key/\/home\/xray\/xray_cert\/xray.key/' /usr/local/etc/xray/config.json
    systemctl start xray && systemctl enable xray
    sleep 3

    sed -i '4,5d' /etc/nginx/conf.d/xray.conf
    sed -i '3a \\treturn 301 https://$http_host$request_uri;' /etc/nginx/conf.d/xray.conf
    Pword=$(xray uuid)
    sed -i "s/your_password/${Pword}/g" /usr/local/etc/xray/config.json
    sed -i '19,24d' /usr/local/etc/xray/config.json
    sed -i 's/\"dest\".*/"dest": 8080/g' /usr/local/etc/xray/config.json

cat>>/etc/nginx/conf.d/xray.conf<<EOF
server {
   listen 127.0.0.1:8080;
   root /home/xray/webpage/blog-main;
   index index.html;
   add_header Strict-Transport-Security "max-age=63072000" always;
}
EOF
    
}

xray_configure(){
    mkdir -p /home/xray/xray_log && touch /home/xray/xray_log/access.log && touch /home/xray/xray_log/error.log && chmod a+w /home/xray/xray_log/*.log

}

xray_install(){
    wget https://github.com/XTLS/Xray-install/raw/main/install-release.sh
    judge "Xray安装脚本 下载"
    bash install-release.sh
    judge "Xray 安装"
    rm install-release.sh
}

domain_handle(){
    echo -e "------------------------------------------"
    read -rp "请输入你的域名信息(eg: www.example.com):" domain
    ok "正在获取 IP 地址信息"
    parse_ipv4=$(curl -sm8 ipget.net/?"${domain}")
    local_ipv4=$(curl -s4m8 https://ip.gs)
    if [[ ${parse_ipv4} == "${local_ipv4}" ]]; then
        ok "域名ip解析通过"
        sleep 2
    else
        error "域名解析ip: ${parse_ipv4} 与本机不符"
        exit 2
    fi

    sed -i '/\/etc\/nginx\/sites-enabled\//d' /etc/nginx/nginx.conf

    
    systemctl restart xray

    cat>/etc/nginx/conf.d/xray.conf<<EOF
server {
    listen 80;
    server_name ${domain};
    root /home/xray/webpage/blog-main;
    index index.html;
}
EOF

    systemctl restart nginx

    
}

flush_certificate(){
    cat>/home/xray/xray_cert/xray-cert-renew.sh<<EOF
#!/bin/bash

/root/.acme.sh/acme.sh --install-cert -d ${domain} --ecc --fullchain-file /home/xray/xray_cert/xray.crt --key-file /home/xray/xray_cert/xray.key
echo "Xray Certificates Renewed"

chmod +r /home/xray/xray_cert/xray.key
echo "Read Permission Granted for Private Key"

sudo systemctl restart xray
echo "Xray Restarted"
EOF

    chmod +x /home/xray/xray_cert/xray-cert-renew.sh

    ( crontab -l | grep -v "0 1 1 * *   bash /home/xray/xray_cert/xray-cert-renew.sh"; echo "0 1 1 * *   bash /home/xray/xray_cert/xray-cert-renew.sh" ) | crontab -

}

install
