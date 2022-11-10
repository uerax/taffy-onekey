#!/usr/bin/env bash

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
stty erase ^?

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
Domain=""

function get_system() {
    source /etc/os-release
    if[ "${ID}"=="debian" && ${VERSION_ID} -ge 9 ];then
    elif[ "${ID}"=="ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 18 ];then
    #elif["${ID}"=="centos" && ${VERSION_ID} -ge 7];then    
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

    wget -O web.zip --no-check-certificate https://github.com/uerax/blog/archive/refs/heads/main.zip 
    judge "伪装站 下载"
    unzip web.zip && rm web.zip

    # 去除80端口默认占用
}

domain_handle(){

    read -rp "请输入你的域名信息(eg: www.example.com):" domain
    Domain=${domaim}
    ok "正在获取 IP 地址信息"
    parse_ipv4=$(curl -sm8 ipget.net/?"${domaim}")
    local_ipv4=$(curl -s4m8 https://ip.gs)
    if [[ ${parse_ipv4} == "${local_ipv4}" ]]; then
        ok "域名ip解析通过"
        sleep 2
    else
        error "域名解析ip: ${parse_ipv4} 与本机不符"
        exit 2
    fi

    sed -i '/\/etc\/nginx\/sites-enabled\//d' /etc/nginx/nginx.conf
    cat>/etc/nginx/conf.d/xray.conf<<EOF
    server {
        listen 80;
        server_name ${domaim};
        root /home/xray/webpage/blog-main;
        index index.html;
    }
    EOF
}

apply_certificate(){
    wget -O -  https://get.acme.sh | sh
    judge "安装acme"
    cd ~ && . .bashrc
    acme.sh --upgrade --auto-upgrade

    if acme.sh --issue --insecure -d "${Domain}" --webroot /home/xray/webpage/blog-main -k ec-256 --force; then
        ok "SSL 证书生成成功"
        sleep 2
        mkdir -p /home/xray/xray_cert
        if acme.sh --install-cert -d ${Domain} --ecc --fullchain-file /home/xray/xray_cert/xray.crt --key-file /home/xray/xray_cert/xray.key; then
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
    increase_max_handle
    nginx_install
    apply_certificate
}




