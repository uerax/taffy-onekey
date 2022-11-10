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

INS = "apt install -y"

function get_system() {
    source /etc/os-release
    if["${ID}"=="debian" && ${VERSION_ID} -ge 9];then
        # do debian
        env_install()
        
    elif["${ID}"=="ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 18];then   
        # do ubuntu
        env_install()
    elif["${ID}"=="centos" && ${VERSION_ID} -ge 7];then    
        # do centos
        INS = "yum"
        env_install()
    else
        print_error "当前系统为 ${ID} ${VERSION_ID} 不在支持的系统列表内"
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
  if [[ 0 -eq $? ]]; then
    ok "$1 完成"
    sleep 1
  else
    error "$1 失败"
    exit 1
  fi
}

env_install(){
    ${INS} wget unzip lsof

    if ! command -v nginx >/dev/null 2>&1; then
        ${INS} nginx
        judge "Nginx 安装"
    else
        ok "Nginx 已存在"
    fi

}