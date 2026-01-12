#!/bin/sh

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binstty 

stty erase ^?

version="v4.1.3"

#fonts color
Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
Blue="\033[0;34m"         # Blue
Purple="\033[0;35m"       # Purple
Cyan="\033[0;36m"         # Cyan
White="\033[0;37m"

GreenBG="\033[42;37m"
RedBG="\033[41;37m"
Font="\033[0m"

#notification information
Info="${Green}[信息]${Font}"
Warn="${Yellow}[警告]${Font}"
OK="${Green}[OK]${Font}"
Error="${Red}[错误]${Font}"

bbr_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/BBR/sysctl.conf"
ukonw_url="https://raw.githubusercontent.com/bakasine/rules/master/xray/uknow.txt"

xray_install_url="https://github.com/uerax/taffy-onekey/raw/master/install-xray.sh"

xray_socks5_append_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Socks5/append.json"

xray_ss_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Shadowsocket/config.json"
xray_ss_append_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Shadowsocket/append.json"

xray_vless_reality_tcp_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/REALITY-TCP/config.json"
xray_vless_reality_tcp_append_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/REALITY-TCP/append.json"

xray_vless_reality_grpc_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/REALITY-GRPC/config.json"
xray_vless_reality_grpc_append_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/REALITY-GRPC/append.json"

xray_vless_reality_h2_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/REALITY-H2/config.json"
vless_reality_h2_append_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/REALITY-H2/append.json"

xray_redirect_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Redirect/xray.json"
xray_redirect_append_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Redirect/xray_ap.json"

# SINGBOX URL START
singbox_install_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/install-singbox.sh"
singbox_cfg_path="/etc/sing-box"
singbox_cfg="${singbox_cfg_path}/config.json"

singbox_outbound=""

singbox_ss_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Shadowsocket/singbox.json"
singbox_ss_append_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Shadowsocket/singbox_ap.json"

singbox_hysteria2_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Hysteria2/singbox.json"
singbox_vless_reality_h2_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/REALITY-H2/singbox.json"
singbox_vless_reality_grpc_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/REALITY-GRPC/singbox.json"
singbox_vless_reality_tcp_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/REALITY-TCP/singbox.json"

singbox_redirect_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Redirect/singbox.json"
singbox_redirect_append_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Redirect/singbox_ap.json"

singbox_route_url="https://raw.githubusercontent.com/bakasine/rules/master/singbox/singbox.txt"
# SINGBOX URL END

# MIHOMO URL START
mihomo_cfg="/etc/mihomo"
mihomo_install_url="https://github.com/uerax/taffy-onekey/raw/master/install-mihomo.sh"

mihomo_ss_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Shadowsocket/mihomo.yaml"

mihomo_vless_reality_grpc_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/REALITY-GRPC/mihomo.yaml"

mihomo_redirect_config_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Redirect/mihomo.yaml"

mihomo_hysteria2_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/config/Hysteria2/mihomo.yaml"


# MIHOMO URL END

xray_cfg="/usr/local/etc/xray/config.json"
xray_path="/opt/xray/"
xray_log="${xray_path}xray_log"
protocol_type=""
ws_path="crayfish"
ss_method=""

xray_outbound=""

PKG_MANAGER="apt install -y"
password=""
domain=""
link=""
port="1991"

xray_onekey_install() {
    is_root
    get_system
    if ! command -v xray >/dev/null 2>&1; then
        env_install
        close_firewall
        xray_install
    fi
    if ! command -v xray >/dev/null 2>&1; then
        printf "${Red}Xray 安装失败!!!${Font}\n"
        exit 1
    fi
    xray_configure
    xray_select
}

is_root() {
    if [ "$(id -u)" -eq 0 ]; then
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
    . '/etc/os-release'
    case "${ID}" in
        "debian"|"ubuntu")
            info "检测系统为 ${ID}，已设置包管理器为 apt"
            ;;
            
        "alpine")
            PKG_MANAGER="apk add --no-cache"
            info "检测系统为 alpine，已设置包管理器为 apk"
            ;;
            
        "centos")
            # 满足你的特定需求
            error "centos fuck out!"
            exit 1
            ;;
            
        *)
            # 兜底逻辑，处理未知系统
            error "当前系统为 ${ID:-Unknown} ${VERSION_ID:-Unknown} 不在支持的系统列表内"
            exit 1
            ;;
    esac
}

_exec_service_action() {
    local action="$1"
    local name="$2"

    # 优先尝试 Systemd (现代主流系统)
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl "${action}" "${name}"
        return $?
    # 其次尝试 OpenRC (针对 Alpine)
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service "${name}" "${action}"
        return $?
    # 再次尝试通用 service 命令 (Debian/Ubuntu 回退方案)
    elif command -v service >/dev/null 2>&1; then
        service "${name}" "${action}"
        return $?
    # 最后尝试硬路径脚本 (SysVinit 兜底)
    elif [ -x "/etc/init.d/${name}" ]; then
        "/etc/init.d/${name}" "${action}"
        return $?
    else
        printf "${Red}错误: 无法找到适用的管理工具来执行 ${action} ${name}${Font}\n"
        return 1
    fi
}

start_service()   { _exec_service_action "start"   "$1"; }
stop_service()    { _exec_service_action "stop"    "$1"; }
restart_service() { _exec_service_action "restart" "$1"; }
service_status()  { _exec_service_action "status"  "$1"; }

enable_service() {
    local name="$1"
    
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl enable "${name}"
    elif command -v rc-update >/dev/null 2>&1; then
        # Alpine: 只有 add 后才能用 rc-service 管理
        rc-update add "${name}" default >/dev/null 2>&1 || true
    else
        # 传统 SysVinit 常用工具
        if command -v chkconfig >/dev/null 2>&1; then
            chkconfig "${name}" on >/dev/null 2>&1 || true
        elif command -v update-rc.d >/dev/null 2>&1; then
            update-rc.d "${name}" defaults >/dev/null 2>&1 || true
        fi
    fi
}

service_is_active() {
    local name="$1"

    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl is-active --quiet "${name}"
        return $?
    elif command -v rc-service >/dev/null 2>&1; then
        # OpenRC status 成功代表服务正在运行
        rc-service "${name}" status >/dev/null 2>&1
        return $?
    else
        # 通用 service status 或直接检测进程
        if service "${name}" status >/dev/null 2>&1; then
            return 0
        fi
        # 最后的暴力检测：通过进程名简单判断
        pgrep -x "${name}" >/dev/null 2>&1
        return $?
    fi
}

run_remote_script() {
    url="$1"
    shift || true
    if command -v curl >/dev/null 2>&1; then
        if command -v bash >/dev/null 2>&1; then
            curl -fsSL "${url}" | bash -s -- "$@"
        else
            curl -fsSL "${url}" | sh -s -- "$@"
        fi
    elif command -v wget >/dev/null 2>&1; then
        if command -v bash >/dev/null 2>&1; then
            wget -qO- "${url}" | bash -s -- "$@"
        else
            wget -qO- "${url}" | sh -s -- "$@"
        fi
    else
        error "缺少 curl/wget，无法获取远程脚本: ${url}"
        return 1
    fi
}

menu_item() {
    # $1 是编号, $2 是描述, $3 是颜色变量
    color="${3:-$Cyan}" # 默认青色
    printf "${color}%s) %s ${Font}\n" "$1" "$2"
} 

env_install() {
    ${PKG_MANAGER} wget lsof curl jq openssl
    judge "git wget lsof curl jq openssl 安装"
}

env_install_singbox() {
    ${PKG_MANAGER} wget lsof curl jq openssl
    judge "wget lsof curl jq openssl 安装"
}
env_install_mihomo() {
    ${PKG_MANAGER} wget lsof curl openssl
    judge "wget lsof curl openssl 安装"
}

yq_install() {
    # 检查 yq 是否已安装
    if command -v yq >/dev/null 2>&1; then
        info "yq 已存在，跳过安装"
        return 0
    fi

    if [ "$ID" = "alpine" ]; then
        info "正在通过 apk 安装 yq (Alpine 适配版)..."
        # Alpine 官方仓库有 yq，这样安装的版本能完美兼容 musl 环境
        $PKG_MANAGER yq
    else
        info "正在下载 yq 二进制文件 (Debian/Ubuntu)..."
        # 确保 wget 存在
        if ! command -v wget >/dev/null 2>&1; then
            $PKG_MANAGER wget
        fi
        
        # 下载二进制文件
        wget -q "https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64" -O /usr/local/bin/yq
        chmod +x /usr/local/bin/yq
    fi
}

port_check() {
    local port="$1"
    [ -z "${port}" ] && return 1

    # 1. 使用 netstat 检测端口（兼容性最高）
    # -a: 所有, -n: 数字格式, -l: 监听, -p: 显示进程(需要 root)
    # 查找是否有 ":端口号 " 且状态为 LISTEN 的行
    check_port=$(netstat -anl | grep "[:.]${port} " | grep "LISTEN")

    if [ -z "${check_port}" ]; then
        ok "${port} 端口未被占用"
        sleep 1
    else
        error "检测到 ${port} 端口被占用"
        
        # 2. 尝试获取占用该端口的 PID
        # netstat -anp 在某些系统下能看到 PID，如果没有就尝试使用 fuser 或 ss
        pid=$(netstat -anp 2>/dev/null | grep "[:.]${port} " | grep "LISTEN" | awk '{print $7}' | cut -d'/' -f1)
        
        # 3. 如果能拿到 PID 则尝试 kill
        if [ -n "${pid}" ] && [ "${pid}" != "-" ]; then
            warn "占用端口 ${port} 的进程 PID 为: ${pid}，准备清理..."
            sleep 2
            kill -9 "${pid}" 2>/dev/null || true
            ok "进程已清理"
        else
            # 如果拿不到具体 PID（比如无权限或工具限制），提醒用户手动检查
            warn "无法自动获取占用进程 PID，请手动检查或更换端口"
        fi
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

xray_install() {

    if ! command -v xray >/dev/null 2>&1; then
        if [ "${system}" = "alpine" ]; then
            install_url="https://github.com/XTLS/Xray-install/raw/main/alpinelinux/install-release.sh"
        else
            install_url="${xray_install_url}"
        fi

        if command -v curl >/dev/null 2>&1; then
            if command -v bash >/dev/null 2>&1; then
                bash -c "$(curl -fsSL \"${install_url}\")"
            else
                sh -c "$(curl -fsSL \"${install_url}\")"
            fi
        elif command -v wget >/dev/null 2>&1; then
            if command -v bash >/dev/null 2>&1; then
                wget -qO- "${install_url}" | bash
            else
                wget -qO- "${install_url}" | sh
            fi
        else
            error "缺少 curl 或 wget，无法下载 Xray 安装脚本"
            exit 1
        fi

        judge "Xray 安装"
    else
        ok "Xray 已安装"
    fi
    
}

xray_configure() {
    mkdir -p ${xray_log} && touch ${xray_log}/access.log && touch ${xray_log}/error.log && chmod a+w ${xray_log}/*.log
}

clash_config() {
    case $protocol_type in
    "hysteria2_nodomain")
    clash_cfg="  - name: $domain
    type: hysteria2
    server: '$domain'
    port: $port
    up: 50 Mbps
    down: 200 Mbps
    password: $password
    sni: https://www.python.org
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
    packet-encoding: xudp
    servername: www.python.org
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
    packet-encoding: xudp
    # skip-cert-verify: true
    servername: www.python.org
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
    packet-encoding: xudp
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
    packet-encoding: xudp
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
    packet-encoding: xudp
    flow: ''
    servername: www.python.org
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
    case $protocol_type in
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

xray_vless_reality_h2() {
    password=$(xray uuid)
    set_port
    port_check $port

    domain="www.python.org"
    protocol_type="reality_h2"
    keys=$(xray x25519)
    private_key=$(printf "%s" "$keys" | awk -F'PrivateKey: ' '{print $2}' | awk '{print $1}')
    public_key=$(printf "%s" "$keys" | awk -F'Password: ' '{print $2}' | awk '{print $1}')
    # short_id=$(openssl rand -hex 8)
    ip=$(curl -sS --connect-timeout 4 ipinfo.io/ip)
    ipv6=$(curl -sS6 --connect-timeout 4 ip.me)

    wget -N ${xray_vless_reality_h2_url} -O ${xray_cfg}
    judge "Xray Reality H2配置文件下载"

    sed -i "s~\${password}~$password~" ${xray_cfg}
    sed -i "s~\${privateKey}~$private_key~" ${xray_cfg}
    sed -i "s~\${pubicKey}~$public_key~" ${xray_cfg}
    sed -i "s~\${port}~$port~" ${xray_cfg}
    
    routing_set
    vless_reality_h2_outbound_config
    restart_service xray

    enable_service xray

    link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&fp=safari&pbk=$public_key&type=http#$ip"
    clash_config
}

xray_vless_reality_h2_append() {
    password=$(xray uuid)
    set_port
    port_check $port

    domain="www.python.org"
    protocol_type="reality_h2"
    keys=$(xray x25519)
    private_key=$(printf "%s" "$keys" | awk -F'PrivateKey: ' '{print $2}' | awk '{print $1}')
    public_key=$(printf "%s" "$keys" | awk -F'Password: ' '{print $2}' | awk '{print $1}')
    # short_id=$(openssl rand -hex 8)
    ip=$(curl -sS --connect-timeout 4 ipinfo.io/ip)

    cd /usr/local/etc/xray

    wget -Nq ${vless_reality_h2_append_url} -O append.json
    judge "Xray Reality H2配置文件下载"

    sed -i "s~\${password}~$password~" append.json
    sed -i "s~\${privateKey}~$private_key~" append.json
    sed -i "s~\${pubicKey}~$public_key~" append.json
    sed -i "s~\${port}~$port~" append.json

    xray run -confdir=./ -dump  > config.json
    rm append.json
    

    vless_reality_h2_outbound_config
    link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&fp=safari&pbk=$public_key&type=http#$ip"
    clash_config
    restart_service xray
}

xray_vless_reality_tcp() {
    password=$(xray uuid)
    set_port
    port_check $port

    domain="www.python.org"
    protocol_type="reality_tcp"
    keys=$(xray x25519)
    private_key=$(printf "%s" "$keys" | awk -F'PrivateKey: ' '{print $2}' | awk '{print $1}')
    public_key=$(printf "%s" "$keys" | awk -F'Password: ' '{print $2}' | awk '{print $1}')
    # short_id=$(openssl rand -hex 8)
    ip=$(curl -sS --connect-timeout 4 ipinfo.io/ip)
    ipv6=$(curl -sS6 --connect-timeout 4 ip.me)

    wget -N ${xray_vless_reality_tcp_url} -O ${xray_cfg}
    judge "Xray Reality 配置文件下载"

    sed -i "s~\${password}~$password~" ${xray_cfg}
    sed -i "s~\${privateKey}~$private_key~" ${xray_cfg}
    sed -i "s~\${pubicKey}~$public_key~" ${xray_cfg}
    sed -i "s~\${port}~$port~" ${xray_cfg}

    routing_set
    vless_reality_tcp_outbound_config

    restart_service xray 

    enable_service xray

    link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&fp=safari&pbk=$public_key&type=tcp&headerType=none#$ip"
    clash_config
}

xray_vless_reality_tcp_append() {
    password=$(xray uuid)
    set_port
    port_check $port

    domain="www.python.org"
    protocol_type="reality_tcp"
    keys=$(xray x25519)
    private_key=$(printf "%s" "$keys" | awk -F'PrivateKey: ' '{print $2}' | awk '{print $1}')
    public_key=$(printf "%s" "$keys" | awk -F'Password: ' '{print $2}' | awk '{print $1}')
    # short_id=$(openssl rand -hex 8)
    ip=$(curl -sS --connect-timeout 4 ipinfo.io/ip)

    cd /usr/local/etc/xray

    wget -Nq ${xray_vless_reality_tcp_append_url} -O append.json
    judge "Xray Reality 配置文件下载"

    sed -i "s~\${password}~$password~" append.json
    sed -i "s~\${privateKey}~$private_key~" append.json
    sed -i "s~\${pubicKey}~$public_key~" append.json
    sed -i "s~\${port}~$port~" append.json

    xray run -confdir=./ -dump  > config.json

    rm append.json

    vless_reality_tcp_outbound_config
    link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&fp=safari&pbk=$public_key&type=tcp&headerType=none#$ip"
    clash_config
    restart_service xray
}

xray_vless_reality_grpc() {
    password=$(xray uuid)
    set_port
    port_check $port

    protocol_type="reality_grpc"
    keys=$(xray x25519)
    private_key=$(printf "%s" "$keys" | awk -F'PrivateKey: ' '{print $2}' | awk '{print $1}')
    public_key=$(printf "%s" "$keys" | awk -F'Password: ' '{print $2}' | awk '{print $1}')
    # short_id=$(openssl rand -hex 8)
    ip=$(curl -sS --connect-timeout 4 ipinfo.io/ip)
    ipv6=$(curl -sS6 --connect-timeout 4 ip.me)

    wget -N ${xray_vless_reality_grpc_url} -O ${xray_cfg}
    judge "Xray Reality 配置文件下载"

    sed -i "s~\${password}~$password~" ${xray_cfg}
    sed -i "s~\${privateKey}~$private_key~" ${xray_cfg}
    sed -i "s~\${pubicKey}~$public_key~" ${xray_cfg}
    sed -i "s~\${ws_path}~$ws_path~" ${xray_cfg}
    sed -i "s~\${port}~$port~" ${xray_cfg}

    routing_set
    vless_reality_grpc_outbound_config

    restart_service xray

    enable_service xray

    clash_config
    link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&sid=8eb7bab5a41eb27d&fp=safari&peer=$domain&allowInsecure=1&pbk=$public_key&type=grpc&serviceName=$ws_path&mode=multi#$ip"
}

xray_vless_reality_grpc_append() {
    password=$(xray uuid)
    set_port
    port_check $port

    domain="www.python.org"
    protocol_type="reality_grpc"
    keys=$(xray x25519)
    private_key=$(printf "%s" "$keys" | awk -F'PrivateKey: ' '{print $2}' | awk '{print $1}')
    public_key=$(printf "%s" "$keys" | awk -F'Password: ' '{print $2}' | awk '{print $1}')
    # short_id=$(openssl rand -hex 8)
    ip=$(curl -sS ipinfo.io/ip)

    cd /usr/local/etc/xray

    wget -Nq ${xray_vless_reality_grpc_append_url} -O append.json
    judge "Xray Reality 配置文件下载"

    sed -i "s~\${password}~$password~" append.json
    sed -i "s~\${privateKey}~$private_key~" append.json
    sed -i "s~\${pubicKey}~$public_key~" append.json
    sed -i "s~\${ws_path}~$ws_path~" append.json
    sed -i "s~\${port}~$port~" append.json

    xray run -confdir=./ -dump  > config.json
    rm append.json

    vless_reality_grpc_outbound_config
    link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&sid=8eb7bab5a41eb27d&fp=safari&peer=$domain&allowInsecure=1&pbk=$public_key&type=grpc&serviceName=$ws_path&mode=multi#$ip"
    clash_config

    restart_service xray 
}

xray_shadowsocket() {
    
    if ! command -v openssl >/dev/null 2>&1; then
          ${PKG_MANAGER} openssl
          judge "openssl 安装"
    fi
    encrypt=1
    ss_method="2022-blake3-aes-128-gcm"
    set_port
    printf "选择加密方法\n"
    menu_item "1" "2022-blake3-aes-128-gcm" "$Green"
    menu_item "2" "2022-blake3-aes-256-gcm"
    menu_item "3" "2022-blake3-chacha20-poly1305"
    menu_item "4" "aes-128-gcm"
    menu_item "5" "chacha20-ietf-poly1305"
    menu_item "6" "xchacha20-ietf-poly1305"
    printf "\n"
    printf "选择加密方法(默认为1)："
    read -r encrypt
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
    restart_service xray
    enable_service xray

    tmp="${ss_method}:${password}"
    tmp=$(printf "%s" "$tmp" | openssl base64)
    domain=`curl -sS ipinfo.io/ip`
    ipv6=`curl -sS6 --connect-timeout 4 ip.me`
    link="ss://$tmp@${domain}:${port}"

    protocol_type="shadowsocket"
    shadowsocket_outbound_config
    clash_config
    qx_config

}

shadowsocket_config() {
    wget -N ${xray_ss_config_url} -O config.json
    judge "配置文件下载"
    sed -i "s~\${method}~$ss_method~" config.json
    sed -i "s~\${password}~$password~" config.json
    sed -i "s~\${port}~$port~" config.json
    mv config.json ${xray_cfg}
}

xray_redirect() {
    protocol_type="redirect"
    ip=`curl -sS ipinfo.io/ip`
    set_port
    printf "输入转发的目标地址: "
    read -r re_ip

    printf "输入转发的目标端口: "
    read -r re_port

    wget -N ${xray_redirect_config_url} -O config.json
    judge "配置文件下载"
    sed -i "s~114514~$port~" config.json
    sed -i "s~1919810~$re_port~" config.json
    sed -i "s~\${ip}~$re_ip~" config.json
    
    mv config.json ${xray_cfg}

    restart_service xray
    enable_service xray

    printf "${Green}IP为:${Font} ${ip}\n"
    printf "${Green}端口为:${Font} ${port}\n"
}

xray_shadowsocket_append() {
    if ! command -v openssl >/dev/null 2>&1; then
          ${PKG_MANAGER} openssl
          judge "openssl 安装"
    fi
    encrypt=1
    protocol_type="shadowsocket"
    ss_method="aes-128-gcm"
    set_port
    printf "选择加密方法\n"
    menu_item "1" "2022-blake3-aes-128-gcm" "$Green"
    menu_item "2" "2022-blake3-aes-256-gcm"
    menu_item "3" "2022-blake3-chacha20-poly1305"
    menu_item "4" "aes-128-gcm"
    menu_item "5" "chacha20-ietf-poly1305"
    menu_item "6" "xchacha20-ietf-poly1305"
    printf "\n"

    # 3. 读取输入 (兼容 Alpine, 拆分提示语以替代 read -p)
    printf "选择加密方法(默认为4)："
    read -r encrypt
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

    cd /usr/local/etc/xray

    wget -Nq ${xray_ss_append_config_url} -O append.json
    judge "配置文件下载"

    sed -i "s~\${password}~$password~" append.json
    sed -i "s~\${method}~$ss_method~" append.json
    sed -i "s~\${port}~$port~" append.json

    xray run -confdir=./ -dump  > config.json
    rm append.json

    tmp="${ss_method}:${password}"
    tmp=$(printf "%s" "$tmp" | openssl base64)
    domain=`curl -sS ipinfo.io/ip`
    ipv6=`curl -sS6 --connect-timeout 4 ip.me`
    link="ss://$tmp@${domain}:${port}"

    shadowsocket_outbound_config
    clash_config
    qx_config

    restart_service xray
}

xray_redirect_append() {
    ip=`curl -sS ipinfo.io/ip`
    set_port
    printf "输入转发的目标地址: "
    read -r re_ip

    printf "输入转发的目标端口: "
    read -r re_port

    cd /usr/local/etc/xray

    wget -Nq ${xray_redirect_append_config_url} -O append.json
    judge "配置文件下载"

    sed -i "s~114514~$port~" append.json
    sed -i "s~1919810~$re_port~" append.json
    sed -i "s~\${ip}~$re_ip~" append.json

    jq '.inbounds += [input]' config.json append.json > tmp.json
    judge 插入配置文件
    mv tmp.json config.json
    rm append.json

    systemctl restart xray

    printf "${Green}IP为:${Font} ${ip}\n"
    printf "${Green}端口为:${Font} ${port}\n"
}

# outbound start
singbox_hy2_outbound_config() {
    singbox_outbound="{
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
    \"password\": \"${password}\"\n}"   
}

vless_reality_grpc_outbound_config() {
    xray_outbound="{
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
    xray_outbound="{
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
            \"publicKey\": \"${public_key}\",
            \"shortId\": \"8eb7bab5a41eb27d\",
            \"spiderX\": \"/\"
        }
    }\n}"
}

vless_reality_h2_outbound_config() {
    xray_outbound="{
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
            \"publicKey\": \"${public_key}\",
            \"shortId\": \"8eb7bab5a41eb27d\",
            \"spiderX\": \"/\"
        }
    }\n}"
}

shadowsocket_outbound_config() {
    xray_outbound="{
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
    protocol_type="socks5"
    ip=`curl -sS ipinfo.io/ip`
    if ! command -v openssl >/dev/null 2>&1; then
          ${PKG_MANAGER} openssl
          judge "openssl 安装"
    fi
    set_port

    printf "%s\n" "------------------------------------------"
    # 拆分 read -rp：先用 printf 打印提示，再用 read 读取
    printf "设置你的用户名: "
    read -r user
    printf "%s\n" "------------------------------------------"
    printf "设置你的密码: "
    read -r password

    cd /usr/local/etc/xray

    wget -Nq ${xray_socks5_append_config_url} -O append.json
    judge "配置文件下载"

    sed -i "s~\${password}~$password~" append.json
    sed -i "s~\${user}~$user~" append.json
    sed -i "s~\${port}~$port~" append.json

    xray run -confdir ./ -dump > config.json
    rm append.json

    restart_service xray

    #link="trojan://${password}@${ip}:${port}#${domain}"

    #clash_config
    #qx_config
}

# outbound end

routing_set() {
    printf "是否配置Routing路由\n"
    printf "请输入(y/n): "
    read -r set_routing
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
    printf "%s\n" "------------------------------------------"
    printf "%s" "设置你的端口(默认443): "
    read -r input
    case "$input" in
        ''|*[!0-9]*)
            port="443"
            ;;
        *)
            if [ "$input" -ge 0 ] 2>/dev/null && [ "$input" -le 65535 ] 2>/dev/null; then
                port="$input"
            else
                port="443"
            fi
            ;;
    esac
} 

# XRAY END

# SINGBOX START
singbox_onekey_install() {
    is_root
    get_system
    if ! command -v sing-box >/dev/null 2>&1; then
        env_install_singbox
        close_firewall
        singbox_install
    fi
    if ! command -v sing-box >/dev/null 2>&1; then
        printf "${Red}sing-box 安装失败!!!${Font}\n"
        exit 1
    fi
    singbox_select
}

singbox_install() { 
    curl -fsSL "$singbox_install_url" | bash 
}

uninstall_singbox() {
    stop_service sing-box
    apt remove sing-box -y
}

singbox_routing_set() {
    printf "是否配置sing-box Route路由\n"
    printf "请输入(y/n，默认为 n): "
    read -r set_routing
    case "$set_routing" in
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
    ${PKG_MANAGER} openssl
    openssl ecparam -name prime256v1 -genkey -noout -out "${singbox_cfg_path}/server.key"

    openssl req -x509 -nodes -key "${singbox_cfg_path}/server.key" -out "${singbox_cfg_path}/server.crt" -subj "/CN=www.python.org" -days 36500
    
    chmod +775 ${singbox_cfg_path}/server*

    password=`tr -cd '0-9A-Za-z' < /dev/urandom | fold -w50 | head -n1`
    domain=$(curl -s https://ip.me)
    ipv6=$(curl -sS6 --connect-timeout 4 ip.me)

    wget -N ${singbox_hysteria2_url} -O config.yaml
    judge "配置文件下载"

    sed -i "s/\${password}/$password/" config.yaml
    sed -i "s/\${domain}/$domain/" config.yaml
    sed -i "s~114514~$port~" config.yaml

    mv config.yaml ${singbox_cfg}

    singbox_routing_set

    restart_service sing-box
    
    protocol_type="hysteria2_nodomain"
    link="hysteria2://${password}@${domain}:${port}?peer=https://www.python.org&insecure=1&obfs=none#${domain}"

    singbox_hy2_outbound_config
    clash_config
}

singbox_vless_reality_h2() {
    password=$(sing-box generate uuid)
    set_port
    port_check $port

    domain="www.python.org"
    protocol_type="reality_h2"
    keys=$(sing-box generate reality-keypair)
    private_key=$(printf "%s" "$keys" | awk '{print $2}')
    public_key=$(printf "%s" "$keys" | awk '{print $4}')
    # short_id=$(openssl rand -hex 8)
    ip=$(curl -sS ipinfo.io/ip)
    ipv6=$(curl -sS6 --connect-timeout 4 ip.me)

    wget -N ${singbox_vless_reality_h2_url} -O ${singbox_cfg}
    judge "配置文件下载"

    sed -i "s~\${password}~$password~" ${singbox_cfg}
    sed -i "s~\${privateKey}~$private_key~" ${singbox_cfg}
    sed -i "s~\${pubicKey}~$public_key~" ${singbox_cfg}
    sed -i "s~114514~$port~" ${singbox_cfg}

    restart_service sing-box

    enable_service sing-box

    link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&fp=safari&pbk=$public_key&type=http#$ip"

    clash_config
}

singbox_vless_reality_grpc() {
    password=$(sing-box generate uuid)
    set_port
    port_check $port

    protocol_type="reality_grpc"
    domain="www.python.org"
    keys=$(sing-box generate reality-keypair)
    private_key=$(printf "%s" "$keys" | awk '{print $2}')
    public_key=$(printf "%s" "$keys" | awk '{print $4}')
    # short_id=$(openssl rand -hex 8)
    ip=$(curl -sS ipinfo.io/ip)
    ipv6=$(curl -sS6 --connect-timeout 4 ip.me)

    wget -N ${singbox_vless_reality_grpc_url} -O ${singbox_cfg}
    judge "配置文件下载"

    sed -i "s~\${password}~$password~" ${singbox_cfg}
    sed -i "s~\${privateKey}~$private_key~" ${singbox_cfg}
    sed -i "s~\${pubicKey}~$public_key~" ${singbox_cfg}
    sed -i "s~\${ws_path}~$ws_path~" ${singbox_cfg}
    sed -i "s~114514~$port~" ${singbox_cfg}

    restart_service sing-box

    enable_service sing-box

    link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&sid=8eb7bab5a41eb27d&fp=safari&pbk=$public_key&type=grpc&peer=$domain&allowInsecure=1&serviceName=$ws_path&mode=multi#$ip"

    clash_config
}

singbox_vless_reality_tcp() {
    password=$(sing-box generate uuid)
    set_port
    port_check $port

    domain="www.python.org"
    protocol_type="reality_tcp"
    keys=$(sing-box generate reality-keypair)
    private_key=$(printf "%s" "$keys" | awk '{print $2}')
    public_key=$(printf "%s" "$keys" | awk '{print $4}')
    # short_id=$(openssl rand -hex 8)
    ip=$(curl -sS ipinfo.io/ip)
    ipv6=$(curl -sS6 --connect-timeout 4 ip.me)

    wget -N ${singbox_vless_reality_tcp_url} -O ${singbox_cfg}
    judge "配置文件下载"

    sed -i "s~\${password}~$password~" ${singbox_cfg}
    sed -i "s~\${privateKey}~$private_key~" ${singbox_cfg}
    sed -i "s~\${pubicKey}~$public_key~" ${singbox_cfg}
    sed -i "s~114514~$port~" ${singbox_cfg}

    restart_service sing-box 

    enable_service sing-box

    link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&fp=safari&pbk=$public_key&type=tcp&headerType=none#$ip"

    clash_config

}

singbox_shadowsocket() {
    
    encrypt="4"
    ss_method="aes-128-gcm"
    
    # 2. 调用设置端口函数
    set_port

    # 3. 打印菜单 (使用自定义的 menu_item 函数)
    printf "选择加密方法\n"
    menu_item "1" "2022-blake3-aes-128-gcm" "$Green"
    menu_item "2" "2022-blake3-aes-256-gcm"
    menu_item "3" "2022-blake3-chacha20-poly1305"
    menu_item "4" "aes-128-gcm"
    menu_item "5" "chacha20-ietf-poly1305"
    menu_item "6" "xchacha20-ietf-poly1305"
    printf "\n"

    # 4. 读取输入 (兼容 Alpine：拆分提示语，替代 read -p)
    printf "选择加密方法(默认为4)："
    read -r encrypt
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
    judge "配置文件下载"
    sed -i "s~\${method}~$ss_method~" config.json
    sed -i "s~\${password}~$password~" config.json
    sed -i "s~114514~$port~" config.json
    mv config.json ${singbox_cfg}
    restart_service sing-box && enable_service sing-box

    tmp="${ss_method}:${password}"
    tmp=$(printf "%s" "$tmp" | openssl base64)
    domain=`curl -sS ipinfo.io/ip`
    ipv6=$(curl -sS6 --connect-timeout 4 ip.me)
    link="ss://$tmp@${domain}:${port}"

    protocol_type="shadowsocket"
    shadowsocket_outbound_config
    clash_config
    qx_config
}

singbox_redirect() {
    ip=`curl -sS ipinfo.io/ip`
    set_port
    # 1. 获取转发目标地址
    printf "输入转发的目标地址: "
    read -r re_ip

    # 2. 获取转发目标端口
    printf "输入转发的目标端口: "
    read -r re_port

    wget -N ${singbox_redirect_config_url} -O config.json
    judge "配置文件下载"

    sed -i "s~\${ip}~$re_ip~" config.json
    sed -i "s~114514~$port~" config.json
    sed -i "s~1919810~$re_port~" config.json

    mv config.json ${singbox_cfg}
    restart_service sing-box
    
    printf "${Green}IP为:${Font} ${ip}\n"
    printf "${Green}端口为:${Font} ${port}"
}

singbox_hy2_append() {
    set_port
    ${PKG_MANAGER} openssl

    openssl ecparam -name prime256v1 -genkey -noout -out "${singbox_cfg_path}/server.key"

    openssl req -x509 -nodes -key "${singbox_cfg_path}/server.key" -out "${singbox_cfg_path}/server.crt" -subj "/CN=www.python.org" -days 36500
    
    chmod +775 ${singbox_cfg_path}/server*

    password=`tr -cd '0-9A-Za-z' < /dev/urandom | fold -w50 | head -n1`
    domain=$(curl -s https://ip.me)

    wget -N ${singbox_hysteria2_url} -O append.json
    judge "配置文件下载"

    sed -i "s/\${password}/$password/" append.json
    sed -i "s/\${domain}/$domain/" append.json
    sed -i "s~114514~$port~" append.json

    stop_service sing-box

    sing-box merge ${singbox_cfg_path}/tmp.json -c ${singbox_cfg_path}/config.json -c  append.json

    rm append.json

    mv ${singbox_cfg_path}/config.json ${singbox_cfg_path}/config.json.bak

    mv ${singbox_cfg_path}/tmp.json ${singbox_cfg_path}/config.json

    restart_service sing-box
    
    protocol_type="hysteria2_nodomain"

    link="hysteria2://${password}@${domain}:${port}?peer=https://www.python.org&insecure=1&obfs=none#${domain}"

    singbox_hy2_outbound_config

    clash_config
}

singbox_reality_grpc_append() {
    password=$(sing-box generate uuid)
    set_port
    port_check $port

    protocol_type="reality_grpc"
    domain="www.python.org"
    keys=$(sing-box generate reality-keypair)
    private_key=$(printf "%s" "$keys" | awk '{print $2}')
    public_key=$(printf "%s" "$keys" | awk '{print $4}')
    # short_id=$(openssl rand -hex 8)
    ip=$(curl -sS ipinfo.io/ip)

    wget -N ${singbox_vless_reality_grpc_url} -O append.json
    judge "配置文件下载"

    sed -i "s~\${password}~$password~" append.json
    sed -i "s~\${privateKey}~$private_key~" append.json
    sed -i "s~\${pubicKey}~$public_key~" append.json
    sed -i "s~\${ws_path}~$ws_path~" append.json
    sed -i "s~114514~$port~" append.json

    stop_service sing-box

    sing-box merge ${singbox_cfg_path}/tmp.json -c ${singbox_cfg_path}/config.json -c  append.json

    rm append.json

    mv ${singbox_cfg_path}/config.json ${singbox_cfg_path}/config.json.bak

    mv ${singbox_cfg_path}/tmp.json ${singbox_cfg_path}/config.json

    restart_service sing-box

    vless_reality_grpc_outbound_config
    clash_config
    qx_config
}

singbox_reality_tcp_append() {
    password=$(sing-box generate uuid)
    set_port
    port_check $port

    domain="www.python.org"
    protocol_type="reality_tcp"
    keys=$(sing-box generate reality-keypair)
    private_key=$(printf "%s" "$keys" | awk '{print $2}')
    public_key=$(printf "%s" "$keys" | awk '{print $4}')
    # short_id=$(openssl rand -hex 8)
    ip=$(curl -sS ipinfo.io/ip)

    wget -N ${singbox_vless_reality_tcp_url} -O append.json
    judge "配置文件下载"

    sed -i "s~\${password}~$password~" append.json
    sed -i "s~\${privateKey}~$private_key~" append.json
    sed -i "s~\${pubicKey}~$public_key~" append.json
    sed -i "s~114514~$port~" append.json

    stop_service sing-box

    sing-box merge ${singbox_cfg_path}/tmp.json -c ${singbox_cfg_path}/config.json -c  append.json

    rm append.json

    mv ${singbox_cfg_path}/config.json ${singbox_cfg_path}/config.json.bak

    mv ${singbox_cfg_path}/tmp.json ${singbox_cfg_path}/config.json

    restart_service sing-box 

    link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&fp=safari&pbk=$public_key&type=tcp&headerType=none#$ip"

    vless_reality_tcp_outbound_config
    clash_config
    qx_config
}

singbox_shadowsocket_append() {
    encrypt="4"
    ss_method="aes-128-gcm"
    
    # 2. 调用设置端口函数
    set_port

    # 3. 打印菜单 (使用自定义的 menu_item 函数，更整洁)
    printf "选择加密方法\n"
    menu_item "1" "2022-blake3-aes-128-gcm" "$Green"
    menu_item "2" "2022-blake3-aes-256-gcm"
    menu_item "3" "2022-blake3-chacha20-poly1305"
    menu_item "4" "aes-128-gcm"
    menu_item "5" "chacha20-ietf-poly1305"
    menu_item "6" "xchacha20-ietf-poly1305"
    printf "\n"

    # 4. 获取用户输入 (兼容 Alpine：拆分提示语，替代 read -p)
    printf "选择加密方法(默认为4)："
    read -r encrypt
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
    judge "配置文件下载"

    sed -i "s~\${password}~$password~" append.json
    sed -i "s~\${method}~$ss_method~" append.json
    sed -i "s~114514~$port~" append.json
    
    stop_service sing-box

    sing-box merge ${singbox_cfg_path}/tmp.json -c ${singbox_cfg_path}/config.json -c  append.json

    rm append.json

    mv ${singbox_cfg_path}/config.json ${singbox_cfg_path}/config.json.bak

    mv ${singbox_cfg_path}/tmp.json ${singbox_cfg_path}/config.json

    restart_service sing-box

    tmp="${ss_method}:${password}"
    tmp=$(printf "%s" "$tmp" | openssl base64)
    domain=`curl -sS ipinfo.io/ip`
    link="ss://$tmp@${domain}:${port}"

    protocol_type="shadowsocket"
    shadowsocket_outbound_config
    clash_config
    qx_config
}

singbox_redirect_append() {
    ip=`curl -sS ipinfo.io/ip`
    set_port
    # 1. 获取转发目标地址
    printf "输入转发的目标地址: "
    read -r re_ip

    # 2. 获取转发目标端口
    printf "输入转发的目标端口: "
    read -r re_port

    wget -Nq ${singbox_redirect_append_config_url} -O append.json
    judge "配置文件下载"

    sed -i "s~\${ip}~$re_ip~" append.json
    sed -i "s~114514~$port~" append.json
    sed -i "s~1919810~$re_port~" append.json
    
    restart_service sing-box

    sing-box merge ${singbox_cfg_path}/tmp.json -c ${singbox_cfg_path}/config.json -c append.json

    rm append.json

    mv ${singbox_cfg_path}/config.json ${singbox_cfg_path}/config.json.bak

    mv ${singbox_cfg_path}/tmp.json ${singbox_cfg_path}/config.json

    restart_service sing-box

    printf "${Green}IP为:${Font} ${ip}\n"
    printf "${Green}端口为:${Font} ${port}\n"
}
# SINGBOX END

# MIHOMO START
mihomo_install() {
    if ! command -v mihomo >/dev/null 2>&1; then
        curl -fsSL "$mihomo_install_url" | bash -s -- install
        judge "Mihomo 安装"
    else
        ok "Mihomo 已安装"
    fi
}

mihomo_update() {
    if ! command -v mihomo >/dev/null 2>&1; then
        curl -fsSL "$mihomo_install_url" | bash -s -- update
        judge "Mihomo 已更新"
    else
        ok "Mihomo 已更新"
    fi
}

mihomo_remove() {
     if ! command -v mihomo >/dev/null 2>&1; then
        curl -fsSL "$mihomo_install_url" | bash -s -- remove
        judge "Mihomo 已卸载"
    else
        ok "Mihomo 已卸载"
    fi   
}

mihomo_onekey_install() {
    is_root
    get_system
    if ! command -v mihomo >/dev/null 2>&1; then
        env_install_mihomo
        close_firewall
        mihomo_install
    fi
    if ! command -v mihomo >/dev/null 2>&1; then
        printf "${Red}mihomo 安装失败!!!${Font}\n"
        exit 1
    fi
    mihomo_select
}

mihomo_shadowsocket() {
    
    if ! command -v openssl >/dev/null 2>&1; then
          ${PKG_MANAGER} openssl
          judge "openssl 安装"
    fi
    encrypt=4
    ss_method="aes-128-gcm"
    set_port

    # 2. 打印菜单（使用之前定义的 menu_item）
    printf "选择加密方法\n"
    menu_item "1" "2022-blake3-aes-128-gcm" "$Green"
    menu_item "2" "2022-blake3-aes-256-gcm"
    menu_item "3" "2022-blake3-chacha20-poly1305"
    menu_item "4" "aes-128-gcm"
    menu_item "5" "chacha20-ietf-poly1305"
    menu_item "6" "xchacha20-ietf-poly1305"
    printf "\n"

    # 3. 读取输入（兼容 Alpine 的 printf + read）
    printf "选择加密方法(默认为4)："
    read -r encrypt
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

    domain=`curl -sS ipinfo.io/ip`
    ipv6=`curl -sS6 --connect-timeout 4 ip.me`

    mihomo_shadowsocket_config
    restart_service mihomo

    tmp="${ss_method}:${password}"
    tmp=$(printf "%s" "$tmp" | openssl base64)

    link="ss://$tmp@${domain}:${port}"

    protocol_type="shadowsocket"
    shadowsocket_outbound_config
    clash_config
    qx_config
}

mihomo_shadowsocket_config() {
    wget -N ${mihomo_ss_config_url} -O tmp.yaml
    judge "配置文件下载"
    sed -i "s~\${method}~$ss_method~" tmp.yaml
    sed -i "s~\${password}~$password~" tmp.yaml
    sed -i "s~\${port}~$port~" tmp.yaml
    sed -i "s~\${name}~$domain~" tmp.yaml
    cp ${mihomo_cfg}/config.yaml ${mihomo_cfg}/bak.yaml
    cat tmp.yaml >> ${mihomo_cfg}/config.yaml 
    rm tmp.yaml
}

mihomo_shadowsocket_append() {
    mihomo_shadowsocket
}

mihomo_vless_reality_grpc() {
    password=$(mihomo generate uuid)
    set_port
    port_check $port

    protocol_type="reality_grpc"
    keys=$(mihomo generate reality-keypair)
    private_key=$(printf "%s" "$keys" | awk '/PrivateKey:/ {print $2}')
    public_key=$(printf "%s" "$keys" | awk '/PrivateKey:/ {print $4}')
    ip=$(curl -sS --connect-timeout 4 ipinfo.io/ip)
    ipv6=$(curl -sS6 --connect-timeout 4 ip.me)

    wget -N ${mihomo_vless_reality_grpc_url} -O tmp.yaml
    judge "Mihomo Reality 配置文件下载"

    sed -i "s~\${password}~$password~" tmp.yaml
    sed -i "s~\${name}~$ip~" tmp.yaml
    sed -i "s~\${privateKey}~$private_key~" tmp.yaml
    sed -i "s~\${publicKey}~$public_key~" tmp.yaml
    sed -i "s~\${ws_path}~$ws_path~" tmp.yaml
    sed -i "s~\${port}~$port~" tmp.yaml

    cp ${mihomo_cfg}/config.yaml ${mihomo_cfg}/bak.yaml
    cat tmp.yaml >> ${mihomo_cfg}/config.yaml 
    rm tmp.yaml

    vless_reality_grpc_outbound_config

    restart_service mihomo 

    clash_config
    link="vless://$password@$ip:$port?encryption=none&security=reality&sni=$domain&sid=8eb7bab5a41eb27d&fp=safari&peer=$domain&allowInsecure=1&pbk=$public_key&type=grpc&serviceName=$ws_path&mode=multi#$ip"

}

mihomo_hysteria2() {
    set_port
    ${PKG_MANAGER} openssl

    protocol_type="hysteria2_nodomain"

    openssl ecparam -name prime256v1 -genkey -noout -out "${mihomo_cfg}/server.key"

    openssl req -x509 -nodes -key "${mihomo_cfg}/server.key" -out "${mihomo_cfg}/server.crt" -subj "/CN=www.python.org" -days 36500
    
    chmod +775 ${mihomo_cfg}/server*

    password=`tr -cd '0-9A-Za-z' < /dev/urandom | fold -w50 | head -n1`
    ip=$(curl -s https://ip.me)
    domain=$ip

    wget -N ${mihomo_hysteria2_url} -O tmp.yaml
    judge "Mihomo Reality 配置文件下载"

    sed -i "s/\${password}/$password/" tmp.yaml
    sed -i "s/\${ip}/$ip/" tmp.yaml
    sed -i "s/\${port}/$port/" tmp.yaml

    cp ${mihomo_cfg}/config.yaml ${mihomo_cfg}/bak.yaml
    cat tmp.yaml >> ${mihomo_cfg}/config.yaml 
    rm tmp.yaml

    restart_service mihomo 

    singbox_hy2_outbound_config
    clash_config
    
}

mihomo_redirect() {
    ip=`curl -sS ipinfo.io/ip`
    set_port
    # 1. 获取转发目标地址
    printf "输入转发的目标地址: "
    read -r re_ip

    # 2. 获取转发目标端口
    printf "输入转发的目标端口: "
    read -r re_port

    wget -N ${mihomo_redirect_config_url} -O tmp.yaml
    judge "配置文件下载"

    sed -i "s~\${ip}~$re_ip~" tmp.yaml
    sed -i "s~\${name}~$re_ip~" tmp.yaml
    sed -i "s~114514~$port~" tmp.yaml
    sed -i "s~1919810~$re_port~" tmp.yaml

    cp ${mihomo_cfg}/config.yaml ${mihomo_cfg}/bak.yaml
    cat tmp.yaml >> ${mihomo_cfg}/config.yaml 
    rm tmp.yaml
    restart_service mihomo
    
    printf "${Green}IP为:${Font} ${ip}\n"
    printf "${Green}端口为:${Font} ${port}\n"
}

mihomo_clear_listeners() {
    sed -i '/listeners:/q' ${mihomo_cfg}/config.yaml
}


# MIHOMO END

info() {
    printf "${Info} ${Green}%s${Font}\n" "$1"
}

ok() {
    printf "${OK} ${Green}%s${Font}\n" "$1"
}

error() {
    printf "${Error} ${RedBG}%s${Font}\n" "$1"
}

warn() {
    printf "${Warn} ${Yellow}%s${Font}\n" "$1"
}

judge() {
    # $? 上一次命令成功为0 失败为非0
    if [ "$?" -eq 0 ]; then
        ok "$1 完成"
    else
        error "$1 失败"
        exit 1
    fi
} 

open_bbr() {
    is_root
    . '/etc/os-release'
    info "过于老的系统版本会导致开启失败"
    if [ "${ID}" = "debian" ] && [ "${VERSION_ID}" -ge 9 ]; then
        info "检测系统为 debian"
        #echo 'deb http://deb.debian.org/debian buster-backports main' >> /etc/apt/sources.list
        #apt update && apt -t buster-backports install linux-image-amd64
        wget -N ${bbr_config_url} -O /etc/sysctl.conf
        judge "配置文件下载"
        sysctl -p
        info "输入一下命令检测是否成功安装"
        info "lsmod | grep bbr"
    elif [ "${ID}" = "ubuntu" ] && [ "$(printf "%s" "${VERSION_ID}" | cut -d '.' -f1)" -ge 18 ]; then
        info "检测系统为 ubuntu"
        wget -N ${bbr_config_url} -O /etc/sysctl.conf
        judge "配置文件下载"
        sysctl -p
        info "输入一下命令检测是否成功安装"
        info "lsmod | grep bbr"
    elif [ "${ID}" = "centos" ]; then
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
    # 统一使用 printf 格式化输出，保证跨系统兼容性
    printf "%s\n" "------------------------------------------------"
    printf "${Green}安装成功!!!!!!!!${Font}\n"
    printf "%s\n" "------------------------------------------------"
    printf "${Green}密码为:${Font} %s\n" "${password}"
    printf "${Green}端口为:${Font} %s\n" "${port}"
    printf "${Green}链接:${Font} %s\n" "${link}"

    # 使用 [ -n "$var" ] 判断变量是否非空
    if [ -n "$qx_cfg" ]; then
        printf "%s\n" "------------------------------------------------"
        printf "${Green}QuantumultX配置: ${Font}\n"
        printf "%b\n" "${qx_cfg}"
    fi

    if [ -n "$xray_outbound" ]; then
        printf "%s\n" "------------------------------------------------"
        printf "${Green}Outbounds配置:${Font}\n"
        printf "%b\n" "${xray_outbound}"
    fi

    if [ -n "$singbox_outbound" ]; then
        printf "%s\n" "------------------------------------------------"
        printf "${Green}Singbox Outbounds配置:${Font}\n"
        printf "%b\n" "${singbox_outbound}"
    fi

    if [ -n "$clash_cfg" ]; then
        printf "%s\n" "------------------------------------------------"
        printf "${Green}Clash配置: ${Font}\n"
        printf "%b\n" "${clash_cfg}"
    fi

    printf "%s\n" "------------------------------------------------"

    # 条件判断语句在 POSIX 中建议变量加双引号
    if [ "$protocol_type" = "vmess_ws" ]; then
        printf "${Yellow}注: 如果套CF需要在SSL/TLS encryption mode 改为 Full ${Font}\n"
    fi
}

show_xray_info() {
    run_remote_script "https://raw.githubusercontent.com/uerax/taffy-onekey/master/configuration.sh" xray
}

show_singbox_info() {
    run_remote_script "https://raw.githubusercontent.com/uerax/taffy-onekey/master/configuration.sh" singbox
}

show_mihomo_info() {
    run_remote_script "https://raw.githubusercontent.com/uerax/taffy-onekey/master/configuration.sh" mihomo
}

update_script() {
    # 1. 获取当前脚本的绝对路径
    # 使用 POSIX 兼容的方式获取路径，避免 readlink 缺失问题
    case "$0" in
        /*) script_abs_path="$0" ;;
        *)  script_abs_path="$(pwd)/${0#./}" ;;
    esac

    info "正在从 GitHub 获取最新版本..."
    
    # 2. 下载到临时文件，防止直接覆盖导致脚本损坏
    update_url="https://raw.githubusercontent.com/uerax/taffy-onekey/master/taffy.sh"
    temp_file="taffy.sh.tmp"
    
    if wget --no-check-certificate -q -O "$temp_file" "$update_url"; then
        # 3. 检查下载的文件是否有效（是否包含基本的 shell 声明）
        if grep -q "#!/bin/" "$temp_file"; then
            mv "$temp_file" "$script_abs_path"
            chmod +x "$script_abs_path"
            ok "更新成功！正在重新启动脚本..."
            exec "$script_abs_path" "$@"
        else
            rm -f "$temp_file"
            error "更新失败：下载的文件无效（可能是网络拦截）。"
            exit 1
        fi
    else
        rm -f "$temp_file"
        error "更新失败：无法连接到 GitHub。"
        exit 1
    fi
}

xray_upgrade() {
    printf "%s\n" "------------------------------------------"
    printf "是否安装指定版本(Y/N): "
    read -r input
    case $input in
    [yY])
      printf "%s" "输入指定版本(eq: 1.7.5): "
      read -r version
      run_remote_script "${xray_install_url}" install --version "${version}"
      judge "Xray 更新"
      ;;
    [nN])
      run_remote_script "${xray_install_url}" install
      judge "Xray 更新"
      ;;
    *)
      run_remote_script "${xray_install_url}" install
      judge "Xray 更新"
      ;;
    esac
    
}

manage_service() {
    action="$1" # start, stop, restart, enable
    service_name="$2"

    case "$action" in
        start)
            start_service "$service_name"
            ;;
        stop)
            stop_service "$service_name"
            ;;
        restart)
            restart_service "$service_name"
            ;;
        enable)
            enable_service "$service_name"
            ;;
        status)
            service_status "$service_name"
            ;;
        *)
            error "Unknown action: $action"
            ;;
    esac
}

uninstall_xray() {
    info "Xray 卸载"
    run_remote_script "${xray_install_url}" remove --purge
    # rm -rf /home/xray
    rm -rf ${xray_path}
}

uninstall() {
    printf "%s\n" "------------------------------------------"

    # 2. 拆分 read -rp：先提示，后读取
    printf "是否确定要完全卸载(Y/N): "
    read -r input
    case $input in
    [yY])
      uninstall_xray
      uninstall_singbox
      printf "全部卸载已完成\n"
    ;;
    *)
    ;;
    esac
}

question_answer() {
    # 统一使用 printf \n 换行，防止在 Debian 下打印出 "-e" 字符
    printf "${Red}1.我啥都不懂${Font}\n"
    printf "${Green}https://github.com/uerax/taffy-onekey/issues 去 New Issue 问${Font}\n"
    printf "${Yellow} ------------------------------------------------ ${Font}\n"

    printf "${Red}2.Nginx 启动失败${Font}\n"
    printf "${Green}执行\"service nginx status\"查看日志${Font}\n"
    printf "${Yellow} ------------------------------------------------ ${Font}\n"

    printf "${Red}3.Xray 启动失败${Font}\n"
    # %b 会处理字符串中的转义字符，是最稳妥的写法
    printf "%b\n" "${Green}执行\"service status xray\" 或者 \"service_status xray\" 查看日志${Font}"
    printf "${Yellow} ------------------------------------------------ ${Font}\n"

    printf "${Red}4.一键安装失败${Font}\n"
    printf "${Green}一般是证书获取失败,检查你的域名输入是否正确,还有域名是否绑定了当前机器的 IP ${Font}\n"
    printf "${Yellow} ------------------------------------------------ ${Font}\n"

    printf "${Red}5.ChatGPT访问不了${Font}\n"
    printf "${Green}可能性1): 你的VPS是大陆、香港或美国LA地区  ${Font}\n"
    printf "${Green}可能性2): key失效前往 https://fscarmen.cloudflare.now.cc/ 重新获取 ${Font}\n"
}

select_xray_append_type() {
    printf "${Green}选择要插入的协议 ${Font}\n"
    printf "${Purple}-------------------------------- ${Font}\n"
    
    # 2. 调用你之前的函数来生成菜单项
    menu_item "1" "shadowsocket" "$Green"
    menu_item "2" "socks5" "$Green"
    menu_item "3" "redirect" "$Green"
    menu_item "4" "vless-reality-tcp" "$Cyan"
    menu_item "5" "vless-reality-grpc" "$Cyan"
    menu_item "q" "不装了" "$Red"
    
    printf "${Purple}-------------------------------- ${Font}\n\n"
    
    # 3. 兼容性读取 (printf + read -r)
    printf "输入数字(回车确认): "
    read -r menu_num
    # 4. 打印空行
    printf "\n"
    mkdir -p ${xray_path}
    case $menu_num in
    1)
        xray_shadowsocket_append
        ;;
    2)
        socks5_append
        ;;
    3)
        xray_redirect_append
        exit
        ;;
    4)
        xray_vless_reality_tcp_append
        ;;
    5)
        xray_vless_reality_grpc_append
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

select_singbox_append_type() {
    printf "${Green}选择要插入的协议 ${Font}\n"
    printf "${Purple}-------------------------------- ${Font}\n"
    
    # 2. 复用你之前的 menu_item 函数
    menu_item "1" "shadowsocket"
    menu_item "2" "hysteria2"
    menu_item "3" "vless-reality-tcp"
    menu_item "4" "vless-reality-grpc"
    menu_item "5" "redirect"
    menu_item "q" "不装了" "$Red"
    
    printf "${Purple}-------------------------------- ${Font}\n\n"
    
    # 3. 兼容所有系统的读取方式：先 printf 提示，再 read 读取
    printf "输入数字(回车确认): "
    read -r menu_num
    
    # 4. 打印一个空行保持美观
    printf "\n"
    case $menu_num in
    1)
        singbox_shadowsocket_append
        ;;
    2)
        singbox_hy2_append
        ;;
    3)
        singbox_reality_tcp_append
        ;;
    4)
        singbox_reality_grpc_append
        ;;
    5)
        singbox_redirect_append
        exit
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

singbox_select() {
    printf "${Green}选择安装的协议 ${Font}\n"
    printf "${Purple}-------------------------------- ${Font}\n"
    
    # 2. 直接调用你的 menu_item 函数
    menu_item "1" "hysteria2"
    menu_item "2" "vless-reality-tcp"
    menu_item "3" "vless-reality-grpc"
    menu_item "4" "vless-reality-h2"
    menu_item "5" "shadowsocket"
    menu_item "10" "redirect"
    menu_item "q" "不装了" "$Red"
    
    printf "${Purple}-------------------------------- ${Font}\n\n"
    
    # 3. 兼容所有系统的读取方式：先 printf 提示，再 read 读取
    printf "输入数字(回车确认): "
    read -r menu_num
    
    # 4. 打印一个空行保持美观
    printf "\n"
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
    10)
        singbox_redirect
        exit
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

xray_select() {
    printf "${Green}选择安装的协议 ${Font}\n"
    printf "${Purple}-------------------------------- ${Font}\n"
    
    # 2. 复用你的 menu_item 函数 (数字, 内容, 颜色)
    menu_item "1" "vless-reality-tcp" "$Green"
    menu_item "2" "vless-reality-grpc" "$Cyan"
    menu_item "3" "vless-reality-h2" "$Green"
    menu_item "4" "redirect" "$Green"
    menu_item "31" "shadowsocket" "$Cyan"
    menu_item "q" "不装了" "$Red"
    
    printf "${Purple}-------------------------------- ${Font}\n\n"
    
    # 3. 兼容所有系统的读取方式：先 printf 提示，再 read 读取
    printf "输入数字(回车确认): "
    read -r menu_num
    printf "\n"
    mkdir -p ${xray_path}
    case $menu_num in
    1)
        xray_vless_reality_tcp
        ;;
    2)
        xray_vless_reality_grpc
        ;;
    3)
        xray_vless_reality_h2
        ;;
    4)
        xray_redirect
        exit
        ;;
    31)
        xray_shadowsocket
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

mihomo_select() {
    printf "${Green}选择安装的协议 ${Font}\n"
    printf "${Purple}-------------------------------- ${Font}\n"
    
    # 2. 调用 menu_item 函数，保持数字与你给出的需求一致 (1, 2, 4, q)
    menu_item "1" "shadowsocket" "$Green"
    menu_item "2" "vless-reality-grpc" "$Cyan"
    menu_item "3" "hysteria2" "$Cyan"
    menu_item "4" "redirect" "$Green"
    menu_item "q" "不装了" "$Red"
    
    printf "${Purple}-------------------------------- ${Font}\n\n"
    
    # 3. 兼容所有系统的读取方式：先 printf 提示，再 read 读取
    # 这样在 Alpine 下不会报错，且光标位置与 read -p 一致
    printf "输入数字(回车确认): "
    read -r menu_num
    printf "\n"
    case $menu_num in
    1)
        mihomo_shadowsocket
        ;;
    2)
        mihomo_vless_reality_grpc
        ;;
    3)
        mihomo_hysteria2
        ;;
    4)
        mihomo_redirect
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

select_mihomo_append_type() {
    printf "${Green}选择要插入的协议 ${Font}\n"
    printf "${Purple}-------------------------------- ${Font}\n"
    
    # 2. 复用 menu_item 函数 (数字, 内容, 颜色)
    # 保持你需求的数字跳跃: 1, 2, 4
    menu_item "1" "shadowsocket" "$Green"
    menu_item "2" "vless-reality-grpc" "$Cyan"
    menu_item "3" "hysteria2" "$Cyan"
    menu_item "4" "redirect" "$Green"
    menu_item "q" "不装了" "$Red"
    
    printf "${Purple}-------------------------------- ${Font}\n\n"
    
    # 3. 兼容性读取：先用 printf 提示，再用 read 读取
    # 这样在 Alpine/BusyBox 环境下不会报错
    printf "输入数字(回车确认): "
    read -r menu_num
    
    # 4. 打印一个空行，保持间距美观
    printf "\n"
    case $menu_num in
    1)
        mihomo_shadowsocket
        ;;
    2)
        mihomo_vless_reality_grpc
        ;;
    3)
        mihomo_hysteria2
        ;;
    4)
        mihomo_redirect
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

menu() {
    # 1. 使用 printf 重新构建布局，用固定空格代替 \t 以保证在不同终端下对齐
    printf "${Cyan}——————————————————————————————————— 脚本信息 ———————————————————————————————————${Font}\n"
    printf "                                ${Yellow}Taffy 脚本${Font}\n"
    printf "                        ${Yellow}--- Authored By uerax ---${Font}\n"
    printf "                  ${Yellow}https://github.com/uerax/taffy-onekey${Font}\n"
    printf "                              ${Yellow}版本号：${version}${Font}\n"
    printf "${Cyan}——————————————————————————————————— 安装向导 ———————————————————————————————————${Font}\n"
    
    # 使用 printf 的格式化能力来保证两列对齐
    printf "${Blue}0)   更新脚本${Font}\n"
    printf "${Green}1)   一键安装 Xray${Font}          ${Green}11)  一键安装 Singbox${Font}\n"
    printf "${Cyan}2)   插入 Xray 协议${Font}         ${Cyan}12)  插入 Singbox 协议${Font}\n"
    printf "${Cyan}3)   更换 Xray 协议${Font}         ${Cyan}13)  更换 Singbox 协议${Font}\n"
    printf "${Purple}4)   安装/更新/回退 Xray${Font}    ${Purple}14)  展示 Singbox 面板${Font}\n"
    printf "${Yellow}5)   卸载 Xray${Font}              ${Purple}15)  查看 Singbox 配置${Font}\n"
    printf "${Purple}6)   查看 Xray 配置链接${Font}\n"
    
    printf "${Cyan}————————————————————————————————————————————————————————————————————————————————${Font}\n"
    printf "${Green}21)  一键安装 Mihomo${Font}\n"
    printf "${Cyan}22)  插入 Mihomo 协议${Font}\n"
    printf "${Purple}25)  查看 Mihomo 配置链接${Font}\n"
    
    printf "${Cyan}————————————————————————————————————————————————————————————————————————————————${Font}\n"
    printf "${Yellow}99)  常见问题${Font}               ${Green}100) 开启 BBR${Font}\n"
    printf "${Red}999) 完全卸载${Font}               ${Red}q)   退出${Font}\n"
    printf "${Cyan}————————————————————————————————————————————————————————————————————————————————${Font}\n\n"

    # 2. 兼容性读取 (解决 Alpine 不支持 read -p 的问题)
    printf "输入数字(回车确认)："
    read -r menu_num
    
    # 3. 打印空行
    printf "\n"
    case $menu_num in
    0)
    update_script
    ;;
    1)
    xray_onekey_install
    ;;
    2)
    select_xray_append_type
    ;;
    3)
    xray_select
    ;;
    4)
    xray_upgrade
    ;;
    5)
    uninstall_xray
    ;;
    6)
    show_xray_info
    ;;
    11)
    singbox_onekey_install
    ;;
    12)
    select_singbox_append_type
    ;;
    13)
    singbox_select
    ;;
    14)
    singbox_operation
    ;;
    15)
    show_singbox_info
    ;;
    21)
    mihomo_onekey_install
    ;;
    22)
    select_mihomo_append_type
    ;;
    25)
    show_mihomo_info
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
        xray_onekey_install
        ;;
    singbox)
        singbox_onekey_install
        ;;
    mihomo)
         mihomo_onekey_install
        ;;
    uninstall)
        uninstall
        ;;
    *)
        menu
        ;;
esac
