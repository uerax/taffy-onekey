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

version="v1.6.1"

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

INS="apt install -y"
password=""
domain=""
link=""
port="1919"

install() {
    is_root
    get_system
    env_install
    # increase_max_handle
    port_check 80
    port_check 443
    close_firewall
    nginx_install
    domain_handle
    apply_certificate
    flush_certificate
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

function env_install() {

    ${INS} wget
    judge "wget 安装"
    ${INS} unzip
    judge "unzip 安装"
    ${INS} lsof
    judge "lsof 安装"
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

    wget -O web.zip --no-check-certificate https://github.com/hentai121/hentai121.github.io/archive/refs/heads/master.zip
    judge "伪装站 下载"
    unzip web.zip && mv -f hentai121.github.io-master ${web_dir} && rm web.zip
}

update_web() {
    cd ${web_path}
    wget -O web.zip --no-check-certificate https://github.com/hentai121/hentai121.github.io/archive/refs/heads/master.zip
    judge "伪装站 下载"
    unzip web.zip
    rm -rf ./${web_dir}
    mv -f hentai121.github.io-master ${web_dir}
    rm web.zip
}

domain_handle() {
    echo -e "------------------------------------------"
    read -rp "输入你的域名(eg: www.example.com):" domain
    ok "正在获取 IP 地址信息"
    parse_ipv4=$(curl -sm8 ipget.net/?"${domain}")
    local_ipv4=$(curl -s4m8 https://ifconfig.co)
    if [[ ${parse_ipv4} == "${local_ipv4}" ]]; then
        ok "域名ip解析通过"
        sleep 2
    else
        error "域名解析ip: ${parse_ipv4} 与本机不符, 请检测是否有误"
    fi

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
}

apply_certificate() {
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

info_return() {
    echo -e "${Green}安装成功!${Font}"
    echo -e "${Green}链接:${Font} ${link}"
    echo -e "${Green}密码为:${Font} ${password}"
    echo -e "${Green}端口为:${Font} ${port}"
}

trojan_grpc() {
    if [ "$domain" = "" ]
    then
      echo -e ""
      read -rp "输入你的域名(回车确认)：" domain
    fi
    password=$(xray uuid)
    port="443"
    cat >${xray_cfg} <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "listen": "/dev/shm/Xray-Trojan-gRPC.socket,0666",
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "${password}" // 填写你的 password
          }
        ]
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "${ws_path}" // 填写你的 ServiceName
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {}
    },
    {
      "tag": "blocked",
      "protocol": "blackhole",
      "settings": {}
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "ip": [
          "geoip:private"
        ],
        "outboundTag": "blocked"
      }
    ]
  }
}
EOF
    systemctl restart xray 
    systemctl enable xray
    sleep 3

    cat >${nginx_cfg} <<EOF
server {
    listen 80;
    server_name ${domain};
    return 301 https://\$http_host\$request_uri;
}
server {
	listen 443 ssl http2 so_keepalive=on;
    listen [::]:443 ssl http2 so_keepalive=on;
	server_name ${domain};

	index index.html;
	root ${web_path}/${web_dir};

	ssl_certificate ${ca_crt};
	ssl_certificate_key ${ca_key};
	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
	
	client_header_timeout 52w;
    keepalive_timeout 52w;
	# 在 location 后填写 /你的 ServiceName
	location /${ws_path} {
		if (\$content_type !~ "application/grpc") {
			return 404;
		}
		client_max_body_size 0;
		client_body_buffer_size 512k;
		grpc_set_header X-Real-IP \$remote_addr;
		client_body_timeout 52w;
		grpc_read_timeout 52w;
		grpc_pass unix:/dev/shm/Xray-Trojan-gRPC.socket;
	}
}
EOF

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
    if [ "$domain" = "" ]
    then
      read -rp "输入你的域名(回车确认)：" domain
    fi
    password=$(xray uuid)
    port="443"
    cat >${xray_cfg} <<EOF
{
    "log": {
        "loglevel": "debug"
    },
    "inbounds": [
        {
            "port": 443,
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "password":"${password}"  // 密码
                    }
                ],
                "fallbacks": [
                    {
                        "dest": ${port}
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "tlsSettings": {
                    "alpn": [
                        "http/1.1"
                    ],
                    "certificates": [
                        {
                            "certificateFile": "${ca_crt}",
                            "keyFile": "${ca_key}"
                        }
                    ]
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom"
        }
    ]
}
EOF
    systemctl restart xray

    systemctl enable xray

    sleep 3

    cat >${nginx_cfg} <<EOF
server {
    listen 80;
    server_name ${domain};
    return 301 https://\$http_host\$request_uri;
}
server {
   listen 127.0.0.1:${port};
   root ${web_path}/${web_dir};
   index index.html;
   add_header Strict-Transport-Security "max-age=63072000" always;
}
EOF

systemctl restart nginx

link="trojan://${password}@${domain}:${port}?flow=xtls-rprx-direct&security=tls&type=tcp&headerType=none#${domain}"

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
    if [ "$domain" = "" ]
    then
      read -rp "输入你的域名(回车确认)：" domain
    fi
    password=$(xray uuid)
    cat >${xray_cfg} <<EOF
{
  "log":{
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": ${port},
      "listen": "127.0.0.1",
      "protocol": "vmess",
      "settings": {
        "clients": [{
          "id": "${password}",
          "alterID": 0
        }]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/${ws_path}"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "domainStrategy": "IPOnDemand",
    "rules": [
      {
        "type": "field",
        "protocol": ["bittorrent"],
        "outboundTag": "blocked"
      }
    ]
  }
}
EOF
    systemctl restart xray
    
    systemctl enable xray

    sleep 3

    cat >${nginx_cfg} <<EOF
server {
    listen 80;
    server_name ${domain};
    return 301 https://\$http_host\$request_uri;
}
server {
    listen 443 ssl;
    server_name ${domain};

    index index.html;
    root ${web_path}/${web_dir};

    ssl_certificate ${ca_crt};
    ssl_certificate_key ${ca_key};
    ssl_protocols         TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers           HIGH:!aNULL:!MD5;

    # 在 location 
    location /${ws_path} {
    proxy_pass http://127.0.0.1:${port};
    proxy_redirect off;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$http_host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF

systemctl restart nginx

link="vmess://${password}@${domain}:${port}?encryption=none&security=tls&type=ws&host=${domain}&path=%2F${ws_path}#${domain}"

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
    if [ "$domain" = "" ]
    then
      read -rp "输入你的域名(回车确认)：" domain
    fi
    password=$(xray uuid)
    cat >${xray_cfg} <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "listen": "/dev/shm/Xray-VLESS-WSS-Nginx.socket,0666",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${password}" // 填写你的 UUID
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/${ws_path}" // 填写你的 path
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {}
    },
    {
      "tag": "blocked",
      "protocol": "blackhole",
      "settings": {}
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "ip": [
          "geoip:private"
        ],
        "outboundTag": "blocked"
      }
    ]
  }
}
EOF
    systemctl restart xray && systemctl enable xray

    sleep 3

    cat > ${nginx_cfg} <<EOF
server {
    listen 80;
    server_name ${domain};
    return 301 https://\$http_host\$request_uri;
}
server {
	listen 443 ssl http2;
	server_name ${domain};

	index index.html;
	root ${web_path}/${web_dir};

	ssl_certificate ${ca_crt};
	ssl_certificate_key ${ca_key};
	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
	
	# 在 location 后填写 /你的 path
	location /${ws_path} {
        if (\$http_upgrade != "websocket") {
            return 404;
        }
        proxy_pass http://unix:/dev/shm/Xray-VLESS-WSS-Nginx.socket;
        proxy_redirect off;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 52w;
    }
}

EOF

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
    if [ "$domain" = "" ]
    then
      read -rp "输入你的域名(回车确认)：" domain
    fi
    password=$(xray uuid)
    cat > ${xray_cfg} <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "listen": "/dev/shm/Xray-VLESS-gRPC.socket,0666",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${password}" // 填写你的 UUID
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "grpc",
        "wsSettings": {
          "path": "/${ws_path}" // 填写你的 path
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {}
    },
    {
      "tag": "blocked",
      "protocol": "blackhole",
      "settings": {}
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "ip": [
          "geoip:private"
        ],
        "outboundTag": "blocked"
      }
    ]
  }
}
EOF
    systemctl restart xray && systemctl enable xray

    sleep 3

    cat >${nginx_cfg} <<EOF
server {
    listen 80;
    server_name ${domain};
    return 301 https://\$http_host\$request_uri;
}
server {
	listen 443 ssl http2 so_keepalive=on;
	server_name ${domain};

	index index.html;
	root ${web_path}/${web_dir};

	ssl_certificate ${ca_crt};
	ssl_certificate_key ${ca_key};
	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
	
  client_header_timeout 52w;
  keepalive_timeout 52w;

	# 在 location 后填写 /你的 path
	location /${ws_path} {
    if (\$content_type !~ "application/grpc") {
			return 404;
		}
    client_max_body_size 0;
		client_body_buffer_size 512k;
		grpc_set_header X-Real-IP \$remote_addr;
		client_body_timeout 52w;
		grpc_read_timeout 52w;
		grpc_pass unix:/dev/shm/Xray-VLESS-gRPC.socket;
    }
}

EOF

systemctl restart nginx

link="vless://${password}@${domain}:${port}?encryption=none&security=tls&sni=${domain}&type=grpc&host=${domain}&path=%2F${ws_path}#${domain}"

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
  if [ "$domain" = "" ]
  then
    read -rp "输入你的域名(回车确认)：" domain
  fi
  password=$(xray uuid)
  vless_tcp_xtls_vision_xray_cfg
  systemctl restart xray && systemctl enable xray
  sleep 3
  vless_tcp_xtls_vision_nginx_cfg
  systemctl restart nginx
}

vless_tcp_xtls_vision_nginx_cfg() {
  cd /etc/nginx/ && wget -N https://raw.githubusercontent.com/uerax/xray-script/master/nginx/vless_tcp_xtls_vision.conf -O /etc/nginx/nginx.conf
}

vless_tcp_xtls_vision_xray_cfg() {
  wget -N https://raw.githubusercontent.com/uerax/xray-script/master/xray/vless_tcp_xtls_vision.json -O config.conf && mv config.conf ${xray_cfg}
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
    rm -rf /home/xray
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
    echo -e "${Red}q)  不进行操作${Font}"
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
    q)
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
