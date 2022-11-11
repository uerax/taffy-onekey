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
link=""

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
    source /etc/os-release
    if [[ "${ID}"=="debian" && ${VERSION_ID} -ge 9 ]]; then
        info "检测系统为 debian"
        apt update
    elif [[ "${ID}"=="ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 18 ]]; then
        info "检测系统为 ubuntu"
        apt update
    elif ["${ID}"=="centos"]; then
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
    if ! command -v iptables >/dev/null 2>&1; then
        # 主要针对oracle vps
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

    mkdir -p /home/xray/webpage/ && cd /home/xray/webpage/

    wget -O web.zip --no-check-certificate https://github.com/hentai121/hentai121.github.io/archive/refs/heads/master.zip
    judge "伪装站 下载"
    unzip web.zip && mv -f hentai121.github.io-master blog-main && rm web.zip
}

domain_handle() {
    echo -e "------------------------------------------"
    read -rp "输入你的域名(eg: www.example.com):" domain
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

    cat >/etc/nginx/conf.d/xray.conf <<EOF
server {
    listen 80;
    server_name ${domain};
    root /home/xray/webpage/blog-main;
    index index.html;
}
EOF

    systemctl restart nginx
}

apply_certificate() {
    wget -O - https://get.acme.sh | sh
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

flush_certificate() {
    cat >/home/xray/xray_cert/xray-cert-renew.sh <<EOF
#!/bin/bash

/root/.acme.sh/acme.sh --install-cert -d ${domain} --ecc --fullchain-file /home/xray/xray_cert/xray.crt --key-file /home/xray/xray_cert/xray.key
echo "Xray Certificates Renewed"

chmod +r /home/xray/xray_cert/xray.key
echo "Read Permission Granted for Private Key"

sudo systemctl restart xray
echo "Xray Restarted"
EOF

    chmod +x /home/xray/xray_cert/xray-cert-renew.sh

    (
        crontab -l | grep -v "0 1 1 * *   bash /home/xray/xray_cert/xray-cert-renew.sh"
        echo "0 1 1 * *   bash /home/xray/xray_cert/xray-cert-renew.sh"
    ) | crontab -

}

xray_install() {
    wget --no-check-certificate https://github.com/XTLS/Xray-install/raw/main/install-release.sh
    judge "Xray安装脚本 下载"
    bash install-release.sh
    judge "Xray 安装"
    rm install-release.sh
}

xray_configure() {
    mkdir -p /home/xray/xray_log && touch /home/xray/xray_log/access.log && touch /home/xray/xray_log/error.log && chmod a+w /home/xray/xray_log/*.log
}

info_return() {
    echo -e "安装成功!"
    echo -e "你的密码为: ${Pword}"
}

# 暂时懒得加 TODO
select_type() {
    echo -e "${Green} 选择安装的模式 ${Font}"
    echo -e "${Green} 1:Trojan-TCP-XTLS ${Font}"
    echo -e "${Green} 2:Trojan-gRpc ${Font}"
    read -rp "请输入数字: " menu_num
    case $menu_num in
    1)
        trojan_tcp_xtls
        ;;
    2)
        trojan_grpc
        ;;
    *)
        error "请输入正确的数字"
        select_type
        ;;
    esac
}

trojan_grpc() {
    Pword=$(xray uuid)
    cat >/usr/local/etc/xray/config.json <<EOF
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
            "password": "${Pword}" // 填写你的 password
          }
        ]
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "crayfish" // 填写你的 ServiceName
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

    systemctl start xray && systemctl enable xray
    sleep 3

    cat >>/etc/nginx/conf.d/xray.conf <<EOF
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
	root /var/www/html;

	ssl_certificate /home/xray/xray_cert/xray.crt;
	ssl_certificate_key /home/xray/xray_cert/xray.key;
	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
	
	client_header_timeout 52w;
        keepalive_timeout 52w;
	# 在 location 后填写 /你的 ServiceName
	location /crayfish {
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

link="trojan://${Pword}@${domain}:443?security=tls&type=grpc&path=crayfish&headerType=none#${domain}"


}

trojan_tcp_xtls() {
    Pword=$(xray uuid)
    cat >/usr/local/etc/xray/config.json <<EOF
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
                        "password":"${Pword}",  // 密码
                        "flow": "xtls-rprx-direct"
                    }
                ],
                "fallbacks": [
                    {
                        "dest": 8080
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "xtls",
                "xtlsSettings": {
                    "alpn": [
                        "http/1.1",
                        "h2"
                    ],
                    "certificates": [
                        {
                            "certificateFile": "/home/xray/xray_cert/xray.crt",  // 证书文件绝对目录
                            "keyFile": "/home/xray/xray_cert/xray.key",  // 密钥文件绝对目录
                            "ocspStapling": 3600  // 验证周期 3600 秒
                        }
                    ],
                    "minVersion": "1.2"  // 如果是ecc证书则最低使用 TLSv1.2 ，如果你不清楚证书类型或者不是 ecc 证书，删掉这行
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
    systemctl start xray && systemctl enable xray
    sleep 3

    cat >>/etc/nginx/conf.d/xray.conf <<EOF
server {
    listen 80;
    server_name ${domain};
    return 301 https://\$http_host\$request_uri;
}
server {
   listen 127.0.0.1:8080;
   root /home/xray/webpage/blog-main;
   index index.html;
   add_header Strict-Transport-Security "max-age=63072000" always;
}
EOF

link="trojan://${Pword}@${domain}:443?security=tls&type=tcp&headerType=none#${domain}"
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

install
