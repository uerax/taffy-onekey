#!/bin/sh

set -e

detect_os() {
    . '/etc/os-release'
    case "${ID}" in
        "debian"|"ubuntu")            
            OS="debian"
            ;;
            
        "alpine")
            OS="alpine"
            ;;

        *)
            exit 1
            ;;
    esac
}

install_mihomo() {
    ARCH_RAW=$(uname -m)
    case "${ARCH_RAW}" in
        'x86_64')    ARCH='amd64';;
        'x86' | 'i686' | 'i386') ARCH='386';;
        'aarch64' | 'arm64') ARCH='arm64';;
        'armv7l')   ARCH='armv7';;
        's390x')    ARCH='s390x';;
        *) echo "Unsupported architecture: ${ARCH_RAW}"; exit 1;;
    esac

    if [ -n "$SPECIFIED_VERSION" ]; then 
        VERSION="$SPECIFIED_VERSION" 
    else 
        VERSION=$(curl -s https://gh-proxy.org/https://api.github.com/repos/MetaCubeX/mihomo/releases/latest \
            | grep tag_name \
            | cut -d ":" -f2 \
            | sed 's/\"//g;s/\,//g;s/\ //g;s/v//')     
    fi

    if [ "$OS" = "debian" ]; then
        curl -Lo mihomo.deb "https://gh-proxy.org/https://github.com/MetaCubeX/mihomo/releases/download/v${VERSION}/mihomo-linux-${ARCH}-v${VERSION}.deb"
        dpkg -i mihomo.deb
        rm mihomo.deb

        # systemd service
        cat > /etc/systemd/system/mihomo.service <<EOF
[Unit]
Description=mihomo Daemon
After=network.target

[Service]
Type=simple
Restart=always
ExecStart=/usr/bin/mihomo -d /etc/mihomo

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable mihomo
        systemctl start mihomo

    elif [ "$OS" = "alpine" ]; then
        curl -Lo mihomo.tar.gz "https://gh-proxy.org/https://github.com/MetaCubeX/mihomo/releases/download/v${VERSION}/mihomo-linux-${ARCH}-v${VERSION}.tar.gz"
        tar -xzf mihomo.tar.gz -C /usr/local/bin
        rm mihomo.tar.gz

        mkdir -p /etc/mihomo
        wget -O /etc/mihomo/config.yaml https://gh-proxy.org/https://raw.githubusercontent.com/uerax/taffy-onekey/refs/heads/master/config/Clash/config.yaml

        # openrc init script
        cat > /etc/init.d/mihomo <<'EOF'
#!/sbin/openrc-run
command="/usr/local/bin/mihomo"
command_args="-d /etc/mihomo"
pidfile="/run/mihomo.pid"
EOF
        chmod +x /etc/init.d/mihomo
        rc-update add mihomo default
        rc-service mihomo start
    fi
}

update_mihomo() {
    ARCH_RAW=$(uname -m)
    case "${ARCH_RAW}" in
        'x86_64')    ARCH='amd64';;
        'x86' | 'i686' | 'i386') ARCH='386';;
        'aarch64' | 'arm64') ARCH='arm64';;
        'armv7l')   ARCH='armv7';;
        's390x')    ARCH='s390x';;
        *) echo "Unsupported architecture: ${ARCH_RAW}"; exit 1;;
    esac

    if [ -n "$SPECIFIED_VERSION" ]; then 
        VERSION="$SPECIFIED_VERSION" 
    else 
        VERSION=$(curl -s https://gh-proxy.org/https://api.github.com/repos/MetaCubeX/mihomo/releases/latest \
            | grep tag_name \
            | cut -d ":" -f2 \
            | sed 's/\"//g;s/\,//g;s/\ //g;s/v//')     
    fi

    echo "Updating mihomo to version ${VERSION}..."

    if [ "$OS" = "debian" ]; then
        curl -Lo mihomo.deb "https://gh-proxy.org/https://github.com/MetaCubeX/mihomo/releases/download/v${VERSION}/mihomo-linux-${ARCH}-v${VERSION}.deb"
        dpkg -i mihomo.deb
        rm mihomo.deb
        systemctl daemon-reload
        systemctl restart mihomo
    elif [ "$OS" = "alpine" ]; then
        curl -Lo mihomo.tar.gz "https://gh-proxy.org/https://github.com/MetaCubeX/mihomo/releases/download/v${VERSION}/mihomo-linux-${ARCH}-v${VERSION}.tar.gz"
        tar -xzf mihomo.tar.gz -C /usr/local/bin
        rm mihomo.tar.gz
        rc-service mihomo restart
    fi
}

uninstall_mihomo() {
    if [ "$OS" = "debian" ]; then
        systemctl stop mihomo
        systemctl disable mihomo
        dpkg -r mihomo || true
        rm -f /etc/systemd/system/mihomo.service
        rm -rf /etc/mihomo
        systemctl daemon-reload
    elif [ "$OS" = "alpine" ]; then
        rc-service mihomo stop
        rc-update del mihomo
        rm -f /etc/init.d/mihomo
        rm -f /usr/local/bin/mihomo
        rm -rf /etc/mihomo
    fi
    echo "mihomo uninstalled."
}

detect_os

SPECIFIED_VERSION="$2"

case "$1" in
    install) install_mihomo ;;
    update) update_mihomo ;;
    remove) uninstall_mihomo ;;
    *) echo "Usage: $0 {install|update|remove}" ;;
esac
