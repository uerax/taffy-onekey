#!/bin/bash

set -e -o pipefail

ARCH_RAW=$(uname -m)
case "${ARCH_RAW}" in
    'x86_64')    ARCH='amd64';;
    'x86' | 'i686' | 'i386')     ARCH='386';;
    'aarch64' | 'arm64') ARCH='arm64';;
    'armv7l')   ARCH='armv7';;
    's390x')    ARCH='s390x';;
    *)          echo "Unsupported architecture: ${ARCH_RAW}"; exit 1;;
esac

VERSION=$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest \
    | grep tag_name \
    | cut -d ":" -f2 \
    | sed 's/\"//g;s/\,//g;s/\ //g;s/v//')

if [ -z "${VERSION}" ]; then
    echo "Failed to resolve sing-box version"
    exit 1
fi

# OS detect
OS_ID=""
if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID}"
fi

install_deb() {
    curl -fLo sing-box.deb "https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box_${VERSION}_linux_${ARCH}.deb"
    if command -v sudo >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
        sudo dpkg -i sing-box.deb
    else
        dpkg -i sing-box.deb
    fi
    rm -f sing-box.deb
}

install_alpine() {
    # Official binary tarball for musl/Alpine
    case "${ARCH}" in
        amd64) TB_ARCH=amd64 ;;
        arm64) TB_ARCH=arm64 ;;
        armv7) TB_ARCH=armv7 ;;
        386) TB_ARCH=386 ;;
        s390x) TB_ARCH=s390x ;;
        *) echo "Unsupported Alpine arch: ${ARCH}"; exit 1 ;;
    esac
    TB="sing-box-${VERSION}-linux-${TB_ARCH}.tar.gz"
    curl -fLo "${TB}" "https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/${TB}"
    tar -xzf "${TB}"
    install -m 755 "sing-box-${VERSION}-linux-${TB_ARCH}/sing-box" /usr/local/bin/sing-box
    rm -rf "${TB}" "sing-box-${VERSION}-linux-${TB_ARCH}"
    mkdir -p /etc/sing-box
    # OpenRC service
    if command -v rc-update >/dev/null 2>&1 && [ ! -f /etc/init.d/sing-box ]; then
        cat > /etc/init.d/sing-box <<'OPENRC'
#!/sbin/openrc-run
name="sing-box"
description="sing-box service"
command="/usr/local/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"
OPENRC
        chmod +x /etc/init.d/sing-box
    fi
    # systemd unit (rare on alpine but possible)
    if [ -d /etc/systemd/system ] && [ ! -f /etc/systemd/system/sing-box.service ]; then
        cat > /etc/systemd/system/sing-box.service <<'UNIT'
[Unit]
Description=sing-box service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
UNIT
    fi
}

case "${OS_ID}" in
    alpine)
        install_alpine
        ;;
    debian|ubuntu|*)
        if command -v dpkg >/dev/null 2>&1; then
            install_deb
        elif [ "${OS_ID}" = "alpine" ]; then
            install_alpine
        else
            echo "No dpkg found; attempting binary install"
            install_alpine
        fi
        ;;
esac

echo "sing-box v${VERSION} installed"
