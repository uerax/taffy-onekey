ARCH_RAW=$(uname -m)
case "${ARCH_RAW}" in
    'x86_64')    ARCH='amd64';;
    'x86' | 'i686' | 'i386')     ARCH='386';;
    'aarch64' | 'arm64') ARCH='arm64';;
    'armv7l')   ARCH='armv7';;
    's390x')    ARCH='s390x';;
    *)          echo "Unsupported architecture: ${ARCH_RAW}"; exit 1;;
esac

# 2. 如果是 Alpine，优先尝试包管理器 (最稳妥)
if command -v apk >/dev/null 2>&1; then
    apk add yq --no-cache 2>/dev/null && return 0
fi

VERSION=$(curl -s https://api.github.com/repos/mikefarah/yq/releases/latest \
    | grep tag_name \
    | cut -d ":" -f2 \
    | sed 's/\"//g;s/\,//g;s/\ //g;s/v//')

curl -Lo /usr/local/bin/yq "https://github.com/mikefarah/yq/releases/download/v${VERSION}/yq_linux_${ARCH}"

chmod +x /usr/local/bin/yq