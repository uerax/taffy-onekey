ARCH_RAW=$(uname -m)
case "${ARCH_RAW}" in
    'x86_64')    ARCH='amd64';;
    'x86' | 'i686' | 'i386')     ARCH='386';;
    'aarch64' | 'arm64') ARCH='arm64';;
    'armv7l')   ARCH='armv7';;
    's390x')    ARCH='s390x';;
    *)          echo "Unsupported architecture: ${ARCH_RAW}"; exit 1;;
esac

VERSION=$(curl -s https://api.github.com/repos/MetaCubeX/mihomo/releases/latest \
    | grep tag_name \
    | cut -d ":" -f2 \
    | sed 's/\"//g;s/\,//g;s/\ //g;s/v//')


curl -Lo mihomo.deb "https://github.com/MetaCubeX/mihomo/releases/download/v${VERSION}/mihomo-linux-${ARCH}-v${VERSION}.deb"

sudo dpkg -i mihomo.deb
rm mihomo.deb

