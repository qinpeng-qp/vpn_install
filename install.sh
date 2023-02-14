#!/bin/bash

#=================================================== ===
# 系统要求：Debian 9+/Ubuntu 18.04+/Centos 7+
# 作者：wulabing
# 说明：V2ray ws+tls onekey 管理
# 版本：1.0
# 邮箱：admin@wulabing.com
# 官方文档：www.v2ray.com
#=================================================== ===

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
导出路径

cd "$(
    cd "$(目录名 "$0")" || 出口
    密码
)" || 退出

#字体颜色
绿色="\033[32m"
红色="\033[31m"
# 黄色="\033[33m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
字体="\033[0m"

#通知信息
# Info="${绿色}[信息]${字体}"
OK="${绿色}[OK]${字体}"
Error="${Red}[错误]${Font}"

# 版本
shell_version="1.1.9.0"
shell_mode="无"
github_branch="主"
version_cmp="/tmp/version_cmp.tmp"
v2ray_conf_dir="/etc/v2ray"
nginx_conf_dir="/etc/nginx/conf/conf.d"
v2ray_conf="${v2ray_conf_dir}/config.json"
nginx_conf="${nginx_conf_dir}/v2ray.conf"
nginx_dir="/etc/nginx"
web_dir="/home/wwwroot"
nginx_openssl_src="/usr/local/src"
v2ray_bin_dir_old="/usr/bin/v2ray"
v2ray_bin_dir="/usr/local/bin/v2ray"
v2ctl_bin_dir="/usr/local/bin/v2ctl"
v2ray_info_file="$HOME/v2ray_info.inf"
v2ray_qr_config_file="/usr/local/vmess_qr.json"
nginx_systemd_file="/etc/systemd/system/nginx.service"
v2ray_systemd_file="/etc/systemd/system/v2ray.service"
v2ray_access_log="/var/log/v2ray/access.log"
v2ray_error_log="/var/log/v2ray/error.log"
amce_sh_file="/root/.acme.sh/acme.sh"
ssl_update_file="/usr/bin/ssl_update.sh"
nginx_version="1.20.1"
openssl_version="1.1.1k"
jemalloc_version="5.2.1"
old_config_status="关闭"
# v2ray_plugin_version="$(wget -qO- "https://github.com/shadowsocks/v2ray-plugin/tags" | grep -E "/shadowsocks/v2ray-plugin/releases/tag/" | head -1 | sed -r 's/.*tag\/v(.+)\">.*/\1/')"

#移动旧版本配置信息对低于1.0版本1
[[ -f "/etc/v2ray/vmess_qr.json" ]] && mv /etc/v2ray/vmess_qr.json $v2ray_qr_config_file

#临时随机数
random_num=$((RANDOM%12+4))
#生成伪装路径
camouflage="/$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})/"

线程=$(grep '处理器' /proc/cpuinfo | sort -u | wc -l)

源'/etc/os-release'

#从VERSION中推出发行版系统的中文名称，为了在debian/ubuntu下添加相对应的Nginx apt源
VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')

检查系统（）{
    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; 然后
        echo -e "${OK} ${GreenBG} 当前系统为 Centos ${VERSION_ID} ${VERSION} ${Font}"
        INS="百胜"
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]]; 然后
        echo -e "${OK} ${GreenBG} 当前系统为 Debian ${VERSION_ID} ${VERSION} ${Font}"
        INS =“适合”
        $INS 更新
        ## 添加Nginx apt源
    elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 16 ]]; 然后
        echo -e "${OK} ${GreenBG} 当前系统为 Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME} ${Font}"
        INS =“适合”
        rm /var/lib/dpkg/lock
        dpkg --configure -a
        rm /var/lib/apt/lists/lock
        rm /var/cache/apt/archives/lock
        $INS 更新
    别的
        echo -e "${Error} ${RedBG} 当前系统为 ${ID} ${VERSION_ID} 不在的系统列表内，安装中断 ${Font}"
        1号出口
    菲

    $INS 安装 dbus

    systemctl 停止防火墙
    systemctl 禁用防火墙
    echo -e "${OK} ${GreenBG} firewalld 已关闭 ${Font}"

    systemctl 停止 ufw
    systemctl 禁用 ufw
    echo -e "${OK} ${GreenBG} ufw 已关闭 ${Font}"
}

is_root() {
    如果 [ 0 == $UID ]; 然后
        echo -e "${OK} ${GreenBG} 当前用户是root用户，进入安装流程 ${Font}"
        睡觉 3
    别的
        echo -e "${Error} ${RedBG}当前用户不是root用户，请切换到root用户后重新执行脚本${Font}"
        1号出口
    菲
}

法官（） {
    如果 [[ 0 -eq $? ]]; 然后
        echo -e "${OK} ${GreenBG} $1 完成 ${Font}"
        睡觉 1
    别的
        echo -e "${Error} ${RedBG} $1 失败${Font}"
        1号出口
    菲
}

chrony_install() {
    ${INS} -y 安装 chrony
    判断“安装chrony时间同步服务”

    timedatectl set-ntp true

    如果 [[ "${ID}" == "centos" ]]; 然后
        systemctl enable chronyd && systemctl restart chronyd
    别的
        systemctl enable chrony && systemctl restart chrony
    菲

    判断“chronyd启动”

    timedatectl set-timezone 亚洲/上海

    echo -e "${OK} ${GreenBG} 等待时间同步 ${Font}"
    睡觉 10

    chronyc sourcestats -v
    chronyc 跟踪 -v
    日期
    阅读-rp“请确认时间是否正确，范围±3分钟（Y/N）：” chrony_install
    [[ -z ${chrony_install} ]] && chrony_install="Y"
    案例 $chrony_install 在
    [yY][eE][sS] | [年年])
        echo -e "${GreenBG} 继续安装 ${Font}"
        睡觉 2
        ;;
    *)
        echo -e "${RedBG} 安装终止 ${Font}"
        2号出口
        ;;
    经社理事会
}

依赖安装（）{
    ${INS} 安装 wget git lsof -y

    如果 [[ "${ID}" == "centos" ]]; 然后
        ${INS} -y 安装 crontabs
    别的
        ${INS} -y 安装 cron
    菲
    判断“安装crontab”

    如果 [[ "${ID}" == "centos" ]]; 然后
        触摸 /var/spool/cron/root && chmod 600 /var/spool/cron/root
        systemctl 启动 crond && systemctl 启用 crond
    别的
        触摸 /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
        systemctl start cron && systemctl 启用 cron

    菲
    判断“crontab自启动配置”

    ${INS} -y 安装 bc
    判断“安装bc”

    ${INS} -y 安装解压
    判断“安装解压”

    ${INS} -y 安装 qrencode
    判断“安装qrencode”

    ${INS} -y 安装卷曲
    判断“安装卷曲”

    如果 [[ "${ID}" == "centos" ]]; 然后
        ${INS} -y groupinstall "开发工具"
    别的
        ${INS} -y 安装 build-essential
    菲
    判断“编译工具包安装”

    如果 [[ "${ID}" == "centos" ]]; 然后
        ${INS} -y 安装 pcre pcre-devel zlib-devel epel-release
    别的
        ${INS} -y 安装 libpcre3 libpcre3-dev zlib1g-dev dbus
    菲

    # ${INS} -y 安装 rng-tools
    # 判断“rng-tools 安装”

    ${INS} -y install haveged
    # 判断“已经安装”

    # sed -i -r '/^HRNGDEVICE/d;/#HRNGDEVICE=\/dev\/null/a HRNGDEVICE=/dev/urandom' /etc/default/rng-tools

    如果 [[ "${ID}" == "centos" ]]; 然后
        # systemctl start rngd && systemctl enable rngd
        # 判断“rng-tools 启动”
        systemctl start haveged && systemctl enable haveged
        # 判断 "haveged 启动"
    别的
        # systemctl start rng-tools && systemctl enable rng-tools
        # 判断“rng-tools 启动”
        systemctl start haveged && systemctl enable haveged
        # 判断 "haveged 启动"
    菲

    mkdir -p /usr/local/bin >/dev/null 2>&1
}

基本优化（）{
    # 最大文件打开数
    sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    echo '* soft nofile 65536' >>/etc/security/limits.conf
    echo '* hard nofile 65536' >>/etc/security/limits.conf

    # 关闭 Selinux
    如果 [[ "${ID}" == "centos" ]]; 然后
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
        设置强制 0
    菲

}

port_alterid_set() {
    如果 [[ "on" != "$old_config_status" ]]; 然后
        read -rp "请输入连接端口（default:443）："端口
        [[ -z ${port} ]] && 端口="443"
        改变ID="0"
    菲
}

修改路径（） {
    如果 [[ "on" == "$old_config_status" ]]; 然后
        camouflage="$(grep '\"path\"' $v2ray_qr_config_file | awk -F '"' '{print $4}')"
    菲
    sed -i "/\"path\"/c \\\t \"path\":\"${camouflage}\"" ${v2ray_conf}
    判断“V2ray伪装路径修改”
}

modify_inbound_port() {
    如果 [[ "on" == "$old_config_status" ]]; 然后
        端口="$(信息提取'\"端口\"')"
    菲
    如果 [[ "$shell_mode" != "h2" ]]; 然后
        端口=$((随机 + 10000))
        sed -i "/\"port\"/c\"port\":${PORT},"${v2ray_conf}
    别的
        sed -i "/\"port\"/c \"port\":${port},"${v2ray_conf}
    菲
    判断“V2ray inbound_port 修改”
}

修改_UUID() {
    [ -z "$UUID" ] && UUID=$(cat /proc/sys/kernel/random/uuid)
    如果 [[ "on" == "$old_config_status" ]]; 然后
        UUID="$(info_extraction '\"id\"')"
    菲
    sed -i "/\"id\"/c \\\t \"id\":\"${UUID}\","${v2ray_conf}
    判断“V2ray UUID修改”
    [ -f ${v2ray_qr_config_file} ] && sed -i "/\"id\"/c \\ \"id\": \"${UUID}\"," ${v2ray_qr_config_file}
    echo -e "${OK} ${GreenBG} UUID:${UUID} ${Font}"
}

修改_nginx_port() {
    如果 [[ "on" == "$old_config_status" ]]; 然后
        端口="$(信息提取'\"端口\"')"
    菲
    sed -i "/ssl http2;$/c \\\tlisten ${port} ssl http2;" ${nginx_conf}
    sed -i "3c \\\tlisten [::]:${port} http2;" ${nginx_conf}
    判断“V2ray端口修改”
    [ -f ${v2ray_qr_config_file} ] && sed -i "/\"port\"/c \\ \"port\": \"${port}\"," ${v2ray_qr_config_file}
    echo -e "${OK ${GreenBG}端口号:${port ${Font}"
}

修改_nginx_other() {
    sed -i "/server_name/c \\\tserver_name ${domain};" ${nginx_conf}
    sed -i "/location/c \\\tlocation ${伪装}" ${nginx_conf}
    sed -i "/proxy_pass/c \\\tproxy_pass http://127.0.0.1:${PORT};" ${nginx_conf}
    sed -i "/return/c \\\treturn 301 https://${domain}\$request_uri;" ${nginx_conf}
    #sed -i "27i \\\tproxy_intercept_errors on;" ${nginx_dir}/conf/nginx.conf
}

web_camouflage() {
    ##请注意这里和LNMP脚本的默认路径破坏，千万不要在安装了MP环境下使用本脚本，否则后果自负
    rm -rf /home/wwwroot
    mkdir -p /home/wwwroot
    cd /home/wwwroot || 出口
    git 克隆 https://github.com/wulabing/3DCEList.git
    判断“网络站点伪装”
}

v2ray_install() {
    如果 [[ -d /root/v2ray ]]; 然后
        rm -rf /root/v2ray
    菲
    如果 [[ -d /etc/v2ray ]]; 然后
        rm -rf /etc/v2ray
    菲
    mkdir -p /root/v2ray
    cd /root/v2ray || 出口
    wget -N --no-check-certificate https://raw.githubusercontent.com/wulabing/V2Ray_ws-tls_bash_onekey/${github_branch}/v2ray.sh

    如果 [[ -f v2ray.sh ]]; 然后
        rm -rf $v2ray_systemd_file
        systemctl 守护进程重载
        bash v2ray.sh --force
        判断“安装V2ray”
    别的
        echo -e "${Error} ${RedBG} V2ray 安装文件下载失败，请检查下载地址是否可用 ${Font}"
        4号出口
    菲
    #清除临时文件
    rm -rf /root/v2ray
}

nginx_exist_check() {
    if [[ -f "/etc/nginx/sbin/nginx" ]]; 然后
        echo -e "${OK} ${GreenBG} Nginx 已存在，跳过编译安装过程 ${Font}"
        睡觉 2
    elif [[ -d "/usr/local/nginx/" ]]; 然后
        echo -e "${OK} ${GreenBG} 检测到其他套件安装的 Nginx，继续安装会造成冲突，请稍后处理安装${Font}"
        1号出口
    别的
        nginx_install
    菲
}

nginx_install() {
    # if [[ -d "/etc/nginx" ]];那么
    # rm -rf /etc/nginx
    #fi

    wget -nc --no-check-certificate http://nginx.org/download/nginx-${nginx_version}.tar.gz -P ${nginx_openssl_src}
    判断“Nginx下载”
    wget -nc --no-check-certificate https://www.openssl.org/source/openssl-${openssl_version}.tar.gz -P ${nginx_openssl_src}
    判断“openssl 下载”
    wget -nc --no-check-certificate https://github.com/jemalloc/jemalloc/releases/download/${jemalloc_version}/jemalloc-${jemalloc_version}.tar.bz2 -P ${nginx_openssl_src}
    法官“jemalloc 下载”

    cd ${nginx_openssl_src} || 出口

    [[ -d nginx-"$nginx_version" ]] && rm -rf nginx-"$nginx_version"
    tar -zxvf nginx-"$nginx_version".tar.gz

    [[ -d openssl-"$openssl_version" ]] && rm -rf openssl-"$openssl_version"
    tar -zxvf openssl-"$openssl_version".tar.gz

    [[ -d jemalloc-"${jemalloc_version}" ]] && rm -rf jemalloc-"${jemalloc_version}"
    tar -xvf jemalloc-"${jemalloc_version}".tar.bz2

    [[ -d "$nginx_dir" ]] && rm -rf ${nginx_dir}

    echo -e "${OK} ${GreenBG} 即将开始编译安装 jemalloc ${Font}"
    睡觉 2

    cd jemalloc-${jemalloc_version} || 出口
    。/配置
    判断“编译检查”
    make -j "${THREAD}" && 安装
    判断“jemalloc 编译安装”
    echo '/usr/local/lib' >/etc/ld.so.conf.d/local.conf
    配置文件

    echo -e "${OK} ${GreenBG} 即将开始编译安装 Nginx，过程久，请耐心等待 ${Font}"
    睡觉 4

    cd ../nginx-${nginx_version} || 出口

    ./configure --prefix="${nginx_dir}" \
        --with-http_ssl_module \
        --with-http_sub_module \
        --with-http_gzip_static_module \
        --with-http_stub_status_module \
        --with-pcre \
        --with-http_realip_module \
        --with-http_flv_module \
        --with-http_mp4_module \
        --with-http_secure_link_module \
        --with-http_v2_module \
        --with-cc-opt='-O3' \
        --with-ld-opt="-ljemalloc" \
        --with-openssl=../openssl-"$openssl_version"
    判断“编译检查”
    make -j "${THREAD}" && 安装
    判断“Nginx 编译安装”

    # 修改基本配置
    sed -i 's/#user nobody;/user root;/' ${nginx_dir}/conf/nginx.conf
    sed -i 's/worker_processes 1;/worker_processes 3;/' ${nginx_dir}/conf/nginx.conf
    sed -i 's/worker_connections 1024;/worker_connections 4096;/'${nginx_dir}/conf/nginx.conf
    sed -i '$i 包括 conf.d/*.conf;' ${nginx_dir}/conf/nginx.conf

    #删除临时文件
    rm -rf ../nginx-"${nginx_version}"
    rm -rf ../openssl-"${openssl_version}"
    rm -rf ../nginx-"${nginx_version}".tar.gz
    rm -rf ../openssl-"${openssl_version}".tar.gz

    #添加配置文件，旧版脚本
    mkdir ${nginx_dir}/conf/conf.d
}

ssl_install() {
    如果 [[ "${ID}" == "centos" ]]; 然后
        ${INS} 安装 socat nc -y
    别的
        ${INS} 安装 socat netcat -y
    菲
    判断“安装SSL证书生成脚本依赖”

    卷曲 https://get.acme.sh | 嘘
    判断“安装SSL证书脚本生成”
}

域检查（）{
    read -rp "请输入你的域名信息(eg:www.wulabing.com):" domain
    domain_ip=$(curl -sm8 https://ipget.net/?ip="${domain}")
    echo -e "${OK} ${GreenBG} 正在获取公网ip信息，请耐心等待${Font}"
    wgcfv4_status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    wgcfv6_status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    如果 [[ ${wgcfv4_status} =~ "on"|"plus" ]] || [[ ${wgcfv6_status} =~ "on"|"plus" ]]; 然后
        # 关闭wgcf-warp，以防误判VPS IP情况
        wg-quick down wgcf >/dev/null 2>&1
        echo -e "${OK} ${GreenBG} 已关闭 wgcf-warp ${Font}"
    菲
    local_ipv4=$(curl -s4m8 https://ip.gs)
    local_ipv6=$(curl -s6m8 https://ip.gs)
    如果 [[ -z ${local_ipv4} && -n ${local_ipv6} ]]; 然后
        echo -e 名称服务器 2a01:4f8:c2c:123f::1 > /etc/resolv.conf
        echo -e "${OK} ${GreenBG} 识别为 IPv6 Only 的 V，自动添加 DNS64 服务器 ${Font}"
    菲
    echo -e "域名DNS解析到的IP：${domain_ip}"
    echo -e "本机IPv4: ${local_ipv4}"
    echo -e "本机IPv6: ${local_ipv6}"
    睡觉 2
    如果 [[ ${domain_ip} == ${local_ipv4} ]]; 然后
        echo -e "${OK} ${GreenBG} 域名DNS解析IP与本机IPv4匹配${Font}"
        睡觉 2
    elif [[ ${domain_ip} == ${local_ipv6} ]]; 然后
        echo -e "${OK} ${GreenBG} 域名DNS解析IP与本机IPv6匹配 ${Font}"
        睡觉 2
    别的
        echo -e "${Error} ${RedBG} 请确保域名添加正确的 A / AAAA 记录，否则将无法正常使用 V2ray ${Font}"
        echo -e "${Error} ${RedBG} 域名 DNS 解析 IP 与本机 IPv4 / IPv6 不匹配 是否继续安装？（y/n）${Font}" && read -r install
        案例$安装在
        [yY][eE][sS] | [年年])
            echo -e "${GreenBG} 继续安装 ${Font}"
            睡觉 2
            ;;
        *)
            echo -e "${RedBG} 安装终止 ${Font}"
            2号出口
            ;;
        经社理事会
    菲
}

端口存在检查（）{
    如果 [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; 然后
        echo -e "OK} ${G} $1 端口绿色通话 ${Font}"
        睡觉 1
    别的
        echo -e "${Error} ${RedBG} 检测到 $1 被端口，下面为 $1 端口请求信息 ${Fon}"
        lsof -i:"$1"
        echo -e "${OK} ${GreenBG} 5s 后将尝试自动杀死进程进程 ${Font}"
        睡觉 5
        lsof -i:"$1" | awk '{打印 $2}' | grep -v "PID" | xargs 杀死 -9
        echo -e "${OK} ${GreenBG} 杀死完成 ${Font}"
        睡觉 1
    菲
}
极致（）{
    "$HOME"/.acme.sh/acme.sh --set-default-ca --serverletsencrypt

    如果 "$HOME"/.acme.sh/acme.sh --issue --insecure -d "${domain}" --standalone -k ec-256 --force; 然后
        echo -e "${OK} ${GreenBG} SSL 证书生成成功 ${Font}"
        睡觉 2
        mkdir /数据
        if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /data/v2ray.crt --keypath /data/v2ray.key --ecc --force；然后
            echo -e "${OK} ${GreenBG} 证书配置成功 ${Font}"
            睡觉 2
            如果 [[ -n $(type -P wgcf) && -n $(type -P wg-quick) ]]; 然后
                wg-quick up wgcf >/dev/null 2>&1
                echo -e "${OK} ${GreenBG} 已启动 wgcf-warp ${Font}"
            菲
        菲
    别的
        echo -e "${Error} ${RedBG} SSL 证书生成失败 ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        如果 [[ -n $(type -P wgcf) && -n $(type -P wg-quick) ]]; 然后
            wg-quick up wgcf >/dev/null 2>&1
            echo -e "${OK} ${GreenBG} 已启动 wgcf-warp ${Font}"
        菲
        1号出口
    菲
}

v2ray_conf_add_tls() {
    cd /etc/v2ray || 出口
    wget --no-check-certificate https://raw.githubusercontent.com/wulabing/V2Ray_ws-tls_bash_onekey/${github_branch}/tls/config.json -O config.json
    修改路径
    modify_inbound_port
    修改_UUID
}

v2ray_conf_add_h2() {
    cd /etc/v2ray || 出口
    wget --no-check-certificate https://raw.githubusercontent.com/wulabing/V2Ray_ws-tls_bash_onekey/${github_branch}/http2/config.json -O config.json
    修改路径
    modify_inbound_port
    修改_UUID
}

old_config_exist_check() {
    如果 [[ -f $v2ray_qr_config_file ]]; 然后
        echo -e "${OK} ${GreenBG} 检测到旧配置文件，是否读取旧文件配置 [Y/N]?${Font}"
        读取 -r ssl_delete
        案例 $ssl_delete in
        [yY][eE][sS] | [年年])
            echo -e "${OK} ${GreenBG} 已保留旧配置 ${Font}"
            old_config_status="开"
            端口=$(info_extraction '\"端口\"')
            ;;
        *)
            rm -rf $v2ray_qr_config_file
            echo -e "${OK} ${GreenBG} 已删除旧配置 ${Font}"
            ;;
        经社理事会
    菲
}

nginx_conf_add() {
    触摸 ${nginx_conf_dir}/v2ray.conf
    猫 >${nginx_conf_dir}/v2ray.conf <<EOF
    服务器 {
        听 443 ssl http2；
        听 [::]:443 http2;
        ssl_certificate /data/v2ray.crt；
        ssl_certificate_key /data/v2ray.key;
        ssl_protocols TLSv1.3；
        ssl_ciphers TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-128-CCM-8-SHA256:TLS13-AES-128-CCM-SHA256 :EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH +aRSA+3DES:RSA+3DES:!MD5;
        server_name serveraddr.com;
        索引 index.html 索引.htm；
        根 /home/wwwroot/3DCEList；
        error_page 400 = /400.html;

        # 在 TLSv1.3 中配置 0-RTT
        ssl_early_data 开启；
        ssl_stapling 开启；
        ssl_stapling_verify 开启；
        add_header Strict-Transport-Security "max-age=31536000";

        位置/射线/
        {
        代理重定向关闭；
        proxy_read_timeout 1200s；
        proxy_pass http://127.0.0.1:10000;
        proxy_http_version 1.1；
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header 升级 \$http_upgrade;
        proxy_set_header 连接“升级”；
        proxy_set_header 主机 \$http_host;

        # 在 TLSv1.3 中配置 0-RTT
        proxy_set_header 早期数据 \$ssl_early_data;
        }
}
    服务器 {
        听 80；
        听 [::]:80;
        server_name serveraddr.com;
        返回 301 https://use.shadowsocksr.win\$request_uri;
    }
EOF

    modify_nginx_port
    modify_nginx_other
    判断“Nginx配置修改”

}

start_process_systemd() {
    systemctl 守护进程重载
    chown -R root.root /var/log/v2ray/
    如果 [[ "$shell_mode" != "h2" ]]; 然后
        systemctl 重启 nginx
        判断“Nginx 启动”
    菲
    systemctl 重启 v2ray
    判断“V2ray 启动”
}

enable_process_systemd() {
    systemctl 启用 v2ray
    判断“设置v2ray引导自启”
    如果 [[ "$shell_mode" != "h2" ]]; 然后
        systemctl 启用 nginx
        判断“设置Nginx引导自启”
    菲

}

stop_process_systemd() {
    如果 [[ "$shell_mode" != "h2" ]]; 然后
        systemctl 停止 nginx
    菲
    systemctl 停止 v2ray
}
nginx_process_disabled() {
    [ -f $nginx_systemd_file ] && systemctl stop nginx && systemctl disable nginx
}

#debian 9 10 手机系
#rc_local_initialization(){
# if [[ -f /etc/rc.local ]];那么
# chmod +x /etc/rc.local
＃ 别的
# touch /etc/rc.local && chmod +x /etc/rc.local
# echo "#!/bin/bash" >> /etc/rc.local
# systemctl 启动 rc-local
#fi
#
# 判断“rc.local配置”
#}

acme_cron_update() {
    wget -N -P /usr/bin --no-check-certificate "https://raw.githubusercontent.com/wulabing/V2Ray_ws-tls_bash_onekey/dev/ssl_update.sh"
    如果 [[ $(crontab -l | grep -c "ssl_update.sh") -lt 1 ]]; 然后
      如果 [[ "${ID}" == "centos" ]]; 然后
          # sed -i "/acme.sh/c 0 3 * * 0 \"/root/.acme.sh\"/acme.sh --cron --home \"/root/.acme.sh\" \
          # &> /dev/null" /var/spool/cron/root
          sed -i "/acme.sh/c 0 3 * * 0 bash ${ssl_update_file}" /var/spool/cron/root
      别的
          # sed -i "/acme.sh/c 0 3 * * 0 \"/root/.acme.sh\"/acme.sh --cron --home \"/root/.acme.sh\" \
          # &> /dev/null" /var/spool/cron/crontabs/root
          sed -i "/acme.sh/c 0 3 * * 0 bash ${ssl_update_file}" /var/spool/cron/crontabs/root
      菲
    菲
    判断“cron 计划任务更新”
}

vmess_qr_config_tls_ws() {
    猫 >$v2ray_qr_config_file <<-EOF
{
  “v”：“2”，
  "ps": "wulabing_${domain}",
  "add": "${domain}",
  "端口": "${端口}",
  "id": "${UUID}",
  “援助”：“${alterID}”，
  “净”：“ws”，
  “类型”：“无”，
  "host": "${domain}",
  "路径": "${迷彩}",
  “tls”：“tls”
}
EOF
}

vmess_qr_config_h2() {
    猫 >$v2ray_qr_config_file <<-EOF
{
  “v”：“2”，
  "ps": "wulabing_${domain}",
  "add": "${domain}",
  "端口": "${端口}",
  "id": "${UUID}",
  “援助”：“${alterID}”，
  “净”：“h2”，
  “类型”：“无”，
  "路径": "${迷彩}",
  “tls”：“tls”
}
EOF
}

vmess_qr_link_image() {
    vmess_link="vmess://$(base64 -w 0 $v2ray_qr_config_file)"
    {
        echo -e "$红色二维码：$Font"
        echo -n "${vmess_link}" | qrencode -o - -t utf8
        echo -e "${Red} URL 导入链接:${vmess_link} ${Font}"
    } >>"${v2ray_info_file}"
}

vmess_quan_link_image() {
    echo "$(info_extraction '\"ps\"') = vmess, $(info_extraction '\"add\"'), \
    $(info_extraction '\"port\"'), chacha20-ietf-poly1305, "\"$(info_extraction '\"id\"')\"", over-tls=true, \
    证书=1, obfs=ws, obfs-path="\"$(info_extraction '\"path\"')\"", " > /tmp/vmess_quan.tmp
    vmess_link="vmess://$(base64 -w 0 /tmp/vmess_quan.tmp)"
    {
        echo -e "$红色二维码：$Font"
        echo -n "${vmess_link}" | qrencode -o - -t utf8
        echo -e "${Red} URL 导入链接:${vmess_link} ${Font}"
    } >>"${v2ray_info_file}"
}

vmess_link_image_choice() {
        echo "请生成选择的链接类型"
        回声“1：V2RayNG/V2RayN”
        回声“2：量子”
        read -rp "请输入：" link_version
        [[ -z ${link_version} ]] && 链接版本=1
        如果 [[ $link_version == 1 ]]; 然后
            vmess_qr_link_image
        elif [[ $link_version == 2 ]]; 然后
            vmess_quan_link_image
        别的
            vmess_qr_link_image
        菲
}

信息提取（）{
    grep "$1" $v2ray_qr_config_file | awk -F '"' '{打印 $4}'
}

基本信息（） {
    {
        echo -e "${OK} ${GreenBG} V2ray+ws+tls 安装成功"
        echo -e "${Red} V2ray 配置信息 ${Font}"
        echo -e "${Red} 地址（地址）:${Font} $(info_extraction '\"add\"') "
        echo -e "${Red} 端口（端口）：${Font} $(info_extraction '\"port\"') "
        echo -e "${Red} 用户id（UUID）：${Font} $(info_extraction '\"id\"')"
        echo -e "${Red} 额外id（alterId）：${Font} $(info_extraction '\"aid\"')"
        echo -e "${Red} 加密方式（security）${Font} 加密方式："
        echo -e "${Red} 传输协议（网络）：${Font} $(info_extraction '\"net\"') "
        echo -e "${Red} 伪装类型（type）：${Font} none "
        echo -e "${Red} 路径（不要落下/）：${Font} $(info_extraction '\"path\"') "
        echo -e "${Red} 安全传输：${Font} tls "
    } >"${v2ray_info_file}"
}

显示信息（）{
    猫“${v2ray_info_file}”
}

ssl_judge_and_install() {
    如果 [[ -f "/data/v2ray.key" || -f "/data/v2ray.crt" ]]; 然后
        echo "/data目录下证书文件已存在"
        echo -e "${OK} ${GreenBG} 是否删除 [Y/N]? ${Font}"
        读取 -r ssl_delete
        案例 $ssl_delete in
        [yY][eE][sS] | [年年])
            rm -rf /数据/*
            echo -e "${OK} ${GreenBG} 已删除 ${Font}"
            ;;
        *) ;;

        经社理事会
    菲

    如果 [[ -f "/data/v2ray.key" || -f "/data/v2ray.crt" ]]; 然后
        echo "证书文件已存在"
    elif [[ -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}. cer" ]]; 然后
        echo "证书文件已存在"
        "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /data/v2ray.crt --keypath /data/v2ray.key --ecc
        判断“证书申请”
    别的
        ssl_install
        极致
    菲
}

nginx_systemd() {
    猫 >$nginx_systemd_file <<EOF
[单元]
描述=NGINX HTTP 和反向代理服务器
After=syslog.target network.target remote-fs.target nss-lookup.target

[服务]
类型=分叉
PIDFile=/etc/nginx/logs/nginx.pid
ExecStartPre=/etc/nginx/sbin/nginx -t
ExecStart=/etc/nginx/sbin/nginx -c ${nginx_dir}/conf/nginx.conf
ExecReload=/etc/nginx/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT \$MAINPID
PrivateTmp=true

[安装]
WantedBy=多用户.target
EOF

    判断“Nginx systemd ServerFile添加”
    systemctl 守护进程重载
}

tls_type() {
    if [[ -f "/etc/nginx/sbin/nginx" ]] && [[ -f "$nginx_conf" ]] && [[ "$shell_mode" == "ws" ]]; 然后
        echo "请支持选择的 TLS 版本（默认：3）："
        echo "请注意，如果使用你的 Quantaumlt X /路由器 /Shadowrocket /旧版本 4.18 版本的 V2ray core 请选择你的路由器版本"
        echo "1: TLS1.1 TLS1.2.TLS1.3（旅游模式）"
        echo "2: TLS1.2 和 TLS1.3（模式）"
        回声“3：仅限 TLS1.3”
        read -rp "请输入：" tls_version
        [[ -z ${tls_version} ]] && tls_version=3
        如果 [[ $tls_version == 3 ]]; 然后
            sed -i 's/ssl_protocols.*/ssl_protocols TLSv1.3;/' $nginx_conf
            echo -e "${OK} ${GreenBG} 已切换至 TLS1.3 only ${Font}"
        elif [[ $tls_version == 1 ]]; 然后
            sed -i 's/ssl_protocols.*/ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;/' $nginx_conf
            echo -e "${OK} ${GreenBG} 已切换至 TLS1.1 TLS1.2 和 TLS1.3 ${Font}"
        别的
            sed -i 's/ssl_protocols.*/ssl_protocols TLSv1.2 TLSv1.3;/' $nginx_conf
            echo -e "${OK} ${GreenBG} 已切换至 TLS1.2 和 TLS1.3 ${Font}"
        菲
        systemctl 重启 nginx
        判断“Nginx重启”
    别的
        echo -e "${Error} ${RedBG} Nginx 或配置文件不存在 或当前安装版本为 h2 ，请安装脚本后执行${Font}"
    菲
}

show_access_log() {
    [ -f ${v2ray_access_log} ] && 尾 -f ${v2ray_access_log} || echo -e "${RedBG}日志文件不存在${Font}"
}

显示错误日志（）{
    [ -f ${v2ray_error_log} ] && 尾 -f ${v2ray_error_log} || echo -e "${RedBG}日志文件不存在${Font}"
}

ssl_update_manuel() {
    [ -f ${amce_sh_file} ] && "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" || echo -e "${RedBG}证书签章工具不存在，请确认你是否使用了自己的证书${Font}"
    domain="$(info_extraction '\"添加\"')"
    "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /data/v2ray.crt --keypath /data/v2ray.key --ecc
}

bbr_boost_sh() {
    [ -f "tcp.sh" ] && rm -rf ./tcp.sh
    wget -N --no-check-certificate "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh" && chmod +x tcp.sh && bash tcp.sh
}

mtproxy_sh() {
    echo -e "${Error} ${RedBG} 功能维护，暂不可用 ${Font}"
}

卸载全部（）{
    stop_process_systemd
    [[ -f $v2ray_systemd_file ]] && rm -f $v2ray_systemd_file
    [[ -f $v2ray_bin_dir ]] && rm -f $v2ray_bin_dir
    [[ -f $v2ctl_bin_dir ]] && rm -f $v2ctl_bin_dir
    [[ -d $v2ray_bin_dir_old ]] && rm -rf $v2ray_bin_dir_old
    如果 [[ -d $nginx_dir ]]; 然后
        echo -e "${OK} ${Green} 是否卸载 Nginx [Y/N]? ${Font}"
        读取 -r uninstall_nginx
        案例 $uninstall_nginx 在
        [yY][eE][sS] | [年年])
            rm -rf $nginx_dir
            rm -rf $nginx_systemd_file
            echo -e "${OK} ${Green} 已卸载 Nginx ${Font}"
            ;;
        *) ;;

        经社理事会
    菲
    [[ -d $v2ray_conf_dir ]] && rm -rf $v2ray_conf_dir
    [[ -d $web_dir ]] && rm -rf $web_dir
    echo -e "${OK} ${Green} 是否卸载acme.sh及证书 [Y/N]?${Font}"
    读取 -r uninstall_acme
    案例 $uninstall_acme 在
    [yY][eE][sS] | [年年])
      /root/.acme.sh/acme.sh --uninstall
      rm -rf /root/.acme.sh
      rm -rf /数据/*
      ;;
    *) ;;
    经社理事会
    systemctl 守护进程重载
    echo -e "${OK} ${GreenBG} 已卸载 ${Font}"
}
delete_tls_key_and_crt() {
    [[ -f $HOME/.acme.sh/acme.sh ]] && /root/.acme.sh/acme.sh 卸载 >/dev/null 2>&1
    [[ -d $HOME/.acme.sh ]] && rm -rf "$HOME/.acme.sh"
    echo -e "${OK} ${GreenBG} 已清空遗书文件 ${Font}"
}
判断模式（）{
    如果 [ -f $v2ray_bin_dir ] || [ -f $v2ray_bin_dir_old/v2ray ]; 然后
        如果 grep -q "ws" $v2ray_qr_config_file; 然后
            shell_mode="ws"
        elif grep -q "h2" $v2ray_qr_config_file; 然后
            shell_mode="h2"
        菲
    菲
}
install_v2ray_ws_tls() {
    is_root
    检查系统
    chrony_install
    依赖安装
    基本优化
    域检查
    old_config_exist_check
    port_alterid_set
    v2ray_install
    端口存在检查 80
    port_exist_check "${port}"
    nginx_exist_check
    v2ray_conf_add_tls
    nginx_conf_add
    web_camouflage
    ssl_judge_and_install
    nginx_systemd
    vmess_qr_config_tls_ws
    基本信息
    vmess_link_image_choice
    tls_type
    显示信息
    start_process_systemd
    enable_process_systemd
    acme_cron_update
}
install_v2_h2() {
    is_root
    检查系统
    chrony_install
    依赖安装
    基本优化
    域检查
    old_config_exist_check
    port_alterid_set
    v2ray_install
    端口存在检查 80
    port_exist_check "${port}"
    v2ray_conf_add_h2
    ssl_judge_and_install
    vmess_qr_config_h2
    基本信息
    vmess_qr_link_image
    显示信息
    start_process_systemd
    enable_process_systemd

}
update_sh() {
    ol_version=$(curl -L -s https://raw.githubusercontent.com/wulabing/V2Ray_ws-tls_bash_onekey/${github_branch}/install.sh | grep "shell_version=" | head -1 | awk -F '=| "''{打印 $3}')
    回声“$ol_version”>$version_cmp
    回声“$shell_version”>>$version_cmp
    if [[ "$shell_version" < "$(sort -rV $version_cmp | head -1)" ]]; 然后
        echo -e "${OK} ${GreenBG} 存在新版本，是否更新 [Y/N]?${Font}"
        读取 -r update_confirm
        案例 $update_confirm 在
        [yY][eE][sS] | [年年])
            wget -N --no-check-certificate https://raw.githubusercontent.com/wulabing/V2Ray_ws-tls_bash_onekey/${github_branch}/install.sh
            echo -e "${OK} ${GreenBG} 更新完成 ${Font}"
            出口 0
            ;;
        *) ;;

        经社理事会
    别的
        echo -e "${OK} ${GreenBG} 当前版本为最新版本 ${Font}"
    菲

}
维持（） {
    echo -e "${RedBG} 这种暂时无法使用${Fon}"
    echo -e "${RedBG}$1${字体}"
    出口 0
}
列表（） {
    案例 1 美元
    tls_modify)
        tls_type
        ;;
    卸载）
        卸载全部
        ;;
    crontab_modify)
        acme_cron_update
        ;;
    促进）
        bbr_boost_sh
        ;;
    *)
        菜单
        ;;
    经社理事会
}
modify_camouflage_path() {
    [[ -z ${camouflage_path} ]] && camouflage_path=1
    sed -i "/location/c \\\tlocation \/${camouflage_path}\/" ${nginx_conf} #修改nginx配置文件的伪装路径
    sed -i "/\"path\"/c \\\t \"path\":\"\/${camouflage_path}\/\"" ${v2ray_conf} #修改v2ray配置文件的伪装路径
    判断“V2ray伪装路径修改”
}

菜单（） {
    update_sh
    echo -e "\t V2ray 安装管理脚本 ${Red}[${shell_version}]${Font}"
    echo -e "\t---作者 wulabing---"
    echo -e "\thttps://github.com/wulabing\n"
    echo -e "当前已安装版本:${shell_mode}\n"

    echo -e "———————————— 安装程序——————————————————"""
    echo -e "${Green}0.${Font} 升级脚本"
    echo -e "${Green}1.${Font} 安装 V2Ray (Nginx+ws+tls)"
    echo -e "${Green}2.${Font} 安装 V2Ray (http/2)"
    echo -e "${Green}3.${Font} 升级 V2Ray 内核"
    echo -e "—————————————— 配置变更 ———————————————"
    echo -e "${Green}4.${Font} 变更 UUID"
    echo -e "${Green}6.${Font} 变更端口"
    echo -e "${Green}7.${Font} 变更 TLS 版本(仅ws+tls有效)"
    echo -e "${Green}18.${Font} 伪装路径"
    echo -e "—————————————— 查看信息 ———————————————"
    echo -e "${Green}8.${Font} 查看实时访问日志"
    echo -e "${Green}9.${Font} 查看实时错误日志"
    echo -e "${Green}10.${Font} 查看V2Ray配置信息"
    echo -e "—————————————— 其他选项 ———————————————"
    echo -e "${Green}11.${Font} 安装 4合1 bbr 锐速安装脚本"
    echo -e "$Green}12.MTproxy(支持TLS重新连接${Font}"
    echo -e "${Green}13.${Font} 证书有效更新"
    echo -e "${Green}14.${Font} 卸载 V2Ray"
    echo -e "${Green}15.${Font} 更新证书crontab计划任务"
    echo -e "${Green}16.${Font} 清空遗书文件"
    echo -e "${Green}17.${Font} 退出\n"

    read -rp "请输入数字：" menu_num
    案例 $menu_num 在
    0)
        update_sh
        ;;
    1)
        shell_mode="ws"
        install_v2ray_ws_tls
        ;;
    2)
        shell_mode="h2"
        install_v2_h2
        ;;
    3)
        bash <(curl -L -s https://raw.githubusercontent.com/wulabing/V2Ray_ws-tls_bash_onekey/${github_branch}/v2ray.sh)
        ;;
    4)
        read -rp "请输入UUID:" UUID
        修改_UUID
        start_process_systemd
        ;;
    6)
        read -rp "请输入连接端口：" 端口
        如果 grep -q "ws" $v2ray_qr_config_file; 然后
            modify_nginx_port
        elif grep -q "h2" $v2ray_qr_config_file; 然后
            modify_inbound_port
        菲
        start_process_systemd
        ;;
    7)
        tls_type
        ;;
    8)
        show_access_log
        ;;
    9)
        显示错误日志
        ;;
    10)
        基本信息
        如果 [[ $shell_mode == "ws" ]]; 然后
            vmess_link_image_choice
        别的
            vmess_qr_link_image
        菲
        显示信息
        ;;
    11)
        bbr_boost_sh
        ;;
    12)
        mtproxy_sh
        ;;
    13)
        stop_process_systemd
        ssl_update_manuel
        start_process_systemd
        ;;
    14)
        源'/etc/os-release'
        卸载全部
        ;;
    15)
        acme_cron_update
        ;;
    16)
        delete_tls_key_and_crt
        ;;
    17)
        出口 0
        ;;
    18)
        read -rp "请输入伪装路径(注意！不要加斜杠 eg:ray):" camouflage_path
        modify_camouflage_path
        start_process_systemd
        ;;
    *)
        echo -e "${RedBG}请输入正确的数字${Font}"
        ;;
    经社理事会
}

判断模式
列出“$1”
