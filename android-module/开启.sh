#!/system/bin/sh
# cns-rs 一键开启脚本 (启动透明代理并执行全协议连通性健康检测)
DIR="${0%/*}"
cd "$DIR" || exit 1

if [ "$(id -u)" = "0" ]; then
    "$DIR/Core/cns_rules.sh" start
else
    su -c "\"$DIR/Core/cns_rules.sh\" start"
fi
