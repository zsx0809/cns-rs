#!/system/bin/sh
# cns-rs 一键检测脚本 (查看运行状态并执行全协议连通性检测)
DIR="${0%/*}"
cd "$DIR" || exit 1

if [ "$(id -u)" = "0" ]; then
    "$DIR/Core/cns_rules.sh" status
    echo ""
    "$DIR/Core/cns_rules.sh" test
else
    su -c "\"$DIR/Core/cns_rules.sh\" status; echo ''; \"$DIR/Core/cns_rules.sh\" test"
fi
