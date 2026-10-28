#!/system/bin/sh
# cns-rs 一键关闭脚本
DIR="${0%/*}"
cd "$DIR" || exit 1

if [ "$(id -u)" = "0" ]; then
    "$DIR/Core/cns_rules.sh" stop
else
    su -c "\"$DIR/Core/cns_rules.sh\" stop"
fi
