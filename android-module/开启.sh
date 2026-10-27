#!/system/bin/sh
# cns-rs 一键开启脚本 (自动启动 Micro-TUN 并执行全链路连通性检测)

su -c "\"${0%/*}/Core/cns_rules.sh\" start"
