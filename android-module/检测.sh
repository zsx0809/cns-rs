#!/system/bin/sh
# cns-rs 一键检测脚本 (查看运行状态并执行 DNS、HTTP、HTTPS、UDP 连通性测试)

su -c "\"${0%/*}/Core/cns_rules.sh\" status; echo ''; \"${0%/*}/Core/cns_rules.sh\" test"
