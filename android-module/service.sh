#!/system/bin/sh
# cns-rs 开机服务调度脚本
MODDIR="${0%/*}"
# 默认值：即使 config.ini 缺失也能安全运行
autoStart='0'

# 等待系统引导就绪
while [ "$(getprop sys.boot_completed)" != "1" ]; do
    sleep 2
done
sleep 5

# 读取配置
if [ -f "$MODDIR/config.ini" ]; then
    . "$MODDIR/config.ini"
fi

# 判断是否启用开机自启
if [ "$autoStart" = "1" ]; then
    "$MODDIR/Core/cns_rules.sh" start >/dev/null 2>&1
fi
