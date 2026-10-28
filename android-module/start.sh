#!/system/bin/sh
# 与 开启.sh 等价（ASCII 文件名别名：部分终端/su 传参对中文名编码不稳）
DIR="${0%/*}"
exec "$DIR/开启.sh" "$@"
