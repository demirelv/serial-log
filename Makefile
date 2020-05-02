
dir-y := src

install-y := config/serial-log.conf.example:etc/serial-log/serial-log.conf
install-y += script/serial-log.sh:etc/init.d/

include Build.mk
