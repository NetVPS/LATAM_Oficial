#!/bin/bash
##-->>AVISO DE LOGIN ROOT
notify() {

        KEY=$(cat /etc/SCRIPT-LATAM/temp/keyapk)
        if [ "$(whoami)" = "root" ]; then
                IP=$(echo $SSH_CONNECTION | awk '{print $1}')
                LOCATION=$(curl -s "http://api.ipapi.com/$IP?access_key=751c2a246e5cbeb5d89d5a6663b64ff7&format=2" | jq -r '.country_name')
                LOCATION2=${LOCATION// /+}
                curl -s "http://xdroid.net/api/message?k=$KEY&t=%F0%9F%93%A3+Login+ROOT+Detectado+%E2%9D%95&c=%F0%9F%96%A5%EF%B8%8F+VPS%3A+KALIX1%0A%F0%9F%8C%90+IP%3A+$IP%0A%F0%9F%97%BA%EF%B8%8F+GEO%3A+$LOCATION2%0A%E2%9A%A0%EF%B8%8FHacer+caso+omiso+a+este+mensaje+encaso+de+que+usted+inicio+su+VPS%2C+si+no+cambie+su+pass+lo+antes+posible%E2%9A%A0%EF%B8%8F%0A%F0%9F%98%8E+By+SCRIPT+LATAM+%E2%9C%8C%EF%B8%8F"
        fi
}
notify
