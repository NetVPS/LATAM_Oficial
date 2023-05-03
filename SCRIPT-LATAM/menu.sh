#!/bin/bash
#29-03-23-648
echo "$$" >/etc/SCRIPT-LATAM/temp/menuid
clear && clear
echo -e "\a\a\a"
check-update
if [ $(whoami) != 'root' ]; then #-- VERIFICAR ROOT
  echo -e "\033[1;31m -- NECESITAS SER USER ROOT PARA EJECUTAR EL SCRIPT --\n\n\033[97m                DIGITE: \033[1;32m sudo su; menu\n"
  sleep 5s
  exit && exit
fi
rebootnb "totallssh" & ##-->> CONTADOR DE SSH
##-->> COLORES
red=$(tput setaf 1)
gren=$(tput setaf 2)
yellow=$(tput setaf 3)
SCPdir="/etc/SCRIPT-LATAM" && [[ ! -d ${SCPdir} ]] && exit 1
SCTemp="/etc/SCRIPT-LATAM/temp" && [[ ! -d ${SCTemp} ]] && exit 1
SCPfrm="${SCPdir}/botmanager"
if [[ -e /etc/bash.bashrc-bakup ]]; then # -- CHECK AUTORUN
  AutoRun="\033[1;93m[\033[1;32m ON \033[1;93m]"
elif [[ -e /etc/bash.bashrc ]]; then
  AutoRun="\033[1;93m[\033[1;31m OFF \033[1;93m]"
fi
msg() { ##-->> COLORES, TITULO, BARRAS
  ##-->> ACTULIZADOR Y VERCION
  [[ ! -e /etc/SCRIPT-LATAM/temp/version_instalacion ]] && printf '1\n' >/etc/SCRIPT-LATAM/temp/version_instalacion
  v11=$(cat /etc/SCRIPT-LATAM/temp/version_actual)
  v22=$(cat /etc/SCRIPT-LATAM/temp/version_instalacion)
  if [[ $v11 = $v22 ]]; then
    vesaoSCT="\e[1;31m[\033[1;37m Ver.\033[1;32m $v22 \033[1;31m]"
  else
    vesaoSCT="\e[1;31m[\e[31m ACTUALIZAR \e[25m\033[1;31m]"
  fi
  ##-->> COLORES
  local colors="/etc/SCRIPT-LATAM/colors"
  if [[ ! -e $colors ]]; then
    COLOR[0]='\033[1;37m' #GRIS='\033[1;37m'
    COLOR[1]='\e[31m'     #ROJO='\e[31m'
    COLOR[2]='\e[32m'     #VERDE='\e[32m'
    COLOR[3]='\e[33m'     #AMARILLO='\e[33m'
    COLOR[4]='\e[34m'     #AZUL='\e[34m'
    COLOR[5]='\e[91m'     #ROJO-NEON='\e[91m'
    COLOR[6]='\033[1;97m' #BALNCO='\033[1;97m'

  else
    local COL=0
    for number in $(cat $colors); do
      case $number in
      1) COLOR[$COL]='\033[1;37m' ;;
      2) COLOR[$COL]='\e[31m' ;;
      3) COLOR[$COL]='\e[32m' ;;
      4) COLOR[$COL]='\e[33m' ;;
      5) COLOR[$COL]='\e[34m' ;;
      6) COLOR[$COL]='\e[35m' ;;
      7) COLOR[$COL]='\033[1;36m' ;;
      esac
      let COL++
    done
  fi
  NEGRITO='\e[1m'
  SINCOLOR='\e[0m'
  case $1 in
  -ne) cor="${COLOR[1]}${NEGRITO}" && echo -ne "${cor}${2}${SINCOLOR}" ;;
  -ama) cor="${COLOR[3]}${NEGRITO}" && echo -e "${cor}${2}${SINCOLOR}" ;;
  -verm) cor="${COLOR[3]}${NEGRITO}[!] ${COLOR[1]}" && echo -e "${cor}${2}${SINCOLOR}" ;;
  -verm2) cor="${COLOR[1]}${NEGRITO}" && echo -e "${cor}${2}${SINCOLOR}" ;;
  -azu) cor="${COLOR[6]}${NEGRITO}" && echo -e "${cor}${2}${SINCOLOR}" ;;
  -verd) cor="${COLOR[2]}${NEGRITO}" && echo -e "${cor}${2}${SINCOLOR}" ;;
  -bra) cor="${COLOR[0]}${SINCOLOR}" && echo -e "${cor}${2}${SINCOLOR}" ;;
  "-bar2" | "-bar") cor="${COLOR[1]}════════════════════════════════════════════════════" && echo -e "${SINCOLOR}${cor}${SINCOLOR}" ;;
  # Centrar texto
  -tit) echo -e " \e[48;5;214m\e[38;5;0m   💻 𝙎 𝘾 𝙍 𝙄 𝙋 𝙏 | 𝙇 𝘼 𝙏 𝘼 𝙈 💻   \e[0m  $vesaoSCT" ;;
  esac
}
#--- INFO DE SISTEMA
os_system() {
  system=$(echo $(cat -n /etc/issue | grep 1 | cut -d' ' -f6,7,8 | sed 's/1//' | sed 's/      //'))
  echo $system | awk '{print $1, $2}'
}
#--- FUNCION IP INSTALACION
meu_ip() {
  if [[ -e /tmp/IP ]]; then
    echo "$(cat /tmp/IP)"
  else
    MEU_IP=$(wget -qO- ifconfig.me)
    echo "$MEU_IP" >/tmp/IP
  fi
}
#--- FUNCION IP ACTUAL
fun_ip() {
  if [[ -e /etc/SCRIPT-LATAM/MEUIPvps ]]; then
    IP="$(cat /etc/SCRIPT-LATAM/MEUIPvps)"
  else
    MEU_IP=$(wget -qO- ifconfig.me)
    echo "$MEU_IP" >/etc/SCRIPT-LATAM/MEUIPvps
  fi
}

#--- MENU DE SELECCION
selection_fun() {
  local selection
  local options="$(seq 0 $1 | paste -sd "," -)"
  read -p $'\033[1;97m  └⊳ Seleccione una opción:\033[1;32m ' selection
  if [[ $options =~ (^|[^\d])$selection($|[^\d]) ]]; then
    echo $selection
  else
    echo "Selección no válida: $selection" >&2
    exit 1
  fi
}
export -f msg
export -f selection_fun
export -f meu_ip
export -f fun_ip
clear && clear
msg -bar && msg -tit
title=$(echo -e "\033[1;4;92m$(cat ${SCPdir}/message.txt)\033[0;37m")
printf "%*s\n" $((($(echo -e "$title" | wc -c) + 68) / 2)) "$title"
msg -bar
echo -e "    \033[1;37mIP: \033[93m$(meu_ip)     \033[1;37mS.O: \033[96m$(os_system)"
##-->> CONTADOR DE CUENTAS
if [[ $(find /etc/SCRIPT-LATAM/temp/ -name "sshtotal" -execdir test -f {} \; -print -quit) ]]; then
  SSH4=$(</etc/SCRIPT-LATAM/temp/sshtotal)
else
  SSH4="0"
fi
if [[ $(find /usr/local/ -name "shadowsocksr" -type d -execdir test -f {}/mujson_mgr.py \; -print -quit) ]]; then
  user_info=$(cd /usr/local/shadowsocksr && python mujson_mgr.py -l)
  user_total=$(echo "${user_info}" | wc -l)
else
  user_total="0"
fi
if [[ $(find /etc/SCRIPT-LATAM/ -name "RegV2ray" -execdir test -f {} \; -print -quit) ]]; then
  v2ray=$(wc -l </etc/SCRIPT-LATAM/RegV2ray)
else
  v2ray="0"
fi
on="\033[93m[\033[1;32m ON \033[93m]" && off="\033[93m[ \033[1;31mOFF \033[93m]"
[[ $(ps x | grep badvpn | grep -v grep | awk '{print $1}') ]] && badvpn=$on || badvpn=$off
VERY="$(ps aux | grep "/etc/SCRIPT-LATAM/menu.sh verificar" | grep -v grep)"
VERY2="$(ps aux | grep "/etc/SCRIPT-LATAM/menu.sh desbloqueo" | grep -v grep)"
VERY3="$(ps aux | grep "${SCPdir}/menu.sh monitorservi" | grep -v grep)"
VERY4="$(ps aux | grep "${SCPdir}/menu.sh autolim" | grep -v grep)"
[[ -e "/etc/SCRIPT-LATAM/temp/T-Lim" ]] && limseg="$(less /etc/SCRIPT-LATAM/temp/T-Lim)"
[[ -z ${VERY} ]] && verificar="\033[93m[ \033[1;31mOFF \033[93m]" || verificar="\033[93m[\033[1;32m ON \033[93m]"
[[ -z ${VERY2} ]] && desbloqueo="\033[93m[ \033[1;31mOFF \033[93m]" || desbloqueo="\033[93m[\033[1;32m ON \033[93m]"
[[ -z ${VERY3} ]] && monitorservi="\033[93m[ \033[1;31mOFF \033[93m]" || monitorservi="\033[93m[\033[1;32m ON \033[93m]"
[[ -z ${VERY4} ]] && autolim="\033[93m[ \033[1;31mOFF \033[93m]" || autolim="\033[93m[\033[1;32m ON \033[93m]"
echo -e "  \033[1;97mLIM.SSH:$verificar \033[1;97m DES.SSH:$desbloqueo\033[1;97m BADVPN:$badvpn"
echo -e "\033[1;97m  SSH REG:\033[93m[\033[1;92m $SSH4 \033[93m]\033[1;97m SS-SRR REG:\033[93m[\033[1;92m $user_total \033[93m]\033[1;97m V2RAY REG:\033[93m[\033[1;92m $v2ray \033[93m]\033[1;97m"

#ONLINES
[[ -e /etc/SCRIPT-LATAM/temp/USRonlines ]] && {
  msg -bar
  onssh=$(cat /etc/SCRIPT-LATAM/temp/USRonlines)
  echo -ne "\033[1;32m CONECTADOS:\033[1;36m[\e[97m $onssh \033[1;36m]"
}
#EXPIRADOS
[[ -e /etc/SCRIPT-LATAM/temp/USRexpired ]] && {
  expi=$(cat /etc/SCRIPT-LATAM/temp/USRexpired)
  echo -ne "\e[1;31m EXPIRADOS:\033[1;36m[\e[1;97m $expi \033[1;36m]"
}
#BLOQUEADOS
[[ -e /etc/SCRIPT-LATAM/temp/USRbloqueados ]] && {
  bloc=$(cat /etc/SCRIPT-LATAM/temp/USRbloqueados)
  echo -ne "\e[1;95m BLOQUEADOS:\033[1;36m[\e[1;97m $bloc \033[1;36m]\n"
  echo -ne "\033[1;97m        ACTULIZACION DE MONITOR CADA: \033[1;34m $limseg s\n"
}

#---FUNION CAMBIAR DE COLOR
canbio_color() {
  clear
  msg -bar2
  msg -tit
  msg -ama "     CONTROLADOR DE COLORES DEL SCRIPT LATAM"
  msg -bar2
  msg -ama "Selecione 7 cores "
  echo -e '\033[1;37m [1] ###\033[0m'
  echo -e '\e[31m [2] ###\033[0m'
  echo -e '\e[32m [3] ###\033[0m'
  echo -e '\e[33m [4] ###\033[0m'
  echo -e '\e[34m [5] ###\033[0m'
  echo -e '\e[35m [6] ###\033[0m'
  echo -e '\033[1;36m [7] ###\033[0m'
  msg -bar2
  for number in $(echo {1..7}); do
    msg -ne "Digite un Color [$number]: " && read corselect
    [[ $corselect != @([1-7]) ]] && corselect=1
    cores+="$corselect "
    corselect=0
  done
  echo "$cores" >/etc/SCRIPT-LATAM/colors
  msg -bar2
}
##-->> FUNCION PUERTOS ACTIVOS
mine_port() {
  clear && clear
  msg -bar
  msg -tit
  msg -bar
  echo -e "\033[1;93m           INFORMACION DE PUERTOS ACTIVOS"
  msg -bar2
  local portasVAR=$(lsof -V -i tcp -P -n | grep -v "ESTABLISHED" | grep -v "COMMAND" | grep "LISTEN")
  local NOREPEAT
  local reQ
  local Port
  while read port; do
    reQ=$(echo ${port} | awk '{print $1}')
    Port=$(echo {$port} | awk '{print $9}' | awk -F ":" '{print $2}')
    [[ $(echo -e $NOREPEAT | grep -w "$Port") ]] && continue
    NOREPEAT+="$Port\n"
    case ${reQ} in
    squid | squid3)
      [[ -z $SQD ]] && local SQD="\033[1;31m SQUID: \033[1;32m"
      SQD+="$Port "
      ;;
    apache | apache2)
      [[ -z $APC ]] && local APC="\033[1;31m APACHE: \033[1;32m"
      APC+="$Port "
      ;;
    ssh | sshd)
      [[ -z $SSH ]] && local SSH="\033[1;31m SSH: \033[1;32m"
      SSH+="$Port "
      ;;
    dropbear)
      [[ -z $DPB ]] && local DPB="\033[1;31m DROPBEAR: \033[1;32m"
      DPB+="$Port "
      ;;
    ssserver | ss-server)
      [[ -z $SSV ]] && local SSV="\033[1;31m SHADOWSOCKS: \033[1;32m"
      SSV+="$Port "
      ;;
    openvpn)
      [[ -z $OVPN ]] && local OVPN="\033[1;31m OPENVPN-TCP: \033[1;32m"
      OVPN+="$Port "
      ;;
    stunnel4 | stunnel)
      [[ -z $SSL ]] && local SSL="\033[1;31m SSL: \033[1;32m"
      SSL+="$Port "
      ;;
    sshl | sslh)
      [[ -z $SSLH ]] && local SSLH="\033[1;31m SSLH: \033[1;32m"
      SSLH+="$Port "
      ;;
    python | python3)
      [[ -z $PY3 ]] && local PY3="\033[1;31m PYTHON|WEBSOCKET|SSR: \033[1;32m"
      PY3+="$Port "
      ;;
    v2ray)
      [[ -z $V2R ]] && local V2R="\033[1;31m V2RAY: \033[1;32m"
      V2R+="$Port "
      ;;
    badvpn-ud)
      [[ -z $BAD ]] && local BAD="\033[1;31m BADVPN: \033[1;32m"
      BAD+="$Port "
      ;;
    psiphond)
      [[ -z $PSI ]] && local PSI="\033[1;31m PSIPHOND: \033[1;32m"
      PSI+="$Port "
      ;;
    esac
  done <<<"${portasVAR}"
  #UDP
  local portasVAR=$(lsof -V -i -P -n | grep -v "ESTABLISHED" | grep -v "COMMAND")
  local NOREPEAT
  local reQ
  local Port
  while read port; do
    reQ=$(echo ${port} | awk '{print $1}')
    Port=$(echo ${port} | awk '{print $9}' | awk -F ":" '{print $2}')
    [[ $(echo -e $NOREPEAT | grep -w "$Port") ]] && continue
    NOREPEAT+="$Port\n"
    case ${reQ} in
    openvpn)
      [[ -z $OVPN ]] && local OVPN="\033[0;36m OPENVPN-UDP: \033[1;32m"
      OVPN+="$Port "
      ;;
    udpServer)
      [[ -z $UDPSER ]] && local UDPSER="\033[0;36m UDP-SERVER \033[1;32m"
      UDPSER+="$Port "
      ;;
    esac
  done <<<"${portasVAR}"
  [[ ! -z $SSH ]] && echo -e $SSH
  [[ ! -z $SSL ]] && echo -e $SSL
  [[ ! -z $SSLH ]] && echo -e $SSLH
  [[ ! -z $DPB ]] && echo -e $DPB
  [[ ! -z $SQD ]] && echo -e $SQD
  [[ ! -z $PY3 ]] && echo -e $PY3
  [[ ! -z $SSV ]] && echo -e $SSV
  [[ ! -z $V2R ]] && echo -e $V2R
  [[ ! -z $APC ]] && echo -e $APC
  [[ ! -z $OVPN ]] && echo -e $OVPN
  [[ ! -z $BAD ]] && echo -e $BAD
  [[ ! -z $PSI ]] && echo -e $PSI
  port=$(cat /etc/systemd/system/UDPserver.service 2>/dev/null | grep 'exclude' 2>/dev/null)
  port2=$(echo $port | awk '{print $4}' | cut -d '=' -f2 2>/dev/null | sed 's/,/ /g' 2>/dev/null)
  [[ ! -z $UDPSER ]] && echo -e "$UDPSER<--> $port2 "
  msg -bar2
  read -t 120 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
}

#--- FUNCION AUTO INICIO
fun_autorun() {
  if [[ -e /etc/bash.bashrc-bakup ]]; then
    mv -f /etc/bash.bashrc-bakup /etc/bash.bashrc
    cat /etc/bash.bashrc | grep -v "/etc/SCRIPT-LATAM/menu.sh" >/tmp/bash
    mv -f /tmp/bash /etc/bash.bashrc
    echo -e "\e[1;31m           --  REMOVIDO CON EXITO --"
    msg -bar
  elif [[ -e /etc/bash.bashrc ]]; then
    cat /etc/bash.bashrc | grep -v /bin/menu >/etc/bash.bashrc.2
    echo 'rebootnb login >/dev/null 2>&1' >>/etc/bash.bashrc.2
    echo '/etc/SCRIPT-LATAM/menu.sh' >>/etc/bash.bashrc.2
    cp /etc/bash.bashrc /etc/bash.bashrc-bakup
    mv -f /etc/bash.bashrc.2 /etc/bash.bashrc
    echo -e "\e[1;32m          --  AUTO INICIO AGREGADO --"
    msg -bar
  fi
}

#--- FUNCION BARRAS DE INSTALACION
fun_bar() {
  comando="$1"
  _=$(
    $comando >/dev/null 2>&1
  ) &
  >/dev/null
  pid=$!
  while [[ -d /proc/$pid ]]; do
    echo -ne " \033[1;33m["
    for ((i = 0; i < 20; i++)); do
      echo -ne "\033[1;31m##"
      sleep 0.2
    done
    echo -ne "\033[1;33m]"
    sleep 1s
    echo
    tput cuu1
    tput dl1
  done
  echo -ne " \033[1;33m[\033[1;31m########################################\033[1;33m] - \033[1;32m100%\033[0m\n"
  sleep 1s
}

#--- FUNCION RX-TX
fun_eth() {
  eth=$(ifconfig | grep -v inet6 | grep -v lo | grep -v 127.0.0.1 | grep "encap:Ethernet" | awk '{print $1}')
  [[ $eth != "" ]] && {
    msg -bar
    msg -ama " Aplicar el sistema para mejorar los paquetes SSH?"
    msg -ama " Opciones para usuarios avanzados"
    msg -bar
    read -p " [S/N]: " -e -i n sshsn
    [[ "$sshsn" = @(s|S|y|Y) ]] && {
      echo -e "${cor[1]} Correccion de problemas de paquetes en SSH ..."
      echo -e " ¿Cual es la tasa RX?"
      echo -ne "[ 1 - 999999999 ]: "
      read rx
      [[ "$rx" = "" ]] && rx="999999999"
      echo -e " ¿Cual es la tasa TX?"
      echo -ne "[ 1 - 999999999 ]: "
      read tx
      [[ "$tx" = "" ]] && tx="999999999"
      apt-get install ethtool -y >/dev/null 2>&1
      ethtool -G $eth rx $rx tx $tx >/dev/null 2>&1
    }
    msg -bar
  }
}

#--- FUNCION REMOVER SCRIPT
remove_script() {
  clear && clear
  msg -bar
  msg -tit
  msg -bar
  msg -ama "          ¿ DESEA DESINSTALAR SCRIPT ?"
  msg -bar
  echo -e "\e[1;97m        Esto borrara todos los archivos LATAM"
  msg -bar
  while [[ ${yesno} != @(s|S|y|Y|n|N) ]]; do
    read -p " [ S / N ]: " yesno
    tput cuu1 && tput dl1
  done
  if [[ ${yesno} = @(s|S|y|Y) ]]; then
    rm -rf ${SCPdir} &>/dev/null
    [[ -e /bin/MENU ]] && rm /bin/MENU
    [[ -e /usr/bin/MENU ]] && rm /usr/bin/MENU
    [[ -e /bin/menu ]] && rm /bin/menu
    [[ -e /usr/bin/menu ]] && rm /usr/bin/menu
    sudo apt-get --purge remove squid -y >/dev/null 2>&1
    sudo apt-get --purge remove stunnel4 -y >/dev/null 2>&1
    sudo apt-get --purge remove dropbear -y >/dev/null 2>&1
    rm -rf /root/* >/dev/null 2>&1
    cd /root
    clear && clear
    exit
    exit
  fi

}

#--- FUNCION INFORMACION DE SISTEMA
systen_info() {
  clear && clear
  msg -bar
  msg -tit
  msg -bar
  msg -ama "                DETALLES DEL SISTEMA"
  null="\033[1;31m"
  msg -bar
  if [ ! /proc/cpuinfo ]; then
    msg -verm "Sistema No Soportado" && msg -bar
    return 1
  fi
  if [ ! /etc/issue.net ]; then
    msg -verm "Sistema No Soportado" && msg -bar
    return 1
  fi
  if [ ! /proc/meminfo ]; then
    msg -verm "Sistema No Soportado" && msg -bar
    return 1
  fi
  totalram=$(free | grep Mem | awk '{print $2}')
  usedram=$(free | grep Mem | awk '{print $3}')
  freeram=$(free | grep Mem | awk '{print $4}')
  swapram=$(cat /proc/meminfo | grep SwapTotal | awk '{print $2}')
  system=$(cat /etc/issue.net)
  clock=$(lscpu | grep "CPU MHz" | awk '{print $3}')
  based=$(cat /etc/*release | grep ID_LIKE | awk -F "=" '{print $2}')
  processor=$(cat /proc/cpuinfo | grep "model name" | uniq | awk -F ":" '{print $2}')
  cpus=$(cat /proc/cpuinfo | grep processor | wc -l)
  [[ "$system" ]] && msg -ama "Sistema Operativo: ${null}$system" || msg -ama "Sistema: ${null}???"
  [[ "$based" ]] && msg -ama "Base de SO: ${null}$based" || msg -ama "Base: ${null}???"
  [[ "$processor" ]] && msg -ama "Procesador: ${null}$processor x$cpus" || msg -ama "Procesador: ${null}???"
  [[ "$clock" ]] && msg -ama "Frecuencia de Operacion: ${null}$clock MHz" || msg -ama "Frecuencia de Operacion: ${null}???"
  msg -ama "Uso del Procesador: ${null}$(ps aux | awk 'BEGIN { sum = 0 }  { sum += sprintf("%f",$3) }; END { printf " " "%.2f" "%%", sum}')"
  msg -ama "Memoria Virtual Total: ${null}$(($totalram / 1024))"
  msg -ama "Memoria Virtual En Uso: ${null}$(($usedram / 1024))"
  msg -ama "Memoria Virtual Libre: ${null}$(($freeram / 1024))"
  msg -ama "Memoria Virtual Swap: ${null}$(($swapram / 1024))MB"
  msg -ama "Tiempo Online: ${null}$(uptime)"
  msg -ama "Nombre De La Maquina: ${null}$(hostname)"
  msg -ama "IP De La  Maquina: ${null}$(ip addr | grep inet | grep -v inet6 | grep -v "host lo" | awk '{print $2}' | awk -F "/" '{print $1}')"
  msg -ama "Version de Kernel: ${null}$(uname -r)"
  msg -ama "Arquitectura: ${null}$(uname -m)"
  msg -bar
  read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
  herramientas_fun
}

#SPEED TEST
speed_test() {
  clear && clear
  msg -bar
  msg -tit
  msg -bar
  mkdir -p /opt/speed/ >/dev/null 2>&1
  wget -O /opt/speed/speedtest https://raw.githubusercontent.com/NetVPS/LATAM_Oficial/main/Ejecutables/speedtest.py &>/dev/null
  chmod +rwx /opt/speed/speedtest
  declare -A cor=([0]="\033[1;37m" [1]="\033[1;34m" [2]="\033[1;31m" [3]="\033[1;33m" [4]="\033[1;32m")

  echo -e "\e[1;93m    PRUEBA DE VELOCIDAD DE HOSTING  [By LATAM]"
  msg -bar
  ping=$(ping -c1 google.com | awk '{print $8 $9}' | grep -v loss | cut -d = -f2 | sed ':a;N;s/\n//g;ta')
  starts_test=$(/opt/speed/speedtest)
  fun_bar "$starts_test"
  down_load=$(echo "$starts_test" | grep "Download" | awk '{print $2,$3}')
  up_load=$(echo "$starts_test" | grep "Upload" | awk '{print $2,$3}')
  msg -bar
  msg -ama " Latencia:\033[1;92m $ping"
  msg -ama " Subida:\033[1;92m $up_load"
  msg -ama " Descarga:\033[1;92m $down_load"
  msg -bar
  read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
  herramientas_fun
}

#---HORARIOS LOCALES
hora_local() {
  timemx() {
    rm -rf /etc/localtime
    ln -s /usr/share/zoneinfo/America/Merida /etc/localtime
    echo -e "\e[1;92m          >> FECHA LOCAL MX APLICADA! <<"
    echo -e "\e[93m           $(date)"
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    herramientas_fun
  }
  timearg() {
    rm -rf /etc/localtime
    ln -sf /usr/share/zoneinfo/America/Argentina/Buenos_Aires /etc/localtime
    echo -e "\e[1;92m          >> FECHA LOCAL ARG APLICADA! <<"
    echo -e "\e[93m           $(date)"
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    herramientas_fun
  }
  timeco() {
    rm -rf /etc/localtime
    ln -sf /usr/share/zoneinfo/America/Bogota /etc/localtime
    echo -e "\e[1;92m          >> FECHA LOCAL CO APLICADA! <<"
    echo -e "\e[93m           $(date)"
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    herramientas_fun
  }
  timeperu() {
    rm -rf /etc/localtime
    ln -sf /usr/share/zoneinfo/America/Lima /etc/localtime
    echo -e "\e[1;92m          >> FECHA LOCAL PE APLICADA! <<"
    echo -e "\e[93m           $(date)"
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    herramientas_fun
  }
  timegt() {

    rm -rf /etc/localtime
    ln -sf /usr/share/zoneinfo/America/Lima /etc/localtime
    echo -e "\e[1;92m          >> FECHA LOCAL GT APLICADA! <<"
    echo -e "\e[93m           $(date)"
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    herramientas_fun
  }
  clear && clear
  msg -bar
  msg -tit
  msg -bar
  echo -e "\e[1;93m           AJUSTES DE HORARIOS LOCALES  "
  msg -bar

  echo -e "\e[1;93m  [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;97mCAMBIAR HORA LOCAL MX"
  echo -e "\e[1;93m  [\e[1;32m2\e[1;93m]\033[1;31m > \e[1;97mCAMBIAR HORA LOCAL ARG"
  echo -e "\e[1;93m  [\e[1;32m3\e[1;93m]\033[1;31m > \e[1;97mCAMBIAR HORA LOCAL CO"
  echo -e "\e[1;93m  [\e[1;32m4\e[1;93m]\033[1;31m > \e[1;97mCAMBIAR HORA LOCAL PE"
  echo -e "\e[1;93m  [\e[1;32m5\e[1;93m]\033[1;31m > \e[1;97mCAMBIAR HORA LOCAL GT"
  msg -bar
  echo -e "    \e[97m\033[1;41m ENTER SIN RESPUESTA REGRESA A MENU ANTERIOR \033[0;97m"
  msg -bar
  echo -ne "    └⊳ Seleccione una Opcion: \033[1;32m" && read opx
  tput cuu1 && tput dl1

  case $opx in
  1)
    timemx
    ;;
  2)
    timearg
    ;;
  3)
    timeco
    ;;
  4)
    timeperu
    ;;
  5)
    timegt
    ;;
  *)
    herramientas_fun
    ;;
  esac

}

#---AJUSTES INTERNOS DE VPS
ajuste_in() {

  reiniciar_ser() { #REINICIO DE PROTOCOLOS BASICOS
    echo -ne " \033[1;31m[ ! ] Services stunnel4 restart"
    service stunnel4 restart >/dev/null 2>&1
    [[ -e /etc/init.d/stunnel4 ]] && /etc/init.d/stunnel4 restart >/dev/null 2>&1 && echo -e "\033[1;32m [OK]" || echo -e "\033[1;31m [FAIL]"
    echo -ne " \033[1;31m[ ! ] Services squid restart"
    service squid restart >/dev/null 2>&1 && echo -e "\033[1;32m [OK]" || echo -e "\033[1;31m [FAIL]"
    echo -ne " \033[1;31m[ ! ] Services squid3 restart"
    service squid3 restart >/dev/null 2>&1 && echo -e "\033[1;32m [OK]" || echo -e "\033[1;31m [FAIL]"
    echo -ne " \033[1;31m[ ! ] Services apache2 restart"
    service apache2 restart >/dev/null 2>&1
    [[ -e /etc/init.d/apache2 ]] && /etc/init.d/apache2 restart >/dev/null 2>&1 && echo -e "\033[1;32m [OK]" || echo -e "\033[1;31m [FAIL]"
    echo -ne " \033[1;31m[ ! ] Services openvpn restart"
    service openvpn restart >/dev/null 2>&1
    [[ -e /etc/init.d/openvpn ]] && /etc/init.d/openvpn restart >/dev/null 2>&1 && echo -e "\033[1;32m [OK]" || echo -e "\033[1;31m [FAIL]"
    echo -ne " \033[1;31m[ ! ] Services dropbear restart"
    service dropbear restart >/dev/null 2>&1
    [[ -e /etc/init.d/dropbear ]] && /etc/init.d/dropbear restart >/dev/null 2>&1 && echo -e "\033[1;32m [OK]" || echo -e "\033[1;31m [FAIL]"
    echo -ne " \033[1;31m[ ! ] Services ssh restart"
    service ssh restart >/dev/null 2>&1
    [[ -e /etc/init.d/ssh ]] && /etc/init.d/ssh restart >/dev/null 2>&1 && echo -e "\033[1;32m [OK]" || echo -e "\033[1;31m [FAIL]"
    echo -ne " \033[1;31m[ ! ] Services fail2ban restart"
    (
      [[ -e /etc/init.d/ssh ]] && /etc/init.d/ssh restart
      fail2ban-client -x stop && fail2ban-client -x start
    ) >/dev/null 2>&1 && echo -e "\033[1;32m [OK]" || echo -e "\033[1;31m [FAIL]"
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    herramientas_fun
  }
  host_name() { #CAMBIO DE HOSTNAME
    unset name
    while [[ ${name} = "" ]]; do
      echo -ne "\033[1;37m Digite Nuevo Hostname: " && read name
      tput cuu1 && tput dl1
    done
    hostnamectl set-hostname $name
    if [ $(hostnamectl status | head -1 | awk '{print $3}') = "${name}" ]; then
      echo -e "\033[1;33m     Host alterado corretamente!, reiniciar VPS"
    else
      echo -e "\033[1;33m                Host no modificado!"
    fi
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    herramientas_fun
  }
  editports() {
    port() {
      local portas
      local portas_var=$(lsof -V -i tcp -P -n | grep -v "ESTABLISHED" | grep -v "COMMAND" | grep "LISTEN")
      i=0
      while read port; do
        var1=$(echo $port | awk '{print $1}') && var2=$(echo $port | awk '{print $9}' | awk -F ":" '{print $2}')
        [[ "$(echo -e ${portas} | grep -w "$var1 $var2")" ]] || {
          portas+="$var1 $var2 $portas"
          echo "$var1 $var2"
          let i++
        }
      done <<<"$portas_var"
    }
    verify_port() {
      local SERVICE="$1"
      local PORTENTRY="$2"
      [[ ! $(echo -e $(port | grep -v ${SERVICE}) | grep -w "$PORTENTRY") ]] && return 0 || return 1
    }
    edit_squid() {
      tput cuu1 >&2 && tput dl1 >&2
      tput cuu1 >&2 && tput dl1 >&2
      tput cuu1 >&2 && tput dl1 >&2
      msg -bar2
      msg -ama "REDEFINIR PUERTOS SQUID"
      msg -bar2
      if [[ -e /etc/squid/squid.conf ]]; then
        local CONF="/etc/squid/squid.conf"
      elif [[ -e /etc/squid3/squid.conf ]]; then
        local CONF="/etc/squid3/squid.conf"
      fi
      NEWCONF="$(cat ${CONF} | grep -v "http_port")"
      msg -ne "Nuevos Puertos: "
      read -p "" newports
      for PTS in $(echo ${newports}); do
        verify_port squid "${PTS}" && echo -e "\033[1;33mPort $PTS \033[1;32mOK" || {
          echo -e "\033[1;33mPort $PTS \033[1;31mFAIL"
          return 1
        }
      done
      rm ${CONF}
      while read varline; do
        echo -e "${varline}" >>${CONF}
        if [[ "${varline}" = "#portas" ]]; then
          for NPT in $(echo ${newports}); do
            echo -e "http_port ${NPT}" >>${CONF}
          done
        fi
      done <<<"${NEWCONF}"
      msg -azu "AGUARDE"
      service squid restart &>/dev/null
      service squid3 restart &>/dev/null
      sleep 1s
      msg -bar2
      echo -e "\e[92m              PUERTOS REDEFINIDOS"
      msg -bar2
    }
    edit_apache() {
      tput cuu1 >&2 && tput dl1 >&2
      tput cuu1 >&2 && tput dl1 >&2
      tput cuu1 >&2 && tput dl1 >&2
      msg -bar2
      msg -azu "REDEFINIR PUERTOS APACHE"
      msg -bar2
      local CONF="/etc/apache2/ports.conf"
      local NEWCONF="$(cat ${CONF})"
      msg -ne "Nuevos Puertos: "
      read -p "" newports
      for PTS in $(echo ${newports}); do
        verify_port apache "${PTS}" && echo -e "\033[1;33mPort $PTS \033[1;32mOK" || {
          echo -e "\033[1;33mPort $PTS \033[1;31mFAIL"
          return 1
        }
      done
      rm ${CONF}
      while read varline; do
        if [[ $(echo ${varline} | grep -w "Listen") ]]; then
          if [[ -z ${END} ]]; then
            echo -e "Listen ${newports}" >>${CONF}
            END="True"
          else
            echo -e "${varline}" >>${CONF}
          fi
        else
          echo -e "${varline}" >>${CONF}
        fi
      done <<<"${NEWCONF}"
      msg -azu "AGUARDE"
      service apache2 restart &>/dev/null
      sleep 1s
      msg -bar2
      echo -e "\e[92m              PUERTOS REDEFINIDOS"
      msg -bar2
    }
    edit_openvpn() {
      tput cuu1 >&2 && tput dl1 >&2
      tput cuu1 >&2 && tput dl1 >&2
      tput cuu1 >&2 && tput dl1 >&2
      msg -bar2
      msg -azu "REDEFINIR PUERTOS OPENVPN"
      msg -bar2
      local CONF="/etc/openvpn/server.conf"
      local CONF2="/etc/openvpn/client-common.txt"
      local NEWCONF="$(cat ${CONF} | grep -v [Pp]ort)"
      local NEWCONF2="$(cat ${CONF2})"
      msg -ne "Nuevos puertos: "
      read -p "" newports
      for PTS in $(echo ${newports}); do
        verify_port openvpn "${PTS}" && echo -e "\033[1;33mPort $PTS \033[1;32mOK" || {
          echo -e "\033[1;33mPort $PTS \033[1;31mFAIL"
          return 1
        }
      done
      rm ${CONF}
      while read varline; do
        echo -e "${varline}" >>${CONF}
        if [[ ${varline} = "proto tcp" ]]; then
          echo -e "port ${newports}" >>${CONF}
        fi
      done <<<"${NEWCONF}"
      rm ${CONF2}
      while read varline; do
        if [[ $(echo ${varline} | grep -v "remote-random" | grep "remote") ]]; then
          echo -e "$(echo ${varline} | cut -d' ' -f1,2) ${newports} $(echo ${varline} | cut -d' ' -f4)" >>${CONF2}
        else
          echo -e "${varline}" >>${CONF2}
        fi
      done <<<"${NEWCONF2}"
      msg -azu "AGUARDE"
      service openvpn restart &>/dev/null
      /etc/init.d/openvpn restart &>/dev/null
      sleep 1s
      msg -bar2
      echo -e "\e[92m               PUERTOS REDEFINIDOS"
      msg -bar2
    }
    edit_dropbear() {
      tput cuu1 >&2 && tput dl1 >&2
      tput cuu1 >&2 && tput dl1 >&2
      tput cuu1 >&2 && tput dl1 >&2
      msg -bar2
      msg -azu "REDEFINIR PUERTOS DROPBEAR"
      msg -bar2
      local CONF="/etc/default/dropbear"
      local NEWCONF="$(cat ${CONF} | grep -v "DROPBEAR_EXTRA_ARGS")"
      msg -ne "Nuevos Puertos: "
      read -p "" newports
      for PTS in $(echo ${newports}); do
        verify_port dropbear "${PTS}" && echo -e "\033[1;33mPort $PTS \033[1;32mOK" || {
          echo -e "\033[1;33mPort $PTS \033[1;31mFAIL"
          return 1
        }
      done
      rm -rf ${CONF}
      while read varline; do
        echo -e "${varline}" >>${CONF}
        if [[ ${varline} = "NO_START=1" ]]; then
          echo -e 'DROPBEAR_EXTRA_ARGS="VAR"' >>${CONF}
          for NPT in $(echo ${newports}); do
            sed -i "s/VAR/-p ${NPT} VAR/g" ${CONF}
          done
          sed -i "s/VAR//g" ${CONF}
        fi
      done <<<"${NEWCONF}"
      msg -azu "AGUARDE"
      SOPORTE rd &>/dev/null
      sleep 1s
      msg -bar2
      echo -e "\e[92m              PUERTOS REDEFINIDOS"
      msg -bar2
    }
    edit_openssh() {
      msg -azu "REDEFINIR PUERTOS OPENSSH"
      msg -bar2
      local CONF="/etc/ssh/sshd_config"
      local NEWCONF="$(cat ${CONF} | grep -v [Pp]ort)"
      msg -ne "Nuevos Puertos: "
      read -p "" newports
      for PTS in $(echo ${newports}); do
        verify_port sshd "${PTS}" && echo -e "\033[1;33mPort $PTS \033[1;32mOK" || {
          echo -e "\033[1;33mPort $PTS \033[1;31mFAIL"
          return 1
        }
      done
      rm ${CONF}
      for NPT in $(echo ${newports}); do
        echo -e "Port ${NPT}" >>${CONF}
      done
      while read varline; do
        echo -e "${varline}" >>${CONF}
      done <<<"${NEWCONF}"
      msg -azu "AGUARDE"
      service ssh restart &>/dev/null
      service sshd restart &>/dev/null
      sleep 1s
      msg -bar2
      echo -e "\e[92m              PUERTOS REDEFINIDOS"
      msg -bar2
    }

    main_fun() {
      clear && clear
      msg -bar2
      msg -tit ""
      msg -bar2
      msg -ama "                EDITAR PUERTOS ACTIVOS "
      msg -bar2
      unset newports
      i=0
      while read line; do
        let i++
        case $line in
        squid | squid3) squid=$i ;;
        apache | apache2) apache=$i ;;
        openvpn) openvpn=$i ;;
        dropbear) dropbear=$i ;;
        sshd) ssh=$i ;;
        esac
      done <<<"$(port | cut -d' ' -f1 | sort -u)"
      for ((a = 1; a <= $i; a++)); do
        [[ $squid = $a ]] && echo -ne "\033[1;32m [$squid] > " && msg -azu "REDEFINIR PUERTOS SQUID"
        [[ $apache = $a ]] && echo -ne "\033[1;32m [$apache] > " && msg -azu "REDEFINIR PUERTOS APACHE"
        [[ $openvpn = $a ]] && echo -ne "\033[1;32m [$openvpn] > " && msg -azu "REDEFINIR PUERTOS OPENVPN"
        [[ $dropbear = $a ]] && echo -ne "\033[1;32m [$dropbear] > " && msg -azu "REDEFINIR PUERTOS DROPBEAR"
        [[ $ssh = $a ]] && echo -ne "\033[1;32m [$ssh] > " && msg -azu "REDEFINIR PUERTOS SSH"
      done
      echo -ne "$(msg -bar2)\n\033[1;32m [0] > " && msg -azu "\e[97m\033[1;41m VOLVER \033[1;37m"
      msg -bar2
      while true; do
        echo -ne "\033[1;37mSeleccione: " && read selection
        tput cuu1 && tput dl1
        [[ ! -z $squid ]] && [[ $squid = $selection ]] && edit_squid && break
        [[ ! -z $apache ]] && [[ $apache = $selection ]] && edit_apache && break
        [[ ! -z $openvpn ]] && [[ $openvpn = $selection ]] && edit_openvpn && break
        [[ ! -z $dropbear ]] && [[ $dropbear = $selection ]] && edit_dropbear && break
        [[ ! -z $ssh ]] && [[ $ssh = $selection ]] && edit_openssh && break
        [[ "0" = $selection ]] && break
      done
      #exit 0
    }
    main_fun
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    herramientas_fun
  }

  cambiopass() { #CAMBIO DE PASS ROOT
    echo -e "${cor[3]} Esta herramienta cambia la contraseña de su servidor vps"
    echo -e "${cor[3]} Esta contraseña es utilizada como usuario root"
    msg -bar
    echo -ne "Desea Seguir? [S/N]: "
    read x
    [[ $x = @(n|N) ]] && msg -bar && return
    msg -bar
    #Inicia Procedimentos
    echo -e "${cor[0]} Escriba su nueva contraseña"
    msg -bar
    read -p " Nuevo passwd: " pass
    (
      echo $pass
      echo $pass
    ) | passwd root 2>/dev/null
    sleep 1s
    msg -bar
    echo -e "${cor[3]} Contraseña cambiada con exito!"
    echo -e "${cor[2]} Su contraseña ahora es: ${cor[4]}$pass"
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    herramientas_fun
  }
  rootpass() { #AGREGAR ROOT A AWS Y GOOGLE VPS
    clear
    msg -bar
    echo -e "${cor[3]}  Esta herramienta cambia a usuario root las VPS de "
    echo -e "${cor[3]}             GoogleCloud y Amazon"
    msg -bar
    echo -ne " Desea Seguir? [S/N]: "
    read x
    [[ $x = @(n|N) ]] && msg -bar && return
    msg -bar
    #Inicia Procedimentos
    echo -e "                 Aplicando Configuraciones"
    fun_bar "service ssh restart"
    #Parametros Aplicados
    sed -i "s;PermitRootLogin prohibit-password;PermitRootLogin yes;g" /etc/ssh/sshd_config
    sed -i "s;PermitRootLogin without-password;PermitRootLogin yes;g" /etc/ssh/sshd_config
    sed -i "s;PasswordAuthentication no;PasswordAuthentication yes;g" /etc/ssh/sshd_config
    msg -bar
    echo -e "Escriba su contraseña root actual o cambiela"
    msg -bar
    read -p " Nuevo passwd: " pass
    (
      echo $pass
      echo $pass
    ) | passwd 2>/dev/null
    sleep 1s
    msg -bar
    echo -e "${cor[3]} Configuraciones aplicadas con exito!"
    echo -e "${cor[2]} Su contraseña ahora es: ${cor[4]}$pass"
    service ssh restart >/dev/null 2>&1
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    herramientas_fun
  }
  pamcrack() { #DESACTIVAR PASS ALFANUMERICO
    echo -e "${cor[3]} Liberar passwd ALFANUMERICO"
    msg -bar
    echo -ne " Desea Seguir? [S/N]: "
    read x
    [[ $x = @(n|N) ]] && msg -bar && return
    echo -e ""
    wget -O /etc/pam.d/common-password https://raw.githubusercontent.com/NetVPS/LATAM_Oficial/main/Ejecutables/common-password &>/dev/null
    chmod +rwx /etc/pam.d/common-password
    fun_bar "service ssh restart"
    echo -e ""
    echo -e " \033[1;31m[ ! ]\033[1;33m Pass Alfanumerico Desactivado"
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    herramientas_fun
  }
  clear && clear
  msg -bar
  msg -tit
  msg -bar
  echo -e "\e[1;93m            AJUSTES INTERNOS DEL VPS  "
  msg -bar
  echo -e "\e[1;93m  [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;97mCAMBIAR HOSTNAME VPS"
  echo -e "\e[1;93m  [\e[1;32m2\e[1;93m]\033[1;31m > \e[1;97mCAMBIAR CONTRASEÑA ROOT"
  echo -e "\e[1;93m  [\e[1;32m3\e[1;93m]\033[1;31m > \e[1;97mAGREGAR ROOT a GoogleCloud y Amazon"
  echo -e "\e[1;93m  [\e[1;32m4\e[1;93m]\033[1;31m > \e[1;97mDESACTIVAR PASS ALFANUMERICO"
  echo -e "\e[1;93m  [\e[1;32m5\e[1;93m]\033[1;31m > \e[1;97mEDITOR DE PUERTOS"
  msg -bar
  echo -e "    \e[97m\033[1;41m ENTER SIN RESPUESTA REGRESA A MENU ANTERIOR \033[0;97m"
  msg -bar
  echo -ne "\033[0;97m  └⊳ Seleccione una Opcion: \033[1;32m" && read opx
  tput cuu1 && tput dl1

  case $opx in
  1)
    host_name
    ;;
  2)
    cambiopass
    ;;
  3)
    rootpass
    ;;
  4)
    pamcrack
    ;;
  5)
    editports
    ;;
  *)
    herramientas_fun
    ;;
  esac

}

#---DNS UNLOCKS
dns_unlock() {

  dnsnetflix() {
    echo "nameserver $dnsp" >/etc/resolv.conf
    #echo "nameserver 8.8.8.8" >> /etc/resolv.conf
    /etc/init.d/ssrmu stop &>/dev/null
    /etc/init.d/ssrmu start &>/dev/null
    /etc/init.d/shadowsocks-r stop &>/dev/null
    /etc/init.d/shadowsocks-r start &>/dev/null
    msg -bar2
    echo -e "${cor[4]}  DNS AGREGADOS CON EXITO"
  }
  clear && clear
  msg -bar2
  msg -tit
  msg -bar2
  echo -e "\033[1;93m         AGREGARDOR DE DNS PERSONALES "
  msg -bar2
  echo -e "\033[1;97m Esta funcion es para DNS Unlocks's"
  msg -bar2
  echo -e "\033[1;39m Solo es para Protolos con Interfas Tun."
  echo -e "\033[1;39m Como: SS,SSR,V2RAY"
  echo -e "\033[1;39m APK: V2RAYNG, SHADOWSHOK , SHADOWSOCKR "
  msg -bar2
  echo -e "\033[1;93m Recuerde escojer entre 1 DNS ya sea el de MX,ARG \n segun le aya entregado el BOT."
  echo ""
  echo -e "\033[1;97m Ingrese su DNS a usar: \033[1;92m"
  read -p "   " dnsp
  echo ""
  msg -bar2
  read -p " Estas seguro de continuar?  [ s | n ]: " dnsnetflix
  [[ "$dnsnetflix" = "s" || "$dnsnetflix" = "S" ]] && dnsnetflix
  msg -bar2
  read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
  herramientas_fun
}

#--- INSTALADOR BBR
bbr_fun() {
  PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
  export PATH
  sh_ver="1.3.1"
  github="raw.githubusercontent.com/cx9208/Linux-NetSpeed/master"
  Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
  Info="${Green_font_prefix}[Informacion]${Font_color_suffix}"
  Error="${Red_font_prefix}[Error]${Font_color_suffix}"
  Tip="${Green_font_prefix}[Atencion]${Font_color_suffix}"
  #Instalar el núcleo BBR
  installbbr() {
    kernel_version="4.11.8"
    if [[ "${release}" == "centos" ]]; then
      rpm --import http://${github}/bbr/${release}/RPM-GPG-KEY-elrepo.org
      yum install -y http://${github}/bbr/${release}/${version}/${bit}/kernel-ml-${kernel_version}.rpm
      yum remove -y kernel-headers
      yum install -y http://${github}/bbr/${release}/${version}/${bit}/kernel-ml-headers-${kernel_version}.rpm
      yum install -y http://${github}/bbr/${release}/${version}/${bit}/kernel-ml-devel-${kernel_version}.rpm
    elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
      mkdir bbr && cd bbr
      wget http://security.debian.org/debian-security/pool/updates/main/o/openssl/libssl1.0.0_1.0.1t-1+deb8u10_amd64.deb
      wget -N --no-check-certificate http://${github}/bbr/debian-ubuntu/linux-headers-${kernel_version}-all.deb
      wget -N --no-check-certificate http://${github}/bbr/debian-ubuntu/${bit}/linux-headers-${kernel_version}.deb
      wget -N --no-check-certificate http://${github}/bbr/debian-ubuntu/${bit}/linux-image-${kernel_version}.deb

      dpkg -i libssl1.0.0_1.0.1t-1+deb8u10_amd64.deb
      dpkg -i linux-headers-${kernel_version}-all.deb
      dpkg -i linux-headers-${kernel_version}.deb
      dpkg -i linux-image-${kernel_version}.deb
      cd .. && rm -rf bbr
    fi
    detele_kernel
    BBR_grub
    msg -bar
    echo -e "${Tip} Deves Reiniciar VPS y Activar Acelerador\n${Red_font_prefix} BBR/BBR Versión mágica${Font_color_suffix}"
    msg -bar
    stty erase '^H' && read -p "Reiniciar VPS para habilitar BBR ? [Y/n] :" yn
    [ -z "${yn}" ] && yn="y"
    if [[ $yn == [Yy] ]]; then
      echo -e "${Info} VPS se reinicia ..."
      reboot
    fi
  }

  #Instale el núcleo BBRplus
  installbbrplus() {
    kernel_version="4.14.129-bbrplus"
    if [[ "${release}" == "centos" ]]; then
      wget -N --no-check-certificate https://${github}/bbrplus/${release}/${version}/kernel-${kernel_version}.rpm
      yum install -y kernel-${kernel_version}.rpm
      rm -f kernel-${kernel_version}.rpm
      kernel_version="4.14.129_bbrplus" #fix a bug
    elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
      mkdir bbrplus && cd bbrplus
      wget -N --no-check-certificate http://${github}/bbrplus/debian-ubuntu/${bit}/linux-headers-${kernel_version}.deb
      wget -N --no-check-certificate http://${github}/bbrplus/debian-ubuntu/${bit}/linux-image-${kernel_version}.deb
      dpkg -i linux-headers-${kernel_version}.deb
      dpkg -i linux-image-${kernel_version}.deb
      cd .. && rm -rf bbrplus
    fi
    detele_kernel
    BBR_grub
    msg -bar
    echo -e "${Tip} Deves Reiniciar VPS y Activar Acelerador \n${Red_font_prefix} BBRplus${Font_color_suffix}"
    msg -bar
    stty erase '^H' && read -p "Reiniciar VPS para habilitar BBRplus? [Y/n]:" yn
    [ -z "${yn}" ] && yn="y"
    if [[ $yn == [Yy] ]]; then
      echo -e "${Info} VPS se reinicia ..."
      reboot
    fi
  }

  #Instale el kernel de Lotserver
  installlot() {
    if [[ "${release}" == "centos" ]]; then
      rpm --import http://${github}/lotserver/${release}/RPM-GPG-KEY-elrepo.org
      yum remove -y kernel-firmware
      yum install -y http://${github}/lotserver/${release}/${version}/${bit}/kernel-firmware-${kernel_version}.rpm
      yum install -y http://${github}/lotserver/${release}/${version}/${bit}/kernel-${kernel_version}.rpm
      yum remove -y kernel-headers
      yum install -y http://${github}/lotserver/${release}/${version}/${bit}/kernel-headers-${kernel_version}.rpm
      yum install -y http://${github}/lotserver/${release}/${version}/${bit}/kernel-devel-${kernel_version}.rpm
    elif [[ "${release}" == "ubuntu" ]]; then
      bash <(wget --no-check-certificate -qO- "http://${github}/Debian_Kernel.sh")
    elif [[ "${release}" == "debian" ]]; then
      bash <(wget --no-check-certificate -qO- "http://${github}/Debian_Kernel.sh")
    fi
    detele_kernel
    BBR_grub
    msg -bar
    echo -e "${Tip} Deves Reiniciar VPS y Activar Acelerador\n${Red_font_prefix}Lotserver${Font_color_suffix}"
    msg -bar
    stty erase '^H' && read -p "Necesita reiniciar el VPS antes de poder abrir Lotserver, reiniciar ahora ? [Y/n] :" yn
    [ -z "${yn}" ] && yn="y"
    if [[ $yn == [Yy] ]]; then
      echo -e "${Info} VPS se reinicia ..."
      reboot
    fi
  }

  # Habilitar BBR
  startbbr() {
    remove_all
    echo "Aceleracion Reconfigurada de Nuevo"
    echo "net.core.default_qdisc=fq" >>/etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.conf
    sysctl -p
    echo -e "${Info}¡BBR comenzó con éxito!"
    msg -bar
  }

  #Habilitar BBRplus
  startbbrplus() {
    remove_all
    echo "net.core.default_qdisc=fq" >>/etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbrplus" >>/etc/sysctl.conf
    sysctl -p
    echo -e "${Info}BBRplus comenzó con éxito!！"
    msg -bar
  }

  # Compilar y habilitar el cambio mágico BBR
  startbbrmod() {
    remove_all
    if [[ "${release}" == "centos" ]]; then
      yum install -y make gcc
      mkdir bbrmod && cd bbrmod
      wget -N --no-check-certificate http://${github}/bbr/tcp_tsunami.c
      echo "obj-m:=tcp_tsunami.o" >Makefile
      make -C /lib/modules/$(uname -r)/build M=$(pwd) modules CC=/usr/bin/gcc
      chmod +x ./tcp_tsunami.ko
      cp -rf ./tcp_tsunami.ko /lib/modules/$(uname -r)/kernel/net/ipv4
      insmod tcp_tsunami.ko
      depmod -a
    else
      apt-get update
      if [[ "${release}" == "ubuntu" && "${version}" = "14" ]]; then
        apt-get -y install build-essential
        apt-get -y install software-properties-common
        add-apt-repository ppa:ubuntu-toolchain-r/test -y
        apt-get update
      fi
      apt-get -y install make gcc
      mkdir bbrmod && cd bbrmod
      wget -N --no-check-certificate http://${github}/bbr/tcp_tsunami.c
      echo "obj-m:=tcp_tsunami.o" >Makefile
      ln -s /usr/bin/gcc /usr/bin/gcc-4.9
      make -C /lib/modules/$(uname -r)/build M=$(pwd) modules CC=/usr/bin/gcc-4.9
      install tcp_tsunami.ko /lib/modules/$(uname -r)/kernel
      cp -rf ./tcp_tsunami.ko /lib/modules/$(uname -r)/kernel/net/ipv4
      depmod -a
    fi

    echo "net.core.default_qdisc=fq" >>/etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=tsunami" >>/etc/sysctl.conf
    sysctl -p
    cd .. && rm -rf bbrmod
    echo -e "${Info}¡La versión mágica de BBR comenzó con éxito!"
    msg -bar
  }

  # Compilar y habilitar el cambio mágico BBR
  startbbrmod_nanqinlang() {
    remove_all
    if [[ "${release}" == "centos" ]]; then
      yum install -y make gcc
      mkdir bbrmod && cd bbrmod
      wget -N --no-check-certificate https://raw.githubusercontent.com/chiakge/Linux-NetSpeed/master/bbr/centos/tcp_nanqinlang.c
      echo "obj-m := tcp_nanqinlang.o" >Makefile
      make -C /lib/modules/$(uname -r)/build M=$(pwd) modules CC=/usr/bin/gcc
      chmod +x ./tcp_nanqinlang.ko
      cp -rf ./tcp_nanqinlang.ko /lib/modules/$(uname -r)/kernel/net/ipv4
      insmod tcp_nanqinlang.ko
      depmod -a
    else
      apt-get update
      if [[ "${release}" == "ubuntu" && "${version}" = "14" ]]; then
        apt-get -y install build-essential
        apt-get -y install software-properties-common
        add-apt-repository ppa:ubuntu-toolchain-r/test -y
        apt-get update
      fi
      apt-get -y install make gcc-4.9
      mkdir bbrmod && cd bbrmod
      wget -N --no-check-certificate https://raw.githubusercontent.com/chiakge/Linux-NetSpeed/master/bbr/tcp_nanqinlang.c
      echo "obj-m := tcp_nanqinlang.o" >Makefile
      make -C /lib/modules/$(uname -r)/build M=$(pwd) modules CC=/usr/bin/gcc-4.9
      install tcp_nanqinlang.ko /lib/modules/$(uname -r)/kernel
      cp -rf ./tcp_nanqinlang.ko /lib/modules/$(uname -r)/kernel/net/ipv4
      depmod -a
    fi

    echo "net.core.default_qdisc=fq" >>/etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=nanqinlang" >>/etc/sysctl.conf
    sysctl -p
    echo -e "${Info}¡La versión mágica de BBR comenzó con éxito!"
    msg -bar
  }

  # Desinstalar toda la aceleración
  remove_all() {
    rm -rf bbrmod
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    sed -i '/fs.file-max/d' /etc/sysctl.conf
    sed -i '/net.core.rmem_max/d' /etc/sysctl.conf
    sed -i '/net.core.wmem_max/d' /etc/sysctl.conf
    sed -i '/net.core.rmem_default/d' /etc/sysctl.conf
    sed -i '/net.core.wmem_default/d' /etc/sysctl.conf
    sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
    sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_tw_recycle/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_keepalive_time/d' /etc/sysctl.conf
    sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_rmem/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_wmem/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_mtu_probing/d' /etc/sysctl.conf
    sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
    sed -i '/fs.inotify.max_user_instances/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
    sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
    sed -i '/net.ipv4.route.gc_timeout/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_synack_retries/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_syn_retries/d' /etc/sysctl.conf
    sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
    sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_timestamps/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_max_orphans/d' /etc/sysctl.conf
    if [[ -e /appex/bin/lotServer.sh ]]; then
      bash <(wget --no-check-certificate -qO- https://github.com/MoeClub/lotServer/raw/master/Install.sh) uninstall
    fi
    clear
    echo -e "${Info}:La aceleración está Desinstalada."
    msg -bar
    sleep 1s
  }

  #Optimizar la configuración del sistema
  optimizing_system() {
    sed -i '/fs.file-max/d' /etc/sysctl.conf
    sed -i '/fs.inotify.max_user_instances/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
    sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
    sed -i '/net.ipv4.route.gc_timeout/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_synack_retries/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_syn_retries/d' /etc/sysctl.conf
    sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
    sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_timestamps/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_max_orphans/d' /etc/sysctl.conf
    sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
    echo "fs.file-max = 1000000
fs.inotify.max_user_instances = 8192
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_max_tw_buckets = 6000
net.ipv4.route.gc_timeout = 100
net.ipv4.tcp_syn_retries = 1
net.ipv4.tcp_synack_retries = 1
net.core.somaxconn = 32768
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_max_orphans = 32768
# forward ipv4
net.ipv4.ip_forward = 1" >>/etc/sysctl.conf
    sysctl -p
    echo "*               soft    nofile           1000000
*               hard    nofile          1000000" >/etc/security/limits.conf
    echo "ulimit -SHn 1000000" >>/etc/profile
    read -p "Después de aplicar la configuracion al VPS necesita reiniciar, reiniciar ahora ? [Y/n] :" yn
    msg -bar
    [ -z "${yn}" ] && yn="y"
    if [[ $yn == [Yy] ]]; then
      echo -e "${Info} Reinicio de VPS..."
      reboot
    fi
  }

  ############# Componentes de gestión del núcleo #############

  # Eliminar kernel redundante
  detele_kernel() {
    if [[ "${release}" == "centos" ]]; then
      rpm_total=$(rpm -qa | grep kernel | grep -v "${kernel_version}" | grep -v "noarch" | wc -l)
      if [ "${rpm_total}" ] >"1"; then
        echo -e "Detectado ${rpm_total} El resto del núcleo, comienza a desinstalar ..."
        for ((integer = 1; integer <= ${rpm_total}; integer++)); do
          rpm_del=$(rpm -qa | grep kernel | grep -v "${kernel_version}" | grep -v "noarch" | head -${integer})
          echo -e "Comience a desinstalar${rpm_del} Kernel ..."
          rpm --nodeps -e ${rpm_del}
          echo -e "Desinstalar ${rpm_del} La desinstalación del núcleo se ha completado, continúa ..."
        done
        echo --nodeps -e "El núcleo se desinstala y continúa ..."
      else
        echo -e " El número de núcleos detectados es incorrecto, ¡por favor verifique!" && exit 1
      fi
    elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
      deb_total=$(dpkg -l | grep linux-image | awk '{print $2}' | grep -v "${kernel_version}" | wc -l)
      if [ "${deb_total}" ] >"1"; then
        echo -e "Detectado ${deb_total} El resto del núcleo, comienza a desinstalar ..."
        for ((integer = 1; integer <= ${deb_total}; integer++)); do
          deb_del=$(dpkg -l | grep linux-image | awk '{print $2}' | grep -v "${kernel_version}" | head -${integer})
          echo -e "Comience a desinstalar ${deb_del} Kernel ..."
          apt-get purge -y ${deb_del}
          echo -e "Desinstalar ${deb_del} La desinstalación del núcleo se ha completado, continúa ..."
        done
        echo -e "El núcleo se desinstala y continúa ..."
      else
        echo -e " El número de núcleos detectados es incorrecto, ¡por favor verifique!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && bbr_fun
      fi
    fi
  }

  #Actualizar arranque
  BBR_grub() {
    if [[ "${release}" == "centos" ]]; then
      if [[ ${version} = "6" ]]; then
        if [ ! -f "/boot/grub/grub.conf" ]; then
          echo -e "${Error} /boot/grub/grub.conf No encontrado, verifique."
          exit 1
        fi
        sed -i 's/^default=.*/default=0/g' /boot/grub/grub.conf
      elif [[ ${version} = "7" ]]; then
        if [ ! -f "/boot/grub2/grub.cfg" ]; then
          echo -e "${Error} /boot/grub2/grub.cfg No encontrado, verifique."
          exit 1
        fi
        grub2-set-default 0
      fi
    elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
      /usr/sbin/update-grub
    fi
  }

  #############Componente de gestión del kernel#############

  #############Componentes de detección del sistema#############

  #Sistema de inspección
  check_sys() {
    if [[ -f /etc/redhat-release ]]; then
      release="centos"
    elif cat /etc/issue | grep -q -E -i "debian"; then
      release="debian"
    elif cat /etc/issue | grep -q -E -i "ubuntu"; then
      release="ubuntu"
    elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
      release="centos"
    elif cat /proc/version | grep -q -E -i "debian"; then
      release="debian"
    elif cat /proc/version | grep -q -E -i "ubuntu"; then
      release="ubuntu"
    elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
      release="centos"
    fi
  }

  #Verifique la versión de Linux
  check_version() {
    if [[ -s /etc/redhat-release ]]; then
      version=$(grep -oE "[0-9.]+" /etc/redhat-release | cut -d . -f 1)
    else
      version=$(grep -oE "[0-9.]+" /etc/issue | cut -d . -f 1)
    fi
    bit=$(uname -m)
    if [[ ${bit} = "x86_64" ]]; then
      bit="x64"
    else
      bit="x32"
    fi
  }

  #Verifique los requisitos del sistema para instalar bbr
  check_sys_bbr() {
    check_version
    if [[ "${release}" == "centos" ]]; then
      if [[ ${version} -ge "6" ]]; then
        installbbr
      else
        echo -e "${Error} BBR El núcleo no es compatible con el sistema actual ${release} ${version} ${bit} !" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && bbr_fun
      fi
    elif [[ "${release}" == "debian" ]]; then
      if [[ ${version} -ge "8" ]]; then
        installbbr
      else
        echo -e "${Error} BBR El núcleo no es compatible con el sistema actual ${release} ${version} ${bit} !" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && bbr_fun
      fi
    elif [[ "${release}" == "ubuntu" ]]; then
      if [[ ${version} -ge "14" ]]; then
        installbbr
      else
        echo -e "${Error} BBR El núcleo no es compatible con el sistema actual ${release} ${version} ${bit} !" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && bbr_fun
      fi
    else
      echo -e "${Error} BBR El núcleo no es compatible con el sistema actual ${release} ${version} ${bit} !" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && bbr_fun
    fi
  }

  check_sys_bbrplus() {
    check_version
    if [[ "${release}" == "centos" ]]; then
      if [[ ${version} -ge "6" ]]; then
        installbbrplus
      else
        echo -e "${Error} BBRplus El núcleo no es compatible con el sistema actual ${release} ${version} ${bit} !" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && bbr_fun
      fi
    elif [[ "${release}" == "debian" ]]; then
      if [[ ${version} -ge "8" ]]; then
        installbbrplus
      else
        echo -e "${Error} BBRplus El núcleo no es compatible con el sistema actual ${release} ${version} ${bit} !" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && bbr_fun
      fi
    elif [[ "${release}" == "ubuntu" ]]; then
      if [[ ${version} -ge "14" ]]; then
        installbbrplus
      else
        echo -e "${Error} BBRplus El núcleo no es compatible con el sistema actual ${release} ${version} ${bit} !" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && bbr_fun
      fi
    else
      echo -e "${Error} BBRplus El núcleo no es compatible con el sistema actual ${release} ${version} ${bit} !" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && bbr_fun
    fi
  }

  check_status() {
    kernel_version=$(uname -r | awk -F "-" '{print $1}')
    kernel_version_full=$(uname -r)
    if [[ ${kernel_version_full} = "4.14.129-bbrplus" ]]; then
      kernel_status="BBRplus"
    elif [[ ${kernel_version} = "3.10.0" || ${kernel_version} = "3.16.0" || ${kernel_version} = "3.2.0" || ${kernel_version} = "4.4.0" || ${kernel_version} = "3.13.0" || ${kernel_version} = "2.6.32" || ${kernel_version} = "4.9.0" ]]; then
      kernel_status="Lotserver"
    elif [[ $(echo ${kernel_version} | awk -F'.' '{print $1}') == "4" ]] && [[ $(echo ${kernel_version} | awk -F'.' '{print $2}') -ge 9 ]] || [[ $(echo ${kernel_version} | awk -F'.' '{print $1}') == "5" ]]; then
      kernel_status="BBR"
    else
      kernel_status="noinstall"
    fi

    if [[ ${kernel_status} == "Lotserver" ]]; then
      if [[ -e /appex/bin/lotServer.sh ]]; then
        run_status=$(bash /appex/bin/lotServer.sh status | grep "LotServer" | awk '{print $3}')
        if [[ ${run_status} = "running!" ]]; then
          run_status="Comenzó exitosamente"
        else
          run_status="No se pudo iniciar"
        fi
      else
        run_status="No hay acelerador instalado"
      fi
    elif [[ ${kernel_status} == "BBR" ]]; then
      run_status=$(grep "net.ipv4.tcp_congestion_control" /etc/sysctl.conf | awk -F "=" '{print $2}')
      if [[ ${run_status} == "bbr" ]]; then
        run_status=$(lsmod | grep "bbr" | awk '{print $1}')
        if [[ ${run_status} == "tcp_bbr" ]]; then
          run_status="BBR Comenzó exitosamente"
        else
          run_status="BBR Comenzó exitosamente"
        fi
      elif [[ ${run_status} == "tsunami" ]]; then
        run_status=$(lsmod | grep "tsunami" | awk '{print $1}')
        if [[ ${run_status} == "tcp_tsunami" ]]; then
          run_status="BBR La revisión mágica se lanzó con éxito"
        else
          run_status="BBR Inicio de modificación mágica fallido"
        fi
      elif [[ ${run_status} == "nanqinlang" ]]; then
        run_status=$(lsmod | grep "nanqinlang" | awk '{print $1}')
        if [[ ${run_status} == "tcp_nanqinlang" ]]; then
          run_status="El violento manifestante de BBR se lanzó con éxito"
        else
          run_status="Violenta revisión mágica de BBR no pudo comenzar"
        fi
      else
        run_status="No hay acelerador instalado"
      fi
    elif [[ ${kernel_status} == "BBRplus" ]]; then
      run_status=$(grep "net.ipv4.tcp_congestion_control" /etc/sysctl.conf | awk -F "=" '{print $2}')
      if [[ ${run_status} == "bbrplus" ]]; then
        run_status=$(lsmod | grep "bbrplus" | awk '{print $1}')
        if [[ ${run_status} == "tcp_bbrplus" ]]; then
          run_status="BBRplus comenzó con éxito"
        else
          run_status="BBRplus comenzó con éxito"
        fi
      else
        run_status="No hay acelerador instalado"
      fi
    fi
  }

  #############Componentes de detección del sistema#############
  check_sys
  check_version
  [[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && [[ ${release} != "centos" ]] && echo -e "${Error} Este script no es compatible con el sistema actual. ${release} !" && herramientas_fun
  # Menú de inicio

  clear && clear
  msg -bar
  msg -tit
  msg -bar
  echo -e "\e[1;93m         ACELERACION BBR [ PLUS/MAGICK ]  "
  echo -e "\033[38;5;239m════════════════\e[48;5;1m\e[38;5;230m  INSTALAR KERNEL \e[0m\e[38;5;239m══════════════════"
  echo -e "\e[1;93m  [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;97m INSTALAR KERNEL MAGICO"
  echo -e "\e[1;93m  [\e[1;32m2\e[1;93m]\033[1;31m > \e[1;97m INSTALAR KERNEL BBRPLUS"
  echo -e "\033[38;5;239m═══════════════\e[48;5;2m\e[38;5;22m  ACTIVAR ACELERADOR \e[0m\e[38;5;239m════════════════"
  echo -e "\e[1;93m  [\e[1;32m3\e[1;93m]\033[1;31m > \e[1;97m ACELERACION (KERNER STOCK UBUNTU 18+)"
  echo -e "\e[1;93m  [\e[1;32m4\e[1;93m]\033[1;31m > \e[1;97m ACELERACION (KERNEL MAGICO)"
  echo -e "\e[1;93m  [\e[1;32m5\e[1;93m]\033[1;31m > \e[1;97m ACELERACION (KERNEL MAGICO MODO AGRECIVO)"
  echo -e "\e[1;93m  [\e[1;32m6\e[1;93m]\033[1;31m > \e[1;97m ACELERACION (KERNEL BB_RPLUS)"
  echo -e "\033[38;5;239m════════════════════════════════════════════════════"
  echo -e "\e[1;93m  [\e[1;32m7\e[1;93m]\033[1;31m > \e[1;91m DESINTALAR TODAS LAS ACELERACIONES"
  echo -e "\e[1;93m  [\e[1;32m8\e[1;93m]\033[1;31m > \e[1;93m OPTIMIZACION DE LA CONFIGURACION "
  msg -bar
  check_status
  if [[ ${kernel_status} == "noinstall" ]]; then
    echo -e " KERNEL ACTUAL: ${Green_font_prefix}No instalado\n${Font_color_suffix} Kernel Acelerado ${Red_font_prefix}Por favor, instale el Núcleo primero.${Font_color_suffix}"
  else
    echo -e " KERNEL ACTUAL: ${Green_font_prefix}Instalado\n${Font_color_suffix} ${_font_prefix}${kernel_status}${Font_color_suffix} Kernel Acelerado, ${Green_font_prefix}${run_status}${Font_color_suffix}"

  fi
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m0\e[1;93m]\033[1;31m > " && echo -e "\e[97m\033[1;41m VOLVER \033[0;37m"
  msg -bar
  echo -ne "\033[1;97m   └⊳ Seleccione una opcion [0-8]: \033[1;32m" && read num
  case "$num" in
  1)
    check_sys_bbr
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    bbr_fun
    ;;
  2)
    check_sys_bbrplus
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    bbr_fun
    ;;
  3)
    startbbr
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    bbr_fun
    ;;
  4)
    startbbrmod
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    bbr_fun
    ;;
  5)
    startbbrmod_nanqinlang
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    bbr_fun
    ;;
  6)
    startbbrplus
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    bbr_fun
    ;;
  7)
    remove_all
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    bbr_fun
    ;;
  8)
    optimizing_system
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    bbr_fun
    ;;
  *)
    herramientas_fun
    # read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    ;;
  esac
  #exit 0
}

#---PONER PASS SQUID
pass_squid() {
  squidpass() {
    tmp_arq="/tmp/arq-tmp"
    if [ -d "/etc/squid" ]; then
      pwd="/etc/squid/passwd"
      config_="/etc/squid/squid.conf"
      service_="squid"
      squid_="0"
    elif [ -d "/etc/squid3" ]; then
      pwd="/etc/squid3/passwd"
      config_="/etc/squid3/squid.conf"
      service_="squid3"
      squid_="1"
    fi
    [[ ! -e $config_ ]] &&
      msg -bar &&
      echo -e " \033[1;36m Proxy Squid no Instalado no puede proseguir" &&
      msg -bar &&
      return 0
    if [ -e $pwd ]; then
      echo -e "${cor[3]} Desea Desactivar Autentificasion del Proxy Squid"
      read -p " [S/N]: " -e -i n sshsn
      [[ "$sshsn" = @(s|S|y|Y) ]] && {
        msg -bar
        echo -e " \033[1;36mDesintalando Dependencias:"
        rm -rf /usr/bin/squid_log1
        fun_bar 'apt-get remove apache2-utils'
        msg -bar
        cat $config_ | grep -v '#Password' >$tmp_arq
        mv -f $tmp_arq $config_
        cat $config_ | grep -v '^auth_param.*passwd*$' >$tmp_arq
        mv -f $tmp_arq $config_
        cat $config_ | grep -v '^auth_param.*proxy*$' >$tmp_arq
        mv -f $tmp_arq $config_
        cat $config_ | grep -v '^acl.*REQUIRED*$' >$tmp_arq
        mv -f $tmp_arq $config_
        cat $config_ | grep -v '^http_access.*authenticated*$' >$tmp_arq
        mv -f $tmp_arq $config_
        cat $config_ | grep -v '^http_access.*all*$' >$tmp_arq
        mv -f $tmp_arq $config_
        echo -e "
http_access allow all" >>"$config_"
        rm -f $pwd
        service $service_ restart >/dev/null 2>&1 &
        echo -e " \033[1;31m Desautentificasion de Proxy Squid Desactivado"
        msg -bar
      }
    else
      echo -e "${cor[3]} "Confirmar Autentificasion ?""
      read -p " [S/N]: " -e -i n sshsn
      [[ "$sshsn" = @(s|S|y|Y) ]] && {
        msg -bar
        echo -e " \033[1;36mInstalando Dependencias:"
        echo "Archivo SQUID PASS" >/usr/bin/squid_log1
        fun_bar 'apt-get install apache2-utils'
        msg -bar
        read -e -p " Tu nombre de usuario deseado: " usrn
        [[ $usrn = "" ]] &&
          msg -bar &&
          echo -e " \033[1;31mEl usuario no puede ser nulo" &&
          msg -bar &&
          return 0
        htpasswd -c $pwd $usrn
        succes_=$(grep -c "$usrn" $pwd)
        if [ "$succes_" = "0" ]; then
          rm -f $pwd
          msg -bar
          echo -e " \033[1;31m Error al generar la contraseña, no se inicio la autenticacion de Squid"
          msg -bar
          return 0
        elif [[ "$succes_" = "1" ]]; then
          cat $config_ | grep -v '^http_access.*all*$' >$tmp_arq
          mv -f $tmp_arq $config_
          if [ "$squid_" = "0" ]; then
            echo -e "#Password
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic realm proxy
acl authenticated proxy_auth REQUIRED
http_access allow authenticated
http_access deny all" >>"$config_"
            service squid restart >/dev/null 2>&1 &
            update-rc.d squid defaults >/dev/null 2>&1 &
          elif [ "$squid_" = "1" ]; then
            echo -e "#Password
auth_param basic program /usr/lib/squid3/basic_ncsa_auth /etc/squid3/passwd
auth_param basic realm proxy
acl authenticated proxy_auth REQUIRED
http_access allow authenticated
http_access deny all" >>"$config_"
            service squid3 restart >/dev/null 2>&1 &
            update-rc.d squid3 defaults >/dev/null 2>&1 &
          fi
          msg -bar
          service squid restart >/dev/null 2>&1
          echo -e " \033[1;32m PROTECCION DE PROXY INICIADA"
          msg -bar
        fi
      }
    fi
  }
  clear && clear
  msg -bar
  msg -tit
  msg -bar
  msg -ama "            AUTENTIFICAR PROXY SQUID "
  msg -bar
  unset squid_log1
  [[ -e /usr/bin/squid_log1 ]] && squid_log1="\033[1;32mACTIVO"
  echo -ne " \e[1;93m [\e[1;32m1\e[1;93m]\033[1;31m > \033[1;97m PONER CONTRASEÑA A SQUID $squid_log1\e[97m \n"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m0\e[1;93m]\033[1;31m > \033[1;97m" && msg -bra "  \e[97m\033[1;41m VOLVER \033[1;37m"
  msg -bar
  echo -ne "\033[1;37mEscoja una Opcion: "
  read optons
  case $optons in
  1)
    msg -bar
    squidpass
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    herramientas_fun
    ;;
  *)
    msg -bar
    herramientas_fun
    ;;
  esac
}

#---FAIL2BAN
fai2ban_fun() {
  pid_fail=$(ps x | grep "fail2ban" | grep -v grep | awk -F "pts" '{print $1}')
  apache=$(dpkg -l | grep apache2 | grep ii)
  squid=$(dpkg -l | grep squid | grep ii)
  dropbear=$(dpkg -l | grep dropbear | grep ii)
  openssh=$(dpkg -l | grep openssh | grep ii)
  stunnel4=$(dpkg -l | grep stunnel4 | grep ii)
  [[ "$openssh" != "" ]] && s1="ssh"
  [[ "$squid" != "" ]] && s2="squid"
  [[ "$dropbear" != "" ]] && s3="dropbear"
  [[ "$apache" != "" ]] && s4="apache"
  [[ "$stunnel4" != "" ]] && s5="stunnel4"
  remove_fail2ba() {
    apt-get remove fail2ban -y &>/dev/null
    service fail2ban stop &>/dev/null
    kill $(ps ax | grep fail2ban | grep -v grep | awk '{print $1}') &>/dev/null
    rm -rf /etc/SCRIPT-LATAM/fail2ban &>/dev/null
    echo -e "\e[1;32m      >> FAIL2BAN DESINTALADO CON EXITO << "
  }
  clear
  clear
  msg -bar
  msg -tit
  msg -bar
  echo -e "\e[93m                INSTALADOR FAIL2BAN   "
  echo -e "\e[97m             ANTI DDOS y SPOOFING SPAM"
  msg -bar
  if [[ ! -z "$pid_fail" ]]; then
    echo -e "\e[1;93m  [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;91mDESINSTALAR FAIL2BAN"
    echo -e "\e[1;93m  [\e[1;32m2\e[1;93m]\033[1;31m > \e[1;93mVER LOG DE REGISTROS"
    msg -bar
    echo -ne " \e[1;93m [\e[1;32m0\e[1;93m]\033[1;31m > " && echo -e "\e[97m\033[1;41m VOLVER \033[0;37m"
    msg -bar
    echo -ne "\033[1;97m   └⊳ Seleccione una opcion [0-2]: \033[1;32m" && read num
    tput cuu1 && tput dl1
    case "$num" in
    1)
      remove_fail2ba
      msg -bar
      read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      herramientas_fun
      ;;
    2)
      cat /var/log/fail2ban.log
      msg -bar
      read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      herramientas_fun
      ;;
    *)
      herramientas_fun
      ;;
    esac
    return 0
  fi

  echo -e "\e[1;92m         CONFIRMAR INSTALACION DE FAIL2BAN?"
  msg -bar
  while [[ -z ${fail2ban} || ${fail2ban} != @(s|S|n|N|y|Y) ]]; do
    echo -ne "\033[1;37mSeleccione una Opcion [S/N]: \033[1;32m" && read fail2ban
    tput cuu1 && tput dl1
  done
  if [[ "$fail2ban" = @(s|S|y|Y) ]]; then
    fun_bar "git clone https://github.com/fail2ban/fail2ban.git"
    cd fail2ban &>/dev/null
    sudo python setup.py install &>/dev/null
    cp files/debian-initd /etc/init.d/fail2ban &>/dev/null
    service fail2ban start &>/dev/null
    echo '[INCLUDES]
before = paths-debian.conf
[DEFAULT]
ignoreip = 127.0.0.1/8
# ignorecommand = /path/to/command <ip>
ignorecommand =
bantime  = 1036800
findtime  = 3600
maxretry = 5
backend = auto
usedns = warn
logencoding = auto
enabled = false
filter = %(__name__)s
destemail = root@localhost
sender = root@localhost
mta = sendmail
protocol = tcp
chain = INPUT
port = 0:65535
fail2ban_agent = Fail2Ban/%(fail2ban_version)s
banaction = iptables-multiport
banaction_allports = iptables-allports
action_ = %(banaction)s[name=%(__name__)s, bantime="%(bantime)s", port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
action_mw = %(banaction)s[name=%(__name__)s, bantime="%(bantime)s", port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
            %(mta)s-whois[name=%(__name__)s, sender="%(sender)s", dest="%(destemail)s", protocol="%(protocol)s", chain="%(chain)s"]
action_mwl = %(banaction)s[name=%(__name__)s, bantime="%(bantime)s", port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
             %(mta)s-whois-lines[name=%(__name__)s, sender="%(sender)s", dest="%(destemail)s", logpath=%(logpath)s, chain="%(chain)s"]
action_xarf = %(banaction)s[name=%(__name__)s, bantime="%(bantime)s", port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
             xarf-login-attack[service=%(__name__)s, sender="%(sender)s", logpath=%(logpath)s, port="%(port)s"]
action_cf_mwl = cloudflare[cfuser="%(cfemail)s", cftoken="%(cfapikey)s"]
                %(mta)s-whois-lines[name=%(__name__)s, sender="%(sender)s", dest="%(destemail)s", logpath=%(logpath)s, chain="%(chain)s"]
action_blocklist_de  = blocklist_de[email="%(sender)s", service=%(filter)s, apikey="%(blocklist_de_apikey)s", agent="%(fail2ban_agent)s"]
action_badips = badips.py[category="%(__name__)s", banaction="%(banaction)s", agent="%(fail2ban_agent)s"]
action_badips_report = badips[category="%(__name__)s", agent="%(fail2ban_agent)s"]
action = %(action_)s' >/etc/fail2ban/jail.local
    echo -ne "\e[1;93m Fail2ban sera activo en los Siguientes\n >> Puertos y Servicos\n"
    msg -bar
    echo -ne "\n"
    [ "$s1" != "" ] && echo -ne " $s1"
    [ "$s2" != "" ] && echo -ne " $s2"
    [ "$s3" != "" ] && echo -ne " $s3"
    [ "$s4" != "" ] && echo -ne " $s4"
    [ "$s5" != "" ] && echo -ne " $s5"
    echo -ne "\n\n"
    msg -bar
    sleep 1
    if [[ "$s1" != "" ]]; then
      echo '[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
[sshd-ddos]
enabled = true
port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s' >>/etc/fail2ban/jail.local
    else
      echo '[sshd]
port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
[sshd-ddos]
port    = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s' >>/etc/fail2ban/jail.local
    fi
    if [[ "$s2" != "" ]]; then
      echo '[squid]
enabled = true
port     =  80,443,3128,8080
logpath = /var/log/squid/access.log' >>/etc/fail2ban/jail.local
    else
      echo '[squid]
port     =  80,443,3128,8080
logpath = /var/log/squid/access.log' >>/etc/fail2ban/jail.local
    fi
    if [[ "$s3" != "" ]]; then
      echo '[dropbear]
enabled = true
port     = ssh
logpath  = %(dropbear_log)s
backend  = %(dropbear_backend)s' >>/etc/fail2ban/jail.local
    else
      echo '[dropbear]
port     = ssh
logpath  = %(dropbear_log)s
backend  = %(dropbear_backend)s' >>/etc/fail2ban/jail.local
    fi
    if [[ "$s4" != "" ]]; then
      echo '[apache-auth]
enabled = true
port     = http,https
logpath  = %(apache_error_log)s' >>/etc/fail2ban/jail.local
    else
      echo '[apache-auth]
port     = http,https
logpath  = %(apache_error_log)s' >>/etc/fail2ban/jail.local
    fi
    echo '[selinux-ssh]
port     = ssh
logpath  = %(auditd_log)s
[apache-badbots]
port     = http,https
logpath  = %(apache_access_log)s
bantime  = 172800
maxretry = 1
[apache-noscript]
port     = http,https
logpath  = %(apache_error_log)s
[apache-overflows]
port     = http,https
logpath  = %(apache_error_log)s
maxretry = 2
[apache-nohome]
port     = http,https
logpath  = %(apache_error_log)s
maxretry = 2
[apache-botsearch]
port     = http,https
logpath  = %(apache_error_log)s
maxretry = 2
[apache-fakegooglebot]
port     = http,https
logpath  = %(apache_access_log)s
maxretry = 1
ignorecommand = %(ignorecommands_dir)s/apache-fakegooglebot <ip>
[apache-modsecurity]
port     = http,https
logpath  = %(apache_error_log)s
maxretry = 2
[apache-shellshock]
port    = http,https
logpath = %(apache_error_log)s
maxretry = 1
[openhab-auth]
filter = openhab
action = iptables-allports[name=NoAuthFailures]
logpath = /opt/openhab/logs/request.log
[nginx-http-auth]
port    = http,https
logpath = %(nginx_error_log)s
[nginx-limit-req]
port    = http,https
logpath = %(nginx_error_log)s
[nginx-botsearch]
port     = http,https
logpath  = %(nginx_error_log)s
maxretry = 2
[php-url-fopen]
port    = http,https
logpath = %(nginx_access_log)s
          %(apache_access_log)s
[suhosin]
port    = http,https
logpath = %(suhosin_log)s
[lighttpd-auth]
port    = http,https
logpath = %(lighttpd_error_log)s
[roundcube-auth]
port     = http,https
logpath  = %(roundcube_errors_log)s
[openwebmail]
port     = http,https
logpath  = /var/log/openwebmail.log
[horde]
port     = http,https
logpath  = /var/log/horde/horde.log
[groupoffice]
port     = http,https
logpath  = /home/groupoffice/log/info.log
[sogo-auth]
port     = http,https
logpath  = /var/log/sogo/sogo.log
[tine20]
logpath  = /var/log/tine20/tine20.log
port     = http,https
[drupal-auth]
port     = http,https
logpath  = %(syslog_daemon)s
backend  = %(syslog_backend)s
[guacamole]
port     = http,https
logpath  = /var/log/tomcat*/catalina.out
[monit]
#Ban clients brute-forcing the monit gui login
port = 2812
logpath  = /var/log/monit
[webmin-auth]
port    = 10000
logpath = %(syslog_authpriv)s
backend = %(syslog_backend)s
[froxlor-auth]
port    = http,https
logpath  = %(syslog_authpriv)s
backend  = %(syslog_backend)s
[3proxy]
port    = 3128
logpath = /var/log/3proxy.log
[proftpd]
port     = ftp,ftp-data,ftps,ftps-data
logpath  = %(proftpd_log)s
backend  = %(proftpd_backend)s
[pure-ftpd]
port     = ftp,ftp-data,ftps,ftps-data
logpath  = %(pureftpd_log)s
backend  = %(pureftpd_backend)s
[gssftpd]
port     = ftp,ftp-data,ftps,ftps-data
logpath  = %(syslog_daemon)s
backend  = %(syslog_backend)s
[wuftpd]
port     = ftp,ftp-data,ftps,ftps-data
logpath  = %(wuftpd_log)s
backend  = %(wuftpd_backend)s
[vsftpd]
port     = ftp,ftp-data,ftps,ftps-data
logpath  = %(vsftpd_log)s
[assp]
port     = smtp,465,submission
logpath  = /root/path/to/assp/logs/maillog.txt
[courier-smtp]
port     = smtp,465,submission
logpath  = %(syslog_mail)s
backend  = %(syslog_backend)s
[postfix]
port     = smtp,465,submission
logpath  = %(postfix_log)s
backend  = %(postfix_backend)s
[postfix-rbl]
port     = smtp,465,submission
logpath  = %(postfix_log)s
backend  = %(postfix_backend)s
maxretry = 1
[sendmail-auth]
port    = submission,465,smtp
logpath = %(syslog_mail)s
backend = %(syslog_backend)s
[sendmail-reject]
port     = smtp,465,submission
logpath  = %(syslog_mail)s
backend  = %(syslog_backend)s
[qmail-rbl]
filter  = qmail
port    = smtp,465,submission
logpath = /service/qmail/log/main/current
[dovecot]
port    = pop3,pop3s,imap,imaps,submission,465,sieve
logpath = %(dovecot_log)s
backend = %(dovecot_backend)s
[sieve]
port   = smtp,465,submission
logpath = %(dovecot_log)s
backend = %(dovecot_backend)s
[solid-pop3d]
port    = pop3,pop3s
logpath = %(solidpop3d_log)s
[exim]
port   = smtp,465,submission
logpath = %(exim_main_log)s
[exim-spam]
port   = smtp,465,submission
logpath = %(exim_main_log)s
[kerio]
port    = imap,smtp,imaps,465
logpath = /opt/kerio/mailserver/store/logs/security.log
[courier-auth]
port     = smtp,465,submission,imap3,imaps,pop3,pop3s
logpath  = %(syslog_mail)s
backend  = %(syslog_backend)s
[postfix-sasl]
port     = smtp,465,submission,imap3,imaps,pop3,pop3s
logpath  = %(postfix_log)s
backend  = %(postfix_backend)s
[perdition]
port   = imap3,imaps,pop3,pop3s
logpath = %(syslog_mail)s
backend = %(syslog_backend)s
[squirrelmail]
port = smtp,465,submission,imap2,imap3,imaps,pop3,pop3s,http,https,socks
logpath = /var/lib/squirrelmail/prefs/squirrelmail_access_log
[cyrus-imap]
port   = imap3,imaps
logpath = %(syslog_mail)s
backend = %(syslog_backend)s
[uwimap-auth]
port   = imap3,imaps
logpath = %(syslog_mail)s
backend = %(syslog_backend)s
[named-refused]
port     = domain,953
logpath  = /var/log/named/security.log
[nsd]
port     = 53
action   = %(banaction)s[name=%(__name__)s-tcp, port="%(port)s", protocol="tcp", chain="%(chain)s", actname=%(banaction)s-tcp]
           %(banaction)s[name=%(__name__)s-udp, port="%(port)s", protocol="udp", chain="%(chain)s", actname=%(banaction)s-udp]
logpath = /var/log/nsd.log
[asterisk]
port     = 5060,5061
action   = %(banaction)s[name=%(__name__)s-tcp, port="%(port)s", protocol="tcp", chain="%(chain)s", actname=%(banaction)s-tcp]
           %(banaction)s[name=%(__name__)s-udp, port="%(port)s", protocol="udp", chain="%(chain)s", actname=%(banaction)s-udp]
           %(mta)s-whois[name=%(__name__)s, dest="%(destemail)s"]
logpath  = /var/log/asterisk/messages
maxretry = 10
[freeswitch]
port     = 5060,5061
action   = %(banaction)s[name=%(__name__)s-tcp, port="%(port)s", protocol="tcp", chain="%(chain)s", actname=%(banaction)s-tcp]
           %(banaction)s[name=%(__name__)s-udp, port="%(port)s", protocol="udp", chain="%(chain)s", actname=%(banaction)s-udp]
           %(mta)s-whois[name=%(__name__)s, dest="%(destemail)s"]
logpath  = /var/log/freeswitch.log
maxretry = 10
[mysqld-auth]
port     = 3306
logpath  = %(mysql_log)s
backend  = %(mysql_backend)s
[recidive]
logpath  = /var/log/fail2ban.log
banaction = %(banaction_allports)s
bantime  = 604800  ; 1 week
findtime = 86400   ; 1 day
[pam-generic]
banaction = %(banaction_allports)s
logpath  = %(syslog_authpriv)s
backend  = %(syslog_backend)s
[xinetd-fail]
banaction = iptables-multiport-log
logpath   = %(syslog_daemon)s
backend   = %(syslog_backend)s
maxretry  = 2
[stunnel]
logpath = /var/log/stunnel4/stunnel.log
[ejabberd-auth]
port    = 5222
logpath = /var/log/ejabberd/ejabberd.log
[counter-strike]
logpath = /opt/cstrike/logs/L[0-9]*.log
# Firewall: http://www.cstrike-planet.com/faq/6
tcpport = 27030,27031,27032,27033,27034,27035,27036,27037,27038,27039
udpport = 1200,27000,27001,27002,27003,27004,27005,27006,27007,27008,27009,27010,27011,27012,27013,27014,27015
action  = %(banaction)s[name=%(__name__)s-tcp, port="%(tcpport)s", protocol="tcp", chain="%(chain)s", actname=%(banaction)s-tcp]
           %(banaction)s[name=%(__name__)s-udp, port="%(udpport)s", protocol="udp", chain="%(chain)s", actname=%(banaction)s-udp]
[nagios]
logpath  = %(syslog_daemon)s     ; nrpe.cfg may define a different log_facility
backend  = %(syslog_backend)s
maxretry = 1
[directadmin]
logpath = /var/log/directadmin/login.log
port = 2222
[portsentry]
logpath  = /var/lib/portsentry/portsentry.history
maxretry = 1
[pass2allow-ftp]
# this pass2allow example allows FTP traffic after successful HTTP authentication
port         = ftp,ftp-data,ftps,ftps-data
# knocking_url variable must be overridden to some secret value in filter.d/apache-pass.local
filter       = apache-pass
# access log of the website with HTTP auth
logpath      = %(apache_access_log)s
blocktype    = RETURN
returntype   = DROP
bantime      = 3600
maxretry     = 1
findtime     = 1
[murmur]
port     = 64738
action   = %(banaction)s[name=%(__name__)s-tcp, port="%(port)s", protocol=tcp, chain="%(chain)s", actname=%(banaction)s-tcp]
           %(banaction)s[name=%(__name__)s-udp, port="%(port)s", protocol=udp, chain="%(chain)s", actname=%(banaction)s-udp]
logpath  = /var/log/mumble-server/mumble-server.log
[screensharingd]
logpath  = /var/log/system.log
logencoding = utf-8
[haproxy-http-auth]
logpath  = /var/log/haproxy.log' >>/etc/fail2ban/jail.local
    service fail2ban restart
    systemctl daemon-reload
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    herramientas_fun
  fi

}

#---ARCHIVOS ONLINE
ftp_apache() {
  clear && clear
  fun_ip() {
    MEU_IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
    MEU_IP2=$(wget -qO- ipv4.icanhazip.com)
    [[ "$MEU_IP" != "$MEU_IP2" ]] && echo "$MEU_IP2" || echo "$MEU_IP"
  }
  IP="$(fun_ip)"
  list_archivos() {

    [[ $(find /var/www/html -name index.html | grep -w "index.html" | head -1) ]] &>/dev/null || {
      echo -e "\e[1;31m              SIN REGITROS A UN "
      msg -bar
      return
    }
    [[ -z $(ls /var/www/html) ]] && echo -e "" || {
      for my_arqs in $(ls /var/www/html); do
        [[ "$my_arqs" = "index.html" ]] && continue
        [[ "$my_arqs" = "index.php" ]] && continue
        [[ -d "$my_arqs" ]] && continue
        echo -e "\033[1;31m[$my_arqs] \033[1;36mhttp://$IP:81/$my_arqs\033[0m"
      done
      msg -bar
    }
  }
  borar_archivos() {
    [[ $(find /var/www/html -name index.html | grep -w "index.html" | head -1) ]] &>/dev/null || {
      echo -e "\e[1;31m              SIN REGITROS A UN "
      msg -bar
      return
    }
    i="1"

    [[ -z $(ls /var/www/html) ]] && echo -e "" || {
      for my_arqs in $(ls /var/www/html); do
        [[ "$my_arqs" = "index.html" ]] && continue
        [[ "$my_arqs" = "index.php" ]] && continue
        [[ -d "$my_arqs" ]] && continue
        select_arc[$i]="$my_arqs"
        echo -e "${cor[2]}[$i] > ${cor[3]}$my_arqs - \033[1;36mhttp://$IP:81/$my_arqs\033[0m"
        let i++
      done
      msg -bar
      echo -e "${cor[5]}Seleccione el archivo que desea borrar"
      msg -bar
      i=$(($i - 1))
      #  while [[ -z ${select_arc[$slct]} ]]; do
      read -p " [1-$i]: " slct
      tput cuu1 && tput dl1
      #  done
      arquivo_move="${select_arc[$slct]}"
      [[ -d /var/www/html ]] && [[ -e /var/www/html/$arquivo_move ]] && rm -rf /var/www/html/$arquivo_move >/dev/null 2>&1
      [[ -e /var/www/$arquivo_move ]] && rm -rf /var/www/$arquivo_move >/dev/null 2>&1
      echo -e "\e[1;32m  >> Completado con Exito!"
      msg -bar
    }
  }
  subir_archivo() {
    i="1"
    [[ -z $(ls $HOME) ]] && echo -e "" || {
      for my_arqs in $(ls $HOME); do
        [[ -d "$my_arqs" ]] && continue
        select_arc[$i]="$my_arqs"
        echo -e "${cor[2]} [$i] > ${cor[3]}$my_arqs"
        let i++
      done
      i=$(($i - 1))
      msg -bar
      echo -e "${cor[5]}Seleccione el archivo"
      msg -bar
      # while [[ -z ${select_arc[$slct]} ]]; do
      read -p " [1-$i]: " slct
      tput cuu1 && tput dl1
      #done
      arquivo_move="${select_arc[$slct]}"
      [ ! -d /var ] && mkdir /var
      [ ! -d /var/www ] && mkdir /var/www
      [ ! -d /var/www/html ] && mkdir /var/www/html
      [ ! -e /var/www/html/index.html ] && touch /var/www/html/index.html
      [ ! -e /var/www/index.html ] && touch /var/www/index.html
      chmod -R 755 /var/www
      cp $HOME/$arquivo_move /var/www/$arquivo_move
      cp $HOME/$arquivo_move /var/www/html/$arquivo_move
      echo -e "\033[1;36m http://$IP:81/$arquivo_move\033[0m"
      msg -bar
      echo -e "\e[1;32m  >> Completado con Exito!"
      msg -bar
    }
  }
  msg -bar
  msg -tit
  msg -bar
  echo -e "\033[1;93m          GESTOR FTP VIA APACHE DIRECTO"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m1\e[1;93m]\033[1;31m > \033[1;97m COLOCAR ARCHIVO OLINE\e[97m \n"
  echo -ne " \e[1;93m [\e[1;32m2\e[1;93m]\033[1;31m > \033[1;97m QUITAR ARCHIVO ONLINE\e[97m \n"
  echo -ne " \e[1;93m [\e[1;32m3\e[1;93m]\033[1;31m > \033[1;97m VER ARCHIVOS ONLINE\e[97m \n"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m0\e[1;93m]\033[1;31m > \033[1;97m" && msg -bra "  \e[97m\033[1;41m VOLVER \033[1;37m"
  msg -bar
  echo -ne "\033[1;37mEscoja una Opcion: "
  read optons
  tput cuu1 && tput dl1
  case $optons in
  3)
    list_archivos
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    ftp_apache
    ;;
  2)
    borar_archivos
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    ftp_apache
    ;;
  1)
    subir_archivo
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    ftp_apache
    ;;
  *)
    msg -bar
    herramientas_fun
    ;;
  esac

}

#---NOTIBOT
noti_bot() {
  add_id() {
    echo -ne "\033[1;37mDIGITE SU ID NUMERICO DE TELEGRAM: \e[1;32m" && read idtele
    tput cuu1 && tput dl1
    echo -ne "\033[1;37mDIGITE SU ID NUMERICO DE GRUPO TELEGRAM: \e[1;32m" && read -p " " -e -i "Enter-OFF" idgrupo
    tput cuu1 && tput dl1
    echo -ne "\033[1;37mDIGITE NOMBRE PARA IDENTIFICAR VPS: \e[1;32m" && read nomvps
    tput cuu1 && tput dl1
    echo -e "\e[1;93m >> Su ID:\e[1;31m$idtele \e[1;93ma sido registrado"
    echo -e "\e[1;93m >> Su ID-GRUPO:\e[1;31m$idgrupo \e[1;93ma sido registrado"
    echo -e "\e[1;93m >> Nombre VPS:\e[1;31m$nomvps \e[1;93ma sido registrado"
    echo "$idtele" >/etc/SCRIPT-LATAM/temp/idtelegram
    echo "-100$idgrupo" >/etc/SCRIPT-LATAM/temp/idgrupo
    echo "$nomvps" >/etc/SCRIPT-LATAM/temp/vpstelegram
    msg -bar
  }
  del_noti() {
    echo -e "\033[1;37mREGISTRO DE NOTIBOT BORRADO \e[1;32m"
    echo "00000000" >/etc/SCRIPT-LATAM/temp/idtelegram
    echo "00000000" >/etc/SCRIPT-LATAM/temp/vpstelegram
    echo "00000000" >/etc/SCRIPT-LATAM/temp/idgrupo
    msg -bar
  }
  msg_test() {
    echo -e "\033[1;32m     SE ENVIO UN MESAJE DE PRUEBA AL BOT\n\e[1;93m              >> @Noty_LATAM_bot \e[1;32m"

    NOM=$(less /etc/SCRIPT-LATAM/temp/idtelegram) >/dev/null 2>&1
    ID=$(echo $NOM) >/dev/null 2>&1
    NOMG=$(less /etc/SCRIPT-LATAM/temp/idgrupo) >/dev/null 2>&1
    IDG=$(echo $NOMG) >/dev/null 2>&1
    NOM2=$(less /etc/SCRIPT-LATAM/temp/vpstelegram) >/dev/null 2>&1
    VPS=$(echo $NOM2) >/dev/null 2>&1
    KEY="5179637690:AAExt2gHMurxUmuJghfhghBCHg-D0Uzlt0rM"
    TIMEOUT="10"
    URL="https://api.telegram.org/bot$KEY/sendMessage"
    SONIDO="0"
    TEXTO="🟢 >>  MENSAJE DE PRUEBA EXITOSO <<\n ▫️ VPS: $VPS  "
    curl -s --max-time $TIMEOUT -d "parse_mode=Markdown&disable_notification=$SONIDO&chat_id=$ID&disable_web_page_preview=1&text=$(echo -e "$TEXTO")" $URL &>/dev/null
    echo "" &>/dev/null
    curl -s --max-time $TIMEOUT -d "parse_mode=Markdown&disable_notification=$SONIDO&chat_id=$IDG&disable_web_page_preview=1&text=$(echo -e "$TEXTO")" $URL &>/dev/null
    echo "" &>/dev/null
    msg -bar
  }
  clear && clear
  msg -bar
  msg -tit
  msg -bar
  echo -e "\033[1;93m                ACTIVAR NOTI-BOT"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m1\e[1;93m]\033[1;31m > \033[1;97m AGREGAR SU ID y NOMBRE DEL VPS\e[97m \n"
  echo -ne " \e[1;93m [\e[1;32m2\e[1;93m]\033[1;31m > \033[1;97m DESACTIVAR NOTIFICACIONES\e[97m \n"
  echo -ne " \e[1;93m [\e[1;32m3\e[1;93m]\033[1;31m > \033[1;97m EJECUTAR MENSAJE DE PRUEBA \e[97m \n"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m0\e[1;93m]\033[1;31m > \033[1;97m" && msg -bra "  \e[97m\033[1;41m VOLVER \033[1;37m"
  msg -bar
  echo -ne "\033[1;37mEscoja una Opcion: \e[1;31m" && read optons
  tput cuu1 && tput dl1

  case $optons in
  3)
    msg_test
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    noti_bot
    ;;
  2)
    del_noti
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    noti_bot
    ;;
  1)
    add_id
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    noti_bot
    ;;
  *)
    msg -bar
    herramientas_fun
    ;;
  esac

}

#--- TOKEN GENERAL
token_ge() {
  clear && clear
  msg -bar2
  msg -tit
  msg -bar2
  msg -ama "                CAMBIAR TOKEN GENERAL"
  msg -bar2
  echo -ne "\e[1;97mDIGITE SU NUEVO TOKEN GENERAL:\e[1;32m " && read passgeneral
  tput cuu1 && tput dl1
  echo -e "\e[1;97m Nuevo Token General:\e[1;32m $passgeneral"
  echo "$passgeneral" >/etc/SCRIPT-LATAM/temp/.passw
  msg -bar
  read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
  herramientas_fun
}

#--- RECUPERAR BASE DE USER
recuperar_base() {
  clear && clear
  msg -bar2
  msg -tit
  msg -bar2
  msg -ama "              RECUPERAR BASE DE USER"
  msg -bar2
  rm -rf /etc/SCRIPT-LATAM/backuplog/principal >/dev/null 2>&1
  i="1"
  [[ -z $(ls /etc/SCRIPT-LATAM/backuplog) ]] && echo -e "" || {
    for my_arqs in $(ls /etc/SCRIPT-LATAM/backuplog); do
      [[ -d "$my_arqs" ]] && continue
      select_arc[$i]="$my_arqs"
      echo -e "\e[1;93m [\e[1;92m$i\e[1;93m] \e[1;91m> \e[1;97m$my_arqs"
      let i++
    done
    i=$(($i - 1))
    msg -bar
    echo -e "\e[1;93m Seleccione el archivo"
    msg -bar
    # while [[ -z ${select_arc[$slct]} ]]; do
    read -p " [1-$i]: " slct
    tput cuu1 && tput dl1
    #done
    backselect="${select_arc[$slct]}"
    cd /etc/SCRIPT-LATAM/backuplog
    file="$backselect"
    tar -xzvf ./$file
    cat /etc/SCRIPT-LATAM/backuplog/principal/cuentassh >/etc/SCRIPT-LATAM/cuentassh
    cat /etc/SCRIPT-LATAM/backuplog/principal/cuentahwid >/etc/SCRIPT-LATAM/cuentahwid
    cat /etc/SCRIPT-LATAM/backuplog/principal/cuentatoken >/etc/SCRIPT-LATAM/cuentatoken
    cd
    msg -bar
    echo -e "\e[1;32m  >> Completado con Exito!"
  }
  msg -bar
  read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
  herramientas_fun

}

#--- CHEKER USER APKS
chekc_users() {
  clear && clear
  msg -bar2
  msg -tit
  msg -bar2
  msg -ama "                   CHECK USER APKS"
  msg -bar2
  verif_ptrs() {
    porta=$1
    PT=$(lsof -V -i tcp -P -n | grep -v "ESTABLISHED" | grep -v "COMMAND" | grep "LISTEN")
    for pton in $(echo -e "$PT" | cut -d: -f2 | cut -d' ' -f1 | uniq); do
      svcs=$(echo -e "$PT" | grep -w "$pton" | awk '{print $1}' | uniq)
      [[ "$porta" = "$pton" ]] && {
        echo -e "\n\033[1;31mPUERTO \033[1;33m$porta \033[1;31mEN USO PELO \033[1;37m$svcs\033[0m"
        sleep 3
        fun_initcheck
      }
    done
  }

  fun_bar() {
    comando[0]="$1"
    comando[1]="$2"
    (
      [[ -e $HOME/fim ]] && rm $HOME/fim
      ${comando[0]} >/dev/null 2>&1
      ${comando[1]} >/dev/null 2>&1
      touch $HOME/fim
    ) >/dev/null 2>&1 &
    tput civis
    echo -ne "\033[1;33m       ESPERE \033[1;37m- \033[1;33m["
    while true; do
      for ((i = 0; i < 18; i++)); do
        echo -ne "\033[1;31m#"
        sleep 0.1s
      done
      [[ -e $HOME/fim ]] && rm $HOME/fim && break
      echo -e "\033[1;33m]"
      sleep 1s
      tput cuu1
      tput dl1
      echo -ne "\033[1;33m       ESPERE \033[1;37m- \033[1;33m["
    done
    echo -e "\033[1;33m]\033[1;37m -\033[1;32m OK !\033[1;37m"
    tput cnorm
  }

  fun_initcheck() {

    var_sks1=$(ps x | grep "checkuser" | grep -v grep >/dev/null && echo -e "\033[1;32m [ ON ]" || echo -e "\033[1;31m [ OFF ] ")
    var_sks2=$(ps x | grep "4gcheck" | grep -v grep >/dev/null && echo -e "\033[1;32m   [ ON ]" || echo -e "\033[1;31m [ OFF ]")
    echo -e " \033[1;31m[\033[1;36m 1 \033[1;31m] \033[1;37m• \033[1;97mACTIVAR / DESACTIVAR (BASICO) $var_sks1 \033[0m"
    echo -e " \033[1;31m[\033[1;36m 2 \033[1;31m] \033[1;37m• \033[1;97mACTIVAR / DESACTIVAR (PLUS) $var_sks2 \033[0m"
    msg -bar2
    echo -e "    \e[97m\033[1;41m ENTER SIN RESPUESTA REGRESA A MENU ANTERIOR \033[0;37m"
    msg -bar2
    echo -ne "\033[1;97m  └⊳ Seleccione una Opcion:\033[1;33m "
    read resposta
    if [[ "$resposta" = '1' ]]; then
      if ps x | grep -w checkuser | grep -v grep 1>/dev/null 2>/dev/null; then
        for i in {1..3}; do tput cuu 1 && tput el; done
        echo ""
        echo -e "\E[1;92m                 CHECKUSER(BASICO)              \E[0m"
        echo ""
        fun_stopbad() {
          screen -r -S "checkuser" -X quit
          rm -rf /bin/check
          [[ $(grep -wc "check.py" /etc/autostart) != '0' ]] && {
            sed -i '/check.py/d' /etc/autostart
          }
          sleep 1
          screen -wipe >/dev/null
        }
        echo -e "           \033[1;91mDESACTIVANDO CHECKUSER(BASICO)\033[1;33m"
        fun_stopbad
        echo ""
        msg -bar
        read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
        herramientas_fun
      else
        for i in {1..3}; do tput cuu 1 && tput el; done
        echo ""
        echo -e "\e[48;5;40m\e[38;5;0m            ACTIVANDO CHECKUSER (BASICO)           \E[0m"
        echo ""
        echo -ne "\033[1;97mCUAL \033[1;91mPUERTO \033[1;32mDESEA ULTILIZAR \033[1;33m?\033[1;37m: "
        read porta
        [[ $porta != ?(+|-)+([0-9]) ]] && {
          echo ""
          echo -e "\033[1;31mPuerto Invalido!"
          sleep 3
          clear
          fun_initcheck
        }
        verif_ptrs $porta
        fun_check() {
          screen -dmS checkuser python3 /etc/SCRIPT-LATAM/filespy/check.py $porta 1
          [[ $(grep -wc "check.py" /etc/autostart) = '0' ]] && {
            echo -e "netstat -tlpn | grep -w $porta > /dev/null || {  screen -r -S 'ws' -X quit;  screen -dmS checkuser python3 /etc/SCRIPT-LATAM/filespy/check.py $porta 1; }" >>/etc/autostart
          } || {
            sed -i '/check.py/d' /etc/autostart
            echo -e "netstat -tlpn | grep -w $porta > /dev/null || {  screen -r -S 'ws' -X quit;  screen -dmS checkuser python3 /etc/SCRIPT-LATAM/filespy/check.py $porta 1; }" >>/etc/autostart
          }
          sleep 1
        }

        fun_check2() {
          screen -dmS checkuser python3 /etc/SCRIPT-LATAM/filespy/check.py $porta 2
          [[ $(grep -wc "check.py" /etc/autostart) = '0' ]] && {
            echo -e "netstat -tlpn | grep -w $porta > /dev/null || {  screen -r -S 'ws' -X quit;  screen -dmS checkuser python3 /etc/SCRIPT-LATAM/filespy/check.py $porta 2; }" >>/etc/autostart
          } || {
            sed -i '/check.py/d' /etc/autostart
            echo -e "netstat -tlpn | grep -w $porta > /dev/null || {  screen -r -S 'ws' -X quit;  screen -dmS checkuser python3 /etc/SCRIPT-LATAM/filespy/check.py $porta 2; }" >>/etc/autostart
          }
          sleep 1
        }
        echo ""
        echo -e "\033[1;97mSELECIONE TIPO DE FORMATO.\033[0m"
        echo ""
        echo -e "\033[1;31m[\033[1;36m1\033[1;31m] \033[1;37m• \033[1;33mFORMATO YYYY/MM/DD (MAS COMUN)\033[0m"
        echo -e "\033[1;31m[\033[1;36m2\033[1;31m] \033[1;37m• \033[1;33mFORMATO DD/MM/YYYY\033[0m"
        echo ""
        echo -ne "\033[1;36mOpcion: \033[1;37m"
        read resposta
        if [[ "$resposta" = '1' ]]; then
          echo ""
          fun_bar 'fun_check'
        elif [[ "$resposta" = '2' ]]; then
          echo ""
          fun_bar 'fun_check2'
        else
          echo ""
          echo -e "\033[1;31mOpcion Invalida !\033[0m"
          sleep 3
          fun_initcheck
        fi
        echo ""
        echo -e "\033[1;32m     CHECKUSER(BASICO) ACTIVADO CON EXITO\033[1;33m"
        echo ""
        echo -e "     URL: \033[1;97mhttp://$(meu_ip):$porta/checkUser"
        echo ""
        msg -bar
        read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
        herramientas_fun
      fi
    elif [[ "$resposta" = '2' ]]; then
      if ps x | grep -w 4gcheck | grep -v grep 1>/dev/null 2>/dev/null; then
        echo ""
        echo -e "\E[1;92m                  CHECKUSER(PLUS)              \E[0m"
        echo ""
        fun_stopbad() {
          screen -r -S "4gcheck" -X quit
          [[ $(grep -wc "4gcheck.py" /etc/autostart) != '0' ]] && {
            sed -i '/4gcheck.py/d' /etc/autostart
          }
          sleep 1
          screen -wipe >/dev/null
        }
        echo -e "           \033[1;91mDESACTIVANDO CHECKUSER(PLUS)\033[1;33m"
        fun_stopbad
        echo ""
        msg -bar
        read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
        herramientas_fun
      else
        echo ""
        echo -e "\e[48;5;40m\e[38;5;0m            ACTIVANDO CHECKUSER (PLUS)           \E[0m"
        echo ""
        echo -ne "\033[1;97mCUAL \033[1;91mPUERTO \033[1;32mDESEA ULTILIZAR \033[1;33m?\033[1;37m: "
        read porta
        [[ $porta != ?(+|-)+([0-9]) ]] && {
          echo ""
          echo -e "\033[1;31mPuerto Invalido!"
          sleep 3

          fun_initcheck
        }
        verif_ptrs $porta
        fun_udpon() {
          screen -dmS 4gcheck python3 /etc/SCRIPT-LATAM/filespy/4gcheck.py $porta
          [[ $(grep -wc "4gcheck.py" /etc/autostart) = '0' ]] && {
            echo -e "netstat -tlpn | grep -w $porta > /dev/null || {  screen -r -S 'ws' -X quit;  screen -dmS checkuser python3 /etc/SCRIPT-LATAM/filespy/4gcheck.py $porta; }" >>/etc/autostart
          } || {
            sed -i '/check.py/d' /etc/autostart
            echo -e "netstat -tlpn | grep -w $porta > /dev/null || {  screen -r -S 'ws' -X quit;  screen -dmS checkuser python3 /etc/SCRIPT-LATAM/filespy/4gcheck.py $porta; }" >>/etc/autostart
          }
          sleep 1
        }
        echo ""
        fun_bar 'fun_udpon'
        echo ""
        echo -e "\033[1;32m       CHECKUSER(PLUS) ACTIVADO CON EXITO\033[1;33m"
        echo ""
        echo -e "     URL: \033[1;97mhttp://$(meu_ip):$porta/checkUser"
        echo ""
        msg -bar
        read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
        herramientas_fun
      fi
      read -t 120 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'

      fun_initcheck
    fi
  }

  inst_depedencias() {
    # ehck installed pip3
    if ! [ -x "$(command -v pip3)" ]; then
      echo 'Error: pip3 no esta instalado.' >&2
      echo 'Instale pip3 .' >&2

      if ! apt-get install -y python3-pip; then
        echo 'Erro ao instalar pip3' >&2
        exit 1
      else
        echo 'Instalado pip3 con exito'
      fi
    fi

    # install flask
    apt install python -y >/dev/null 2>&1
    pip3 install flask >/dev/null 2>&1
    echo "by: @LATAM" >/usr/lib/licence
    mkdir -p /etc/rec
    echo "by: @LATAM" >/etc/rec/licence

    # download check.py
    [[ -e "/etc/SCRIPT-LATAM/filespy/check.py" ]] && {
      sleep 0.1
    } || {
      wget -O /etc/SCRIPT-LATAM/filespy/check.py https://raw.githubusercontent.com/NetVPS/LATAM_Oficial/main/Ejecutables/check.py &>/dev/null
      chmod +rwx /etc/SCRIPT-LATAM/filespy/check.py
    }

    [[ -e "/etc/SCRIPT-LATAM/filespy/4gcheck.py" ]] && {
      sleep 0.1
    } || {
      wget -O /etc/SCRIPT-LATAM/filespy/4gcheck.py https://raw.githubusercontent.com/NetVPS/LATAM_Oficial/main/Ejecutables/4gcheck.py &>/dev/null
      chmod +rwx /etc/SCRIPT-LATAM/filespy/4gcheck.py
    }

    [[ -e "/bin/check" ]] && {
      sleep 0.1
    } || {
      wget -O /bin/check https://raw.githubusercontent.com/NetVPS/LATAM_Oficial/main/Ejecutables/check &>/dev/null
      chmod 777 /bin/check
    }
  }

  [[ -e "/etc/SCRIPT-LATAM/filespy/check.py" ]] && [[ -e "/etc/SCRIPT-LATAM/filespy/4gcheck.py" ]] && [[ -e "/bin/check" ]] && {
    fun_initcheck
  } || {

    echo -e "\n\033[1;97m     SE INSTALARA EL WEBHOOK  DE APK PERSONALES \033[0m"
    echo ""
    echo -ne "\033[1;32m     Proceder con la Instalacion ? \033[1;33m[\033[1;97ms \033[1;37m/ n\033[1;33m]:\033[1;32m "
    read resposta
    [[ "$resposta" = 's' ]] && {
      echo -e "\n\033[1;32m                 Instalando CHECKUSER"
      echo ""
      fun_bar 'inst_depedencias'
      fun_initcheck
    } || {
      msg -bar
      read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      herramientas_fun
    }
  }

  msg -bar
  read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
  herramientas_fun

}
chekc_online() {
  ##-->> DESCARGAR ARHIVO
  if [ -e "/etc/SCRIPT-LATAM/chekerapp/onlineapp.sh" ]; then
    clear && clear
    msg -bar2
    msg -tit
    msg -bar2
    msg -ama "               CHEKER ONLINES APKS"
    msg -bar2
    echo -e "\033[1;97m            ELIMINANDO ONLINES APKS \033[0m"
    rm -rf /etc/SCRIPT-LATAM/chekerapp/onlineapp.sh
    service apache2 stop &>/dev/null
    sed -i '/\/etc\/SCRIPT-LATAM\/chekerapp\/onlineapp\.sh/d' /etc/crontab

    service cron reload &>/dev/null
  else
    clear && clear
    msg -bar2
    msg -tit
    msg -bar2
    msg -ama "               CHEKER ONLINES APKS"
    msg -bar2
    echo -e "\033[1;97m     SE INSTALARAN LOS PAQUETES CORRESPONDIENTES \033[0m"
    apt-get update &>/dev/null
    apt-get install apache2 -y &>/dev/null
    fun_bar "apt-get install apache2 -y &>/dev/null "
    sed -i 's/Listen 80/Listen 8888/' /etc/apache2/ports.conf
    sed -i 's/:80>/:8888>/' /etc/apache2/sites-available/000-default.conf
    service apache2 restart &>/dev/null
    mkdir -p /var/www/html/server
    mkdir -p /etc/SCRIPT-LATAM/chekerapp
    wget -O /etc/SCRIPT-LATAM/chekerapp/onlineapp.sh https://raw.githubusercontent.com/NT-GIT-HUB/StatusServer/main/onlineapp.sh &>/dev/null
    chmod +rwx /etc/SCRIPT-LATAM/chekerapp/onlineapp.sh
    /etc/SCRIPT-LATAM/chekerapp/onlineapp.sh &>/dev/null
    agregar_tarea_cron() {
      local script="/etc/SCRIPT-LATAM/chekerapp/onlineapp.sh"
      local tarea="*/1 * * * * root /bin/bash ${script}"
      echo "${tarea}" >>/etc/crontab
    }
    agregar_tarea_cron
    service cron reload &>/dev/null
    ufw allow 8888/tcp &>/dev/null
    check_apache_port() {
      if netstat -tln | grep -q :8888; then
        echo ""
        echo -e "\n\033[1;32m             CHECK ONLINES STATUS \033[1;32m ON \033[1;33m"
      else
        echo ""
        echo -e "\n\033[1;32m             CHECK ONLINES STATUS \033[1;31mOFF \033[1;33m"
      fi
    }
    check_apache_port
    echo -e "  URL: \033[1;97mhttp://$(meu_ip):8888:/server/online"

  fi
  msg -bar
  read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
  herramientas_fun
}

#---FUNCION HERRAMIENTAS
herramientas_fun() {
  clear && clear
  tput cuu1 && tput dl1
  msg -bar2
  msg -tit
  msg -bar2
  msg -ama "                MENU DE HERRAMIENTAS"
  msg -bar2
  var_sks1=$(ps x | grep "checkuser" | grep -v grep >/dev/null && echo -e "\033[1;32m ON BASICO" || echo -e "\033[1;31mOFF BASICO")
  var_sks2=$(ps x | grep "4gcheck" | grep -v grep >/dev/null && echo -e "\033[1;32mON PLUS" || echo -e "\033[1;31mOFF PLUS ")
  chonlines=$(netstat -tln | grep -q :8888 >/dev/null && echo -e "\033[1;32m ON " || echo -e "\033[1;31mOFF")

  local Numb=1
  echo -e " \e[1;93m[\e[1;32m$Numb\e[1;93m]\033[1;31m >\033[1;97m GESTOR DE CUENTAS VIA BOT TELEGRAM "
  script[$Numb]="LATAMbot.sh"
  let Numb++
  echo -e " \e[1;93m[\e[1;32m$Numb\e[1;93m]\033[1;31m >\033[1;97m FIX BASE DE USER      "
  script[$Numb]="fixbaseuser"
  let Numb++
  echo -e " \e[1;93m[\e[1;32m$Numb\e[1;93m]\033[1;31m >\033[1;97m CHECK USER APK [ $var_sks1 \033[1;97m| $var_sks2\033[1;97m]     "
  script[$Numb]="chekcusers"
  let Numb++
  echo -e " \e[1;93m[\e[1;32m$Numb\e[1;93m]\033[1;31m >\033[1;97m CHECK ONLINES APK [ $chonlines \033[1;97m]     "
  script[$Numb]="checkonlines"
  #echo -e "\033[1;93m--------------------OPTIMIZADORES-------------------"
  echo -e "\033[1;93m--------------------- EXTRAS -----------------------"
  let Numb++
  echo -ne " \e[1;93m[\e[1;32m$Numb\e[1;93m]\033[1;31m >\033[1;97m ALERTAS NOTY-BOT      "
  script[$Numb]="notibot"
  let Numb++
  echo -ne " \e[1;93m[\e[1;32m$Numb\e[1;93m]\033[1;31m >\033[1;97m FTP X APACHE\n"
  script[$Numb]="ftpapache"
  let Numb++
  echo -ne " \e[1;93m[\e[1;32m$Numb\e[1;93m]\033[1;31m >\033[1;97m ACTIVAR (BBR/PLUS)    "
  script[$Numb]="bbr"
  let Numb++
  echo -ne " \e[1;93m[\e[1;32m$Numb\e[1;93m]\033[1;31m >\033[1;97m TOKEN GENERAL\n"
  script[$Numb]="tokengeneral"
  echo -e "\033[1;93m-------------------- SEGURIDAD ---------------------"
  let Numb++
  echo -ne " \e[1;93m[\e[1;32m$Numb\e[1;93m]\033[1;31m >\033[1;97m FAIL2BAN PROTECION    "
  script[$Numb]="fai2ban"
  let Numb++
  echo -e " \e[1;93m[\e[1;32m$Numb\e[1;93m]\033[1;31m >\033[1;97m PASS PROXY SQUID  "
  script[$Numb]="passsquid"
  echo -e "\033[1;93m------------------ AJUSTES DEL VPS -----------------"
  let Numb++
  echo -ne " \e[1;93m[\e[1;32m$Numb\e[1;93m]\033[1;31m >\033[1;97m AJUSTES INTERNOS      "
  script[$Numb]="ajustein"
  let Numb++
  echo -e "\e[1;93m[\e[1;32m$Numb\e[1;93m]\033[1;31m >\033[1;97m HORARIO LOCAL      "
  script[$Numb]="horalocal"
  let Numb++
  echo -ne " \e[1;93m[\e[1;32m$Numb\e[1;93m]\033[1;31m >\033[1;97m AGREGAR DNS UNLOCK'S  "
  script[$Numb]="dnsunlock"
  let Numb++
  echo -e "\e[1;93m[\e[1;32m$Numb\e[1;93m]\033[1;31m >\033[1;97m SPEED TEST VPS      "
  script[$Numb]="speed"
  echo -e "\033[1;93m----------------------------------------------------"
  let Numb++
  echo -e " \e[1;93m[\e[1;32m$Numb\e[1;93m]\033[1;31m >\033[1;96m  - - - >> DETALLES DE SISTEMA << - - - - - "
  script[$Numb]="systeminf"
  msg -bar
  echo -e "    \e[97m\033[1;41m ENTER SIN RESPUESTA REGRESA A MENU ANTERIOR \033[0;97m"
  script[0]="voltar"
  msg -bar2
  selection=$(selection_fun $Numb)
  [[ -e "${SCPfrm}/${script[$selection]}" ]] && {
    ${SCPfrm}/${script[$selection]}
  } || {
    case ${script[$selection]} in
    #"agregar")agregar_ferramenta;;
    "speed") speed_test ;;
    "limpar") limpar_caches ;;
    "systeminf") systen_info ;;
    "horalocal") hora_local ;;
    "ajustein") ajuste_in ;;
    "dnsunlock") dns_unlock ;;
    "bbr") bbr_fun ;;
    "passsquid") pass_squid ;;
    "fai2ban") fai2ban_fun ;;
    "ftpapache") ftp_apache ;;
    "notibot") noti_bot ;;
    "tokengeneral") token_ge ;;
    "fixbaseuser") recuperar_base ;;
    "chekcusers") chekc_users ;;
    "checkonlines") chekc_online ;;
    *) menu ;;
    esac
  }
  exit 0
}

#--- MONITOR PID DE PROTOCOLOS
pid_inst() {
  [[ $1 = "" ]] && echo -e "\033[1;31m[ OFF ]" && return 0
  unset portas
  portas_var=$(lsof -V -i -P -n | grep -v "ESTABLISHED" | grep -v "COMMAND")
  i=0
  while read port; do
    var1=$(echo $port | awk '{print $1}') && var2=$(echo $port | awk '{print $9}' | awk -F ":" '{print $2}')
    [[ "$(echo -e ${portas[@]} | grep "$var1 $var2")" ]] || {
      portas[$i]="$var1 $var2\n"
      let i++
    }
  done <<<"$portas_var"
  [[ $(echo "${portas[@]}" | grep "$1") ]] && echo -e "\033[1;32m[ON]" || echo -e "\033[1;31m[ OFF ]"
}

# MENU FLUTUANTE
menu_func() {
  local options=${#@}
  local array
  for ((num = 1; num <= $options; num++)); do
    echo -ne "  $(msg -verd "[$num]") $(msg -verm2 "=>>") "
    array=(${!num})
    case ${array[0]} in
    "-vd") msg -verd "\033[1;33m[!]\033[1;32m ${array[@]:1}" | sed ':a;N;$!ba;s/\n/ /g' ;;
    "-vm") msg -verm2 "\033[1;33m[!]\033[1;31m ${array[@]:1}" | sed ':a;N;$!ba;s/\n/ /g' ;;
    "-fi") msg -azu "${array[@]:2} ${array[1]}" | sed ':a;N;$!ba;s/\n/ /g' ;;
    *) msg -azu "${array[@]}" | sed ':a;N;$!ba;s/\n/ /g' ;;
    esac
  done
}

#--- MONITOR DE PROTOCOLOS AUTO
monservi_fun() {
  clear && clear
  #AUTO INICIAR
  automprotos() {
    echo '#!/bin/sh -e' >/etc/rc.local
    sudo chmod +x /etc/rc.local
    echo "sudo rebootnb reboot" >>/etc/rc.local
    echo "sudo rebootnb resetprotos" >>/etc/rc.local
  }
  autobadvpn() {
    echo "sudo rebootnb resetbadvpn" >>/etc/rc.local
  }
  autowebsoket() {
    echo "sudo rebootnb resetwebsocket" >>/etc/rc.local
  }
  autolimitador() {
    echo "sudo rebootnb resetlimitador" >>/etc/rc.local
  }
  autodesbloqueador() {
    echo "sudo rebootnb resetdesbloqueador" >>/etc/rc.local
  }
  #MONITOREAR
  monssh() {
    echo "resetssh" >/etc/SCRIPT-LATAM/temp/monitorpt
  }
  mondropbear() {
    echo "resetdropbear" >>/etc/SCRIPT-LATAM/temp/monitorpt
  }
  monssl() {
    echo "resetssl" >>/etc/SCRIPT-LATAM/temp/monitorpt
  }
  monsquid() {
    echo "resetsquid" >>/etc/SCRIPT-LATAM/temp/monitorpt
  }
  monapache() {
    echo "resetapache" >>/etc/SCRIPT-LATAM/temp/monitorpt
  }
  monv2ray() {
    echo "resetv2ray" >>/etc/SCRIPT-LATAM/temp/monitorpt
  }
  monwebsoket() {
    echo "resetwebp" >>/etc/SCRIPT-LATAM/temp/monitorpt
  }
  msg -bar
  msg -tit
  msg -bar
  echo -e "\033[1;93m          MONITOR DE SERVICIONS PRINCIPALES"
  msg -bar
  #AUTO INICIOS
  PIDVRF3="$(ps aux | grep "monitorproto" | grep -v grep | awk '{print $2}')"
  if [[ -z $PIDVRF3 ]]; then
    echo -e "\e[1;32m >>> AUTO INICIOS"
    echo -ne "\e[1;96m # Iniciar M-PROTOCOLOS ante reboot\e[1;93m [\033[1;97m s \033[1;93m| \033[1;97mn \033[1;93m]\033[1;97m: \e[1;32m" && read automprotos
    echo '#!/bin/sh -e' >/etc/rc.local
    sudo chmod +x /etc/rc.local
    echo "sudo rebootnb reboot" >>/etc/rc.local
    [[ "$automprotos" = "s" || "$automprotos" = "S" ]] && automprotos
    echo -ne "\e[1;97m Iniciar BADVPN ante reboot\e[1;93m ....... [\033[1;97m s \033[1;93m| \033[1;97mn \033[1;93m]\033[1;97m: \e[1;32m" && read autobadvpn
    [[ "$autobadvpn" = "s" || "$autobadvpn" = "S" ]] && autobadvpn
    echo -ne "\e[1;97m Iniciar PROXY-WEBSOKET ante reboot\e[1;93m [\033[1;97m s \033[1;93m| \033[1;97mn \033[1;93m]\033[1;97m: \e[1;32m" && read autowebsoket
    [[ "$autowebsoket" = "s" || "$autowebsoket" = "S" ]] && autowebsoket
    echo -ne "\e[1;97m Iniciar LIMITADOR ante reboot\e[1;93m .... [\033[1;97m s \033[1;93m| \033[1;97mn \033[1;93m]\033[1;97m: \e[1;32m" && read autolimitador
    [[ "$autolimitador" = "s" || "$autolimitador" = "S" ]] && autolimitador
    echo -ne "\e[1;97m Iniciar DESBLOQUEADOR ante reboot\e[1;93m  [\033[1;97m s \033[1;93m| \033[1;97mn \033[1;93m]\033[1;97m: \e[1;32m" && read autodesbloqueador
    [[ "$autodesbloqueador" = "s" || "$autodesbloqueador" = "S" ]] && autodesbloqueador
    echo "sleep 2s" >>/etc/rc.local
    echo "exit 0" >>/etc/rc.local
    msg -bar
    echo -e "\e[1;32m >>> MONITOR DE PROTOCOLOS"
    echo -ne "\e[1;97m Monitorear SSH\e[1;93m ................... [\033[1;97m s \033[1;93m| \033[1;97mn \033[1;93m]\033[1;97m: \e[1;32m" && read monssh
    echo "null" >/etc/SCRIPT-LATAM/temp/monitorpt
    [[ "$monssh" = "s" || "$monssh" = "S" ]] && monssh
    echo -ne "\e[1;97m Monitorear DROPBEAR\e[1;93m .............. [\033[1;97m s \033[1;93m| \033[1;97mn \033[1;93m]\033[1;97m: \e[1;32m" && read mondropbear
    [[ "$mondropbear" = "s" || "$mondropbear" = "S" ]] && mondropbear
    echo -ne "\e[1;97m Monitorear SSL\e[1;93m ................... [\033[1;97m s \033[1;93m| \033[1;97mn \033[1;93m]\033[1;97m: \e[1;32m" && read monssl
    [[ "$monssl" = "s" || "$monssl" = "S" ]] && monssl
    echo -ne "\e[1;97m Monitorear SQUID\e[1;93m ................. [\033[1;97m s \033[1;93m| \033[1;97mn \033[1;93m]\033[1;97m: \e[1;32m" && read monsquid
    [[ "$monsquid" = "s" || "$monsquid" = "S" ]] && monsquid
    echo -ne "\e[1;97m Monitorear APACHE\e[1;93m ................ [\033[1;97m s \033[1;93m| \033[1;97mn \033[1;93m]\033[1;97m: \e[1;32m" && read monapache
    [[ "$monapache" = "s" || "$monapache" = "S" ]] && monapache
    echo -ne "\e[1;97m Monitorear V2RAY\e[1;93m ................. [\033[1;97m s \033[1;93m| \033[1;97mn \033[1;93m]\033[1;97m: \e[1;32m" && read monv2ray
    [[ "$monv2ray" = "s" || "$monv2ray" = "S" ]] && monv2ray
    echo -ne "\e[1;97m Monitorear PROXY WEBSOCKET\e[1;93m ....... [\033[1;97m s \033[1;93m| \033[1;97mn \033[1;93m]\033[1;97m: \e[1;32m" && read monwebsoket
    [[ "$monwebsoket" = "s" || "$monwebsoket" = "S" ]] && monwebsoket
    msg -bar
    echo -ne "\033[1;96m   ¿Cada cuantos segundos ejecutar el Monitor?\n\033[1;97m  +Segundos = -Uso de CPU | -Segundos = +Uso de CPU\033[0;92m \n                Predeterminado:\033[1;37m 120s\n     Cuantos Segundos (Numeros Unicamente): " && read tiemmoni
    error() {
      msg -verm "Tiempo invalido,se ajustara a 120s (Tiempo por Defeto)"
      sleep 5s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      tiemmoni="120"
      echo "${tiemmoni}" >/etc/SCRIPT-LATAM/temp/T-Mon

    }
    #[[ -z "$tiemmoni" ]] && tiemmoni="120"
    if [[ "$tiemmoni" != +([0-9]) ]]; then
      error
    fi
    [[ -z "$tiemmoni" ]] && tiemmoni="120"
    if [ "$tiemmoni" -lt "120" ]; then
      error
    fi
    echo "${tiemmoni}" >/etc/SCRIPT-LATAM/temp/T-Mon
    screen -dmS monitorproto watch -n $tiemmoni /etc/SCRIPT-LATAM/menu.sh "monitorservi"
  else
    for pid in $(echo $PIDVRF3); do
      screen -S monitorproto -p 0 -X quit
      rm -rf /etc/rc.local >/dev/null 2>&1
    done
  fi
  [[ -z ${VERY3} ]] && monitorservi="\033[1;32m ACTIVADO " || monitorservi="\033[1;31m DESACTIVADO "
  echo -e "            $monitorservi  --  CON EXITO"
  msg -bar
}

#--- EJECUTOR MOTITOR DE PROTOCOLOS
monitor_auto() {
  for servicex in $(cat /etc/SCRIPT-LATAM/temp/monitorpt); do
    rebootnb $servicex
  done
}

#--- ACTIVADOR MOTITOR DE PROTOCOLOS
if [[ "$1" = "monitorservi" ]]; then
  monitor_auto
  exit
fi

#--- FUNCION AUTO LIMPIEZA Y FRESH RAM
autolimpieza_fun() {
  clear
  clear
  msg -bar
  msg -tit
  msg -bar
  echo -e "\033[1;32m                 AUTO MANTENIMIENTO"
  PIDVRF4="$(ps aux | grep "autolimpieza" | grep -v grep | awk '{print $2}')"
  if [[ -z $PIDVRF4 ]]; then
    msg -bar
    echo ""
    echo -e "\033[1;93m ----- Se procedera cada 12 hrs a"
    echo ""
    echo -e "\033[97m >> Actulizar Paquetes"
    echo -e "\033[97m >> Remover Paquetes Obsoletos"
    echo -e "\033[97m >> Se Limpiara Cache sys/temp "
    echo -e "\033[97m >> Se Refrescara RAM"
    echo -e "\033[97m >> Se Refrescara SWAP"
    echo -e "\033[97m >> Limpieza de VRAM de v2ray (Si esta Activo)"
    echo ""
    screen -dmS autolimpieza watch -n 43200 /etc/SCRIPT-LATAM/menu.sh "autolim"
  else
    screen -S autolimpieza -p 0 -X quit
  fi
  msg -bar
  [[ -z ${VERY4} ]] && autolim="\033[1;32m ACTIVADO " || autolim="\033[1;31m DESACTIVADO "
  echo -e "            $autolim  --  CON EXITO"
  msg -bar
  read -t 120 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
}

#--- EJECUTOR AUTOLIMPIEZA
autolim_fun() {
  clear && clear
  apt-get update
  apt-get upgrade -y
  dpkg --configure -a
  apt -f install -y
  apt-get autoremove -y
  apt-get clean -y
  apt-get autoclean -y
  sync
  echo 1 >/proc/sys/vm/drop_caches
  sync
  echo 2 >/proc/sys/vm/drop_caches
  sync
  echo 3 >/proc/sys/vm/drop_caches
  swapoff -a && swapon -a
  v2ray clean
}

#--- ACTIVADOR AUTOLIMPIEZA
if [[ "$1" = "autolim" ]]; then
  autolim_fun
  exit
fi

#############

#--- CREDITOS Y TERMINOS DE USO
creditoss() {
  clear && clear
  msg -bar
  msg -tit
  msg -bar
  echo -ne " \033[1;93m          CREDITOS Y REGISTRO DE CAMBIOS\n"
  msg -bar
  [[ -e ${SCPdir}/message.txt ]] && echo -e "\033[1;97m RESELLER AUTORIZADO: \n\033[1;96m $(cat ${SCPdir}/message.txt) "
  [[ -e ${SCPdir}/key.txt ]] && echo -e "\033[1;97m KEY DE REGISTRO:\n \033[1;93m $(cat ${SCPdir}/key.txt)"
  [[ -e ${SCPdir}/F-Instalacion ]] && echo -e "\033[1;97m ACTIVACION:\n \033[1;92m $(cat ${SCPdir}/F-Instalacion)"
  msg -bar
  echo -ne "\033[1;97m            \e[100m CAMBIOS DE SCRIPT LATAM \e[0;97m \n"
  registro=$(curl -sSL "https://raw.githubusercontent.com/NetVPS/LATAM_Oficial/main/cambios")
  echo -ne "$registro"
  msg -bar
  echo -e "  \e[48;5;1m\e[38;5;15m          ❗️ ⚠️  LATAM SE DESLINDA ⚠️ ❗️            \e[0;97m\n"
  echo -e "\033[1;33m >> Del mal uso a este panel VPN"
  echo -e "\033[1;33m >> El uso indebido a redes de Terceros "
  echo -e "\033[1;33m >> Del mal uso al Hosting y Bloqueo del mismo  "
  echo -e "\033[1;33m >> Abusar de las VPN con redes de Terceros \n"
  msg -bar
  read -t 120 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
}

#--- INSTALAR DROPBEAR
proto_dropbear() {
  activar_dropbear() {

    mportas() {
      unset portas
      portas_var=$(lsof -V -i tcp -P -n | grep -v "ESTABLISHED" | grep -v "COMMAND" | grep "LISTEN")
      while read port; do
        var1=$(echo $port | awk '{print $1}') && var2=$(echo $port | awk '{print $9}' | awk -F ":" '{print $2}')
        [[ "$(echo -e $portas | grep "$var1 $var2")" ]] || portas+="$var1 $var2\n"
      done <<<"$portas_var"
      i=1
      echo -e "$portas"
    }
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    echo -e "\033[1;93m         INSTALADOR DROPBEAR | SCRIPT LATAM"
    msg -bar
    echo -e "\033[1;97m Puede activar varios puertos en orden secuencial\n Ejemplo: \033[1;32m 442 443 444\033[1;37m"
    msg -bar
    echo -ne "\033[1;97m Digite  Puertos:\033[1;32m" && read -p " " -e -i "444 445" DPORT
    tput cuu1 && tput dl1
    TTOTAL2=($DPORT)
    for ((i = 0; i < ${#TTOTAL2[@]}; i++)); do
      [[ $(mportas | grep "${TTOTAL2[$i]}") = "" ]] && {
        echo -e "\033[1;33m Puerto Elegido:\033[1;32m ${TTOTAL2[$i]} OK"
        PORT2="$PORT2 ${TTOTAL2[$i]}"
      } || {
        echo -e "\033[1;33m Puerto Elegido:\033[1;31m ${TTOTAL2[$i]} FAIL"
      }
    done
    [[ -z $PORT2 ]] && {
      echo -e "\033[1;31m Ningun Puerto Valido Fue Elegido\033[0m"
      return 1
    }

    msg -bar
    echo -e "\033[1;97m Revisando Actualizaciones"
    fun_bar "apt update; apt upgrade -y > /dev/null 2>&1"
    echo -e "\033[1;97m Instalando Dropbear"
    fun_bar "apt-get install dropbear -y > /dev/null 2>&1"
    apt-get install dropbear -y >/dev/null 2>&1
    touch /etc/dropbear/banner
    msg -bar
    cat <<EOF >/etc/default/dropbear
NO_START=0
DROPBEAR_EXTRA_ARGS="VAR"
DROPBEAR_BANNER="/etc/dropbear/banner"
DROPBEAR_RECEIVE_WINDOW=65536
EOF

    for dpts in $(echo $PORT2); do
      sed -i "s/VAR/-p $dpts VAR/g" /etc/default/dropbear
    done
    sed -i "s/VAR//g" /etc/default/dropbear
    [[ ! $(cat /etc/shells | grep "/bin/false") ]] && echo -e "/bin/false" >>/etc/shells
    dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key >/dev/null 2>&1
    dropbearkey -t dss -f /etc/dropbear/dropbear_dss_host_key >/dev/null 2>&1
    service ssh restart >/dev/null 2>&1
    sed -i "s/=1/=0/g" /etc/default/dropbear
    service dropbear restart
    sed -i "s/=0/=1/g" /etc/default/dropbear
    sleep 3s
    echo -e "\033[1;92m        >> DROPBEAR INSTALADO CON EXITO <<"
    msg -bar
    #UFW
    # for ufww in $(mportas | awk '{print $2}'); do
    #   ufw allow $ufww >/dev/null 2>&1
    # done

  }

  desactivar_dropbear() {
    clear && clear
    msg -bar
    echo -e "\033[1;91m              DESINSTALANDO DROPBEAR"
    msg -bar
    service dropbear stop >/dev/null 2>&1
    fun_bar "apt-get remove dropbear -y"
    killall dropbear >/dev/null 2>&1
    rm -rf /etc/dropbear/* >/dev/null 2>&1
    msg -bar
    echo -e "\033[1;32m             DROPBEAR DESINSTALADO EXITO"
    msg -bar
    [[ -e /etc/default/dropbear ]] && rm /etc/default/dropbear
  }

  clear && clear
  msg -bar
  msg -tit
  msg -bar
  echo -e "\033[1;93m         INSTALADOR DROPBEAR | SCRIPT LATAM"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;97m INSTALAR UN DROPBEAR \e[97m \n"
  echo -ne " \e[1;93m [\e[1;32m2\e[1;93m]\033[1;31m > \033[1;97m DETENER TODOS LOS DROPBEAR\e[97m \n"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m0\e[1;93m]\033[1;31m > \033[1;97m" && msg -bra "  \e[97m\033[1;41m VOLVER \033[1;37m"
  msg -bar
  echo -ne "\033[1;97mDigite solo el numero segun su respuesta:\e[32m "
  read opcao
  case $opcao in
  1)
    msg -bar
    activar_dropbear
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    ;;
  2)
    msg -bar
    desactivar_dropbear
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    ;;

  esac
  menu_inst

}

#--- INSTALAR SSL
proto_ssl() {
  clear
  clear
  declare -A cor=([0]="\033[1;37m" [1]="\033[1;34m" [2]="\033[1;31m" [3]="\033[1;33m" [4]="\033[1;32m")
  mportas() {
    unset portas
    portas_var=$(lsof -V -i tcp -P -n | grep -v "ESTABLISHED" | grep -v "COMMAND" | grep "LISTEN")
    while read port; do
      var1=$(echo $port | awk '{print $1}') && var2=$(echo $port | awk '{print $9}' | awk -F ":" '{print $2}')
      [[ "$(echo -e $portas | grep "$var1 $var2")" ]] || portas+="$var1 $var2\n"
    done <<<"$portas_var"
    i=1
    echo -e "$portas"
  }
  ssl_stunel() {
    clear
    clear
    [[ $(mportas | grep stunnel4 | head -1) ]] && {
      msg -bar
      echo -e "\033[1;31m                 DESINSTALANDO SSL"
      msg -bar
      service stunnel4 stop >/dev/null 2>&1
      fun_bar "apt-get purge  stunnel4 -y"
      msg -bar
      echo -e "\033[1;32m        >> SSL DESINSTALADO  CON EXITO <<"
      msg -bar
      return 0
    }
    msg -bar
    msg -tit
    msg -bar
    echo -e "\033[1;93m             INSTALADOR SSL SCRIPT LATAM"
    msg -bar
    echo -e "\033[1;97m Seleccione un puerto de anclaje."
    echo -e "\033[1;97m Puede ser un SSH/DROPBEAR/SQUID/OPENVPN/WEBSOCKET"
    msg -bar
    while true; do
      echo -ne "\033[1;97m Puerto-Local:\033[1;32m" && read -p " " -e -i "22" portx
      if [[ ! -z $portx ]]; then
        if [[ $(echo $portx | grep "[0-9]") ]]; then
          [[ $(mportas | grep $portx | awk '{print $2}' | head -1) ]] && break || echo -e "\033[1;31m Puerto Invalido - Reintente con otro Activo"
        fi
      fi
    done
    msg -bar
    DPORT="$(mportas | grep $portx | awk '{print $2}' | head -1)"
    echo -e "\033[1;33m             Ahora Que Puerto sera SSL"
    msg -bar
    while true; do
      echo -ne "\033[1;97m Puerto para SSL:\033[1;32m" && read -p " " -e -i "443" SSLPORT
      [[ $(mportas | grep -w "$SSLPORT") ]] || break
      echo -e "\033[1;33m Este Puerto esta en Uso"
      unset SSLPORT
    done
    msg -bar
    echo -e "\033[1;32m                 Instalando SSL"
    msg -bar
    fun_bar "apt-get install stunnel4 -y"
    apt-get install stunnel4 -y >/dev/null 2>&1
    msg -bar
    echo -e "\033[1;97m A continuacion se le pediran datos de su crt si\n desconoce que datos lleva presione puro ENTER"
    msg -bar
    sleep 5s
    echo -e "client = no\n[SSL]\ncert = /etc/stunnel/stunnel.pem\naccept = ${SSLPORT}\nconnect = 127.0.0.1:${portx}" >/etc/stunnel/stunnel.conf
    ####Coreccion2.0#####
    openssl genrsa -out stunnel.key 2048 >/dev/null 2>&1
    # (echo "mx" ; echo "mx" ; echo "mx" ; echo "mx" ; echo "mx" ; echo "mx" ; echo "@vpsmx" )|openssl req -new -key stunnel.key -x509 -days 1000 -out stunnel.crt > /dev/null 2>&1
    openssl req -new -key stunnel.key -x509 -days 1000 -out stunnel.crt
    cat stunnel.crt stunnel.key >stunnel.pem
    mv stunnel.pem /etc/stunnel/
    ##-->> AutoInicio
    sed -i '/ENABLED=[01]/d' /etc/default/stunnel4
    echo "ENABLED=1" >>/etc/default/stunnel4
    service stunnel4 restart >/dev/null 2>&1
    msg -bar
    echo -e "\033[1;32m          >> SSL INSTALADO CON EXITO <<"
    msg -bar
    rm -rf /etc/SCRIPT-LATAM/stunnel.crt >/dev/null 2>&1
    rm -rf /etc/SCRIPT-LATAM/stunnel.key >/dev/null 2>&1
    rm -rf /root/stunnel.crt >/dev/null 2>&1
    rm -rf /root/stunnel.key >/dev/null 2>&1
    return 0
  }
  ssl_stunel_2() {
    clear
    clear
    msg -bar
    msg -tit
    msg -bar
    echo -e "\033[1;93m              AGREGAR MAS PUESRTOS SSL"
    msg -bar
    echo -e "\033[1;97m Seleccione un puerto de anclaje."
    echo -e "\033[1;97m Puede ser un SSH/DROPBEAR/SQUID/OPENVPN/SSL/PY"
    msg -bar
    while true; do
      echo -ne "\033[1;97m Puerto-Local: \033[1;32m" && read portx
      if [[ ! -z $portx ]]; then
        if [[ $(echo $portx | grep "[0-9]") ]]; then
          [[ $(mportas | grep $portx | head -1) ]] && break || echo -e "\033[1;31m Puerto Invalido - Reintente con otro Activo"
        fi
      fi
    done
    msg -bar
    DPORT="$(mportas | grep $portx | awk '{print $2}' | head -1)"
    echo -e "\033[1;33m             Ahora Que Puerto sera SSL"
    msg -bar
    while true; do
      echo -ne "\033[97m Puerto-SSL: \033[1;32m" && read SSLPORT
      [[ $(mportas | grep -w "$SSLPORT") ]] || break
      echo -e "\033[1;33m Este Puerto esta en Uso"
      unset SSLPORT
    done
    msg -bar
    echo -e "client = no\n[SSL+]\ncert = /etc/stunnel/stunnel.pem\naccept = ${SSLPORT}\nconnect = 127.0.0.1:${portx}" >>/etc/stunnel/stunnel.conf
    ##-->> AutoInicio
    sed -i '/ENABLED=[01]/d' /etc/default/stunnel4
    echo "ENABLED=1" >>/etc/default/stunnel4
    service stunnel4 restart >/dev/null 2>&1
    echo -e "\033[1;32m            PUERTO AGREGADO CON EXITO"
    msg -bar
    rm -rf /etc/SCRIPT-LATAM/stunnel.crt >/dev/null 2>&1
    rm -rf /etc/SCRIPT-LATAM/stunnel.key >/dev/null 2>&1
    rm -rf /root/stunnel.crt >/dev/null 2>&1
    rm -rf /root/stunnel.key >/dev/null 2>&1
    return 0
  }
  cert_ssl() {
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    echo -e "\033[1;93m             AGREGAR CERTIFICADO MANUAL"
    msg -bar
    echo -e "\033[1;97m Tenga ya su SSL activo y configurado Previamente"
    echo -e "\033[1;93m >> Suba su certificado en zip a Dropbox"
    msg -bar
    echo -ne "\033[1;97m Pegue el link Abajo:\e[1;96m\n  " && read linkd
    wget $linkd -O /etc/stunnel/certificado.zip &>/dev/null
    cd /etc/stunnel/
    unzip -o certificado.zip &>/dev/null
    cat private.key certificate.crt ca_bundle.crt >stunnel.pem
    ##-->> AutoInicio
    sed -i '/ENABLED=[01]/d' /etc/default/stunnel4
    echo "ENABLED=1" >>/etc/default/stunnel4
    systemctl start stunnel4 &>/dev/null
    systemctl start stunnel &>/dev/null
    systemctl restart stunnel4 &>/dev/null
    systemctl restart stunnel &>/dev/null
    cd
    msg -bar
    echo -e "\e[1;32m         >> CERTIFICADO INSTALADO CON EXITO <<"
    msg -bar

  }

  certificadom() {

    if [ -f /etc/stunnel/stunnel.conf ]; then
      insapa2() {
        for pid in $(pgrep python); do
          kill $pid
        done
        for pid in $(pgrep apache2); do
          kill $pid
        done
        service dropbear stop
        apt install apache2 -y
        echo "Listen 80

<IfModule ssl_module>
        Listen 443
</IfModule>

<IfModule mod_gnutls.c>
        Listen 443
</IfModule> " >/etc/apache2/ports.conf
        service apache2 restart
      }
      clear && clear
      msg -bar
      msg -tit
      msg -bar
      echo -e "\033[1;93m             AGREGAR CERTIFICADO ZEROSSL"
      msg -bar
      echo -e "\e[1;37m Verificar dominio.......... \e[0m\n"
      echo -e "\e[1;37m TIENES QUE MODIFICAR EL ARCHIVO DESCARGADO\n EJEMPLO: 530DDCDC3 comodoca.com 7bac5e210\e[0m"
      msg -bar
      read -p " LLAVE > Nombre Del Archivo: " keyy
      msg -bar
      read -p " DATOS > De La LLAVE: " dat2w
      [[ ! -d /var/www/html/.well-known ]] && mkdir /var/www/html/.well-known
      [[ ! -d /var/www/html/.well-known/pki-validation ]] && mkdir /var/www/html/.well-known/pki-validation
      datfr1=$(echo "$dat2w" | awk '{print $1}')
      datfr2=$(echo "$dat2w" | awk '{print $2}')
      datfr3=$(echo "$dat2w" | awk '{print $3}')
      echo -ne "${datfr1}\n${datfr2}\n${datfr3}" >/var/www/html/.well-known/pki-validation/$keyy.txt
      msg -bar
      echo -e "\e[1;37m VERIFIQUE EN LA PÁGINA ZEROSSL \e[0m"
      msg -bar
      read -p " ENTER PARA CONTINUAR"
      clear
      msg -bar
      echo -e "\e[1;33m👇 LINK DEL CERTIFICADO 👇       \n     \e[0m"
      echo -e "\e[1;36m LINK\e[37m: \e[34m"
      read link
      incertis() {
        wget $link -O /etc/stunnel/certificado.zip
        cd /etc/stunnel/
        unzip certificado.zip
        cat private.key certificate.crt ca_bundle.crt >stunnel.pem
        ##-->> AutoInicio
        sed -i '/ENABLED=[01]/d' /etc/default/stunnel4
        echo "ENABLED=1" >>/etc/default/stunnel4
        systemctl start stunnel4 &>/dev/null
        systemctl start stunnel &>/dev/null
        systemctl restart stunnel4 &>/dev/null
        systemctl restart stunnel &>/dev/null
      }
      incertis &>/dev/null && echo -e " \e[1;33mEXTRAYENDO CERTIFICADO " | pv -qL 10
      msg -bar
      echo -e "${cor[4]} CERTIFICADO INSTALADO \e[0m"
      msg -bar

      for pid in $(pgrep apache2); do
        kill $pid
      done
      apt install apache2 -y &>/dev/null
      echo "Listen 81

<IfModule ssl_module>
        Listen 443
</IfModule>

<IfModule mod_gnutls.c>
        Listen 443
</IfModule> " >/etc/apache2/ports.conf
      service apache2 restart &>/dev/null
      service dropbear start &>/dev/null
      service dropbear restart &>/dev/null
      for port in $(cat /etc/SCRIPT-LATAM/PortM/PDirect.log | grep -v "nobody" | cut -d' ' -f1); do
        PIDVRF3="$(ps aux | grep pid-"$port" | grep -v grep | awk '{print $2}')"
        Portd="$(cat /etc/SCRIPT-LATAM/PortM/PDirect.log | grep -v "nobody" | cut -d' ' -f1)"
        if [[ -z ${Portd} ]]; then
          # systemctl start python.PD &>/dev/null
          screen -dmS pydic-"$port" python /etc/SCRIPT-LATAM/filespy/PDirect-8081.py
        else
          # systemctl start python.PD &>/dev/null
          screen -dmS pydic-"$port" python /etc/SCRIPT-LATAM/filespy/PDirect-8081.py
        fi
      done
    else
      msg -bar
      echo -e "${cor[3]} SSL/TLS NO INSTALADO \e[0m"
      msg -bar
    fi
  }

  gerar_cert() {
    clear
    case $1 in
    1)
      msg -bar
      msg -ama "Generador De Certificado Let's Encrypt"
      msg -bar
      ;;
    2)
      msg -bar
      msg -ama "Generador De Certificado Zerossl"
      msg -bar
      ;;
    esac
    msg -ama "Requiere ingresar un dominio."
    msg -ama "el mismo solo deve resolver DNS, y apuntar"
    msg -ama "a la direccion ip de este servidor."
    msg -bar
    msg -ama "Temporalmente requiere tener"
    msg -ama "los puertos 80 y 443 libres."
    if [[ $1 = 2 ]]; then
      msg -bar
      msg -ama "Requiere tener una cuenta Zerossl."
    fi
    msg -bar
    msg -ne " Continuar [S/N]: "
    read opcion
    [[ $opcion != @(s|S|y|Y) ]] && return 1

    if [[ $1 = 2 ]]; then
      while [[ -z $mail ]]; do
        clear
        msg -bar
        msg -ama "ingresa tu correo usado en Zerossl"
        msg -bar3
        msg -ne " >>> "
        read mail
      done
    fi

    if [[ -e ${tmp_crt}/dominio.txt ]]; then
      domain=$(cat ${tmp_crt}/dominio.txt)
      [[ $domain = "multi-domain" ]] && unset domain
      if [[ ! -z $domain ]]; then
        clear
        msg -bar
        msg -azu "Dominio asociado a esta ip"
        msg -bar
        echo -e "$(msg -verm2 " >>> ") $(msg -ama "$domain")"
        msg -ne "Continuar, usando este dominio? [S/N]: "
        read opcion
        tput cuu1 && tput dl1
        [[ $opcion != @(S|s|Y|y) ]] && unset domain
      fi
    fi

    while [[ -z $domain ]]; do
      clear
      msg -bar
      msg -ama "ingresa tu dominio"
      msg -bar
      msg -ne " >>> "
      read domain
    done
    msg -bar
    msg -ama " Comprovando direccion IP ..."
    local_ip=$(wget -qO- ipv4.icanhazip.com)
    domain_ip=$(ping "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
    sleep 1
    [[ -z "${domain_ip}" ]] && domain_ip="ip no encontrada"
    if [[ $(echo "${local_ip}" | tr '.' '+' | bc) -ne $(echo "${domain_ip}" | tr '.' '+' | bc) ]]; then
      clear
      msg -bar
      msg -verm2 "ERROR DE DIRECCION IP"
      msg -bar
      msg -ama " La direccion ip de su dominio\n no coincide con la de su servidor."
      msg -bar
      echo -e " $(msg -azu "IP dominio:  ")$(msg -verm2 "${domain_ip}")"
      echo -e " $(msg -azu "IP servidor: ")$(msg -verm2 "${local_ip}")"
      msg -bar
      msg -ama " Verifique su dominio, e intente de nuevo."
      msg -bar

    fi

    stop_port
    acme_install
    echo "$domain" >${tmp_crt}/dominio.txt

  }

  clear && clear
  msg -bar

  msg -tit
  msg -bar
  echo -e "\e[1;93m    INSTALADOR MONO Y MULTI SSL | SCRIPT LATAM"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;97m INSTALAR | PARAR SSL \e[97m \n"
  echo -ne " \e[1;93m [\e[1;32m2\e[1;93m]\033[1;31m > \033[1;97m AGREGAR PUERTOS SSL EXTRA \e[97m \n"
  echo -ne " \e[1;93m [\e[1;32m3\e[1;93m]\033[1;31m > \033[1;97m AGREGAR CERTIFICADO MANUAL (zip) \e[97m \n"
  echo -ne " \e[1;93m [\e[1;32m4\e[1;93m]\033[1;31m > \033[1;97m AGREGAR CERTIFICADO ZEROSSL \e[97m \n"
  echo -ne " \e[1;93m [\e[1;32m5\e[1;93m]\033[1;31m > \033[1;97m AGREGAR CERTIFICADO SSL (Let's Encript) \e[97m \n"
  echo -ne " \e[1;93m [\e[1;32m5\e[1;93m]\033[1;31m > \033[1;97m AGREGAR CERTIFICADO SSL (Zerossl Directo) \e[97m \n"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m0\e[1;93m]\033[1;31m > \033[1;97m" && msg -bra "  \e[97m\033[1;41m VOLVER \033[1;37m"
  msg -bar
  echo -ne "\033[1;97mDigite solo el numero segun su respuesta:\e[32m "
  read opcao
  case $opcao in
  1)
    msg -bar
    ssl_stunel
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    proto_ssl
    ;;
  2)
    msg -bar
    ssl_stunel_2
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    proto_ssl
    ;;
  3)
    msg -bar
    cert_ssl
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    proto_ssl
    ;;
  4)
    msg -bar
    certificadom
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    proto_ssl
    ;;
  5)
    msg -bar
    gerar_cert 1
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    proto_ssl
    ;;
  6)
    msg -bar
    gerar_cert 2
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    proto_ssl
    ;;
  esac
  menu_inst
}

#--- PROTOCOLO SQUID
proto_squid() {
  clear
  clear
  mportas() {
    unset portas
    portas_var=$(lsof -V -i tcp -P -n | grep -v "ESTABLISHED" | grep -v "COMMAND" | grep "LISTEN")
    while read port; do
      var1=$(echo $port | awk '{print $1}') && var2=$(echo $port | awk '{print $9}' | awk -F ":" '{print $2}')
      [[ "$(echo -e $portas | grep "$var1 $var2")" ]] || portas+="$var1 $var2\n"
    done <<<"$portas_var"
    i=1
    echo -e "$portas"
  }
  fun_ip() {
    MEU_IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
    MEU_IP2=$(wget -qO- ipv4.icanhazip.com)
    [[ "$MEU_IP" != "$MEU_IP2" ]] && IP="$MEU_IP2" || IP="$MEU_IP"
  }
  #ETHOOL SSH
  fun_eth() {
    eth=$(ifconfig | grep -v inet6 | grep -v lo | grep -v 127.0.0.1 | grep "encap:Ethernet" | awk '{print $1}')
    [[ $eth != "" ]] && {
      msg -bar
      echo -e "${cor[3]} Aplicar el sistema para mejorar los paquetes SSH?"
      echo -e "${cor[3]} Opciones para usuarios avanzados"
      msg -bar
      read -p "[S/N]: " -e -i n sshsn
      tput cuu1 && tput dl1
      [[ "$sshsn" = @(s|S|y|Y) ]] && {
        echo -e "${cor[1]} Correccion de problemas de paquetes en SSH..."
        msg -bar
        echo -e " Cual es la tasa RX"
        echo -ne "[ 1 - 999999999 ]: "
        read rx
        [[ "$rx" = "" ]] && rx="999999999"
        echo -e " Cual es la tasa TX"
        echo -ne "[ 1 - 999999999 ]: "
        read tx
        [[ "$tx" = "" ]] && tx="999999999"
        apt-get install ethtool -y >/dev/null 2>&1
        ethtool -G $eth rx $rx tx $tx >/dev/null 2>&1
        msg -bar
      }
    }
  }

  fun_squid() {
    if [[ -e /etc/squid/squid.conf ]]; then
      var_squid="/etc/squid/squid.conf"
    elif [[ -e /etc/squid3/squid.conf ]]; then
      var_squid="/etc/squid3/squid.conf"
    fi
    [[ -e $var_squid ]] && {
      clear
      clear
      msg -bar
      echo -e "\033[1;31m                DESINSTALADO SQUID"
      msg -bar
      service squid stop >/dev/null 2>&1
      fun_bar "apt-get remove squid3 -y"
      msg -bar
      echo -e "\033[1;32m         >> SQUID DESINSTALADO CON EXITO << "
      msg -bar
      [[ -e $var_squid ]] && rm $var_squid
      return 0
    }
    msg -bar
    msg -tit
    msg -bar
    msg -ama "         INSTALADOR SQUID | SCRIPT LATAM "
    msg -bar
    fun_ip
    echo -ne "\033[97m Confirme su ip:\033[1;32m"
    read -p " " -e -i $IP ip
    msg -bar
    echo -e "\033[1;97mPuede activar varios puertosen forma secuencial\n \033[1;93mEjemplo: \033[1;32m80 8080 8799 3128"
    msg -bar
    echo -ne "Digite losPuertos:\033[1;32m "
    read -p " " -e -i "8080 7999" portasx
    msg -bar
    totalporta=($portasx)
    unset PORT
    for ((i = 0; i < ${#totalporta[@]}; i++)); do
      [[ $(mportas | grep "${totalporta[$i]}") = "" ]] && {
        echo -e "\033[1;33m Puerto Escojido:\033[1;32m ${totalporta[$i]} OK"
        PORT+="${totalporta[$i]}\n"
      } || {
        echo -e "\033[1;33m Puerto Escojido:\033[1;31m ${totalporta[$i]} FAIL"
      }
    done
    [[ -z $PORT ]] && {
      echo -e "\033[1;31m  No se ha elegido ninguna puerto valido, reintente\033[0m"
      return 1
    }
    msg -bar
    echo -e " INSTALANDO SQUID"
    msg -bar
    fun_bar "apt-get install squid3 -y"

    msg -bar
    echo -e " INICIANDO CONFIGURACION"
    echo -e ".bookclaro.com.br/\n.claro.com.ar/\n.claro.com.br/\n.claro.com.co/\n.claro.com.ec/\n.claro.com.gt/\n.cloudfront.net/\n.claro.com.ni/\n.claro.com.pe/\n.claro.com.sv/\n.claro.cr/\n.clarocurtas.com.br/\n.claroideas.com/\n.claroideias.com.br/\n.claromusica.com/\n.clarosomdechamada.com.br/\n.clarovideo.com/\n.facebook.net/\n.facebook.com/\n.netclaro.com.br/\n.oi.com.br/\n.oimusica.com.br/\n.speedtest.net/\n.tim.com.br/\n.timanamaria.com.br/\n.vivo.com.br/\n.rdio.com/\n.compute-1.amazonaws.com/\n.portalrecarga.vivo.com.br/\n.vivo.ddivulga.com/" >/etc/payloads
    msg -bar
    echo -e "\033[1;32m Ahora Escoja Una Conf Para Su Proxy"
    msg -bar
    echo -e "|1| Basico"
    echo -e "|2| Avanzado\033[1;37m"
    msg -bar
    read -p "[1/2]: " -e -i 1 proxy_opt
    tput cuu1 && tput dl1
    if [[ $proxy_opt = 1 ]]; then
      echo -e "             INSTALANDO SQUID BASICO"
    elif [[ $proxy_opt = 2 ]]; then
      echo -e "            INSTALANDO SQUID AVANZADO"
    else
      echo -e "             INSTALANDO SQUID BASICO"
      proxy_opt=1
    fi
    unset var_squid
    if [[ -d /etc/squid ]]; then
      var_squid="/etc/squid/squid.conf"
    elif [[ -d /etc/squid3 ]]; then
      var_squid="/etc/squid3/squid.conf"
    fi
    if [[ "$proxy_opt" = @(02|2) ]]; then
      echo -e "#ConfiguracaoSquiD
acl url1 dstdomain -i $ip
acl url2 dstdomain -i 127.0.0.1
acl url3 url_regex -i '/etc/payloads'
acl url4 url_regex -i '/etc/opendns'
acl url5 dstdomain -i localhost
acl accept dstdomain -i GET
acl accept dstdomain -i POST
acl accept dstdomain -i OPTIONS
acl accept dstdomain -i CONNECT
acl accept dstdomain -i PUT
acl HEAD dstdomain -i HEAD
acl accept dstdomain -i TRACE
acl accept dstdomain -i OPTIONS
acl accept dstdomain -i PATCH
acl accept dstdomain -i PROPATCH
acl accept dstdomain -i DELETE
acl accept dstdomain -i REQUEST
acl accept dstdomain -i METHOD
acl accept dstdomain -i NETDATA
acl accept dstdomain -i MOVE
acl all src 0.0.0.0/0
http_access allow url1
http_access allow url2
http_access allow url3
http_access allow url4
http_access allow url5
http_access allow accept
http_access allow HEAD
http_access deny all

# Request Headers Forcing

request_header_access Allow allow all
request_header_access Authorization allow all
request_header_access WWW-Authenticate allow all
request_header_access Proxy-Authorization allow all
request_header_access Proxy-Authenticate allow all
request_header_access Cache-Control allow all
request_header_access Content-Encoding allow all
request_header_access Content-Length allow all
request_header_access Content-Type allow all
request_header_access Date allow all
request_header_access Expires allow all
request_header_access Host allow all
request_header_access If-Modified-Since allow all
request_header_access Last-Modified allow all
request_header_access Location allow all
request_header_access Pragma allow all
request_header_access Accept allow all
request_header_access Accept-Charset allow all
request_header_access Accept-Encoding allow all
request_header_access Accept-Language allow all
request_header_access Content-Language allow all
request_header_access Mime-Version allow all
request_header_access Retry-After allow all
request_header_access Title allow all
request_header_access Connection allow all
request_header_access Proxy-Connection allow all
request_header_access User-Agent allow all
request_header_access Cookie allow all
#request_header_access All deny all

# Response Headers Spoofing

#reply_header_access Via deny all
#reply_header_access X-Cache deny all
#reply_header_access X-Cache-Lookup deny all

#portas" >$var_squid
      for pts in $(echo -e $PORT); do
        echo -e "http_port $pts" >>$var_squid
      done
      echo -e "
#nome
visible_hostname SCRIPT-LATAM

via off
forwarded_for off
pipeline_prefetch off" >>$var_squid
    else
      echo -e "#Configuracion SquiD
acl localhost src 127.0.0.1/32 ::1
acl to_localhost dst 127.0.0.0/8 0.0.0.0/32 ::1
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT
acl SSH dst $ip-$ip/255.255.255.255
http_access allow SSH
http_access allow manager localhost
http_access deny manager
http_access allow localhost
http_access deny all
coredump_dir /var/spool/squid

#Puertos" >$var_squid
      for pts in $(echo -e $PORT); do
        echo -e "http_port $pts" >>$var_squid
      done
      echo -e "
#HostName
visible_hostname SCRIPT-LATAM

via off
forwarded_for off
pipeline_prefetch off" >>$var_squid
    fi
    touch /etc/opendns
    fun_eth
    msg -bar
    echo -ne " \033[1;31m   [ ! ] \033[1;33m    REINICIANDO SERVICIOS"
    squid3 -k reconfigure >/dev/null 2>&1
    squid -k reconfigure >/dev/null 2>&1
    service ssh restart >/dev/null 2>&1
    service squid3 restart >/dev/null 2>&1
    service squid restart >/dev/null 2>&1
    echo -e " \033[1;32m[OK]"
    msg -bar
    echo -e "\033[1;32m               >> SQUID CONFIGURADO << "
    msg -bar
    #UFW
    for ufww in $(mportas | awk '{print $2}'); do
      ufw allow $ufww >/dev/null 2>&1
    done
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    menu_inst
  }
  online_squid() {
    payload="/etc/payloads"
    msg -bar
    echo -e "\033[1;33m            CONFIGURACIONES EXTRA PARA SQUID"
    msg -bar
    echo -ne " $(msg -verd "[1]") $(msg -verm2 "=>>") \e[1;97mCOLOCAR HOST EN SQUID \e[97m \n"
    echo -ne " $(msg -verd "[2]") $(msg -verm2 "=>>") \e[1;97mREMOVER HOST DE SQUID\e[97m \n"
    echo -ne " $(msg -verd "[3]") $(msg -verm2 "=>>") \e[1;31mDESINSTALAR SQUID \e[97m \n"
    echo -ne "$(msg -bar2)\n$(msg -verd " [0]") $(msg -verm2 ">") " && msg -bra "\e[97m\033[1;41m VOLVER \033[1;37m"
    msg -bar
    while [[ $varpay != @(0|[1-3]) ]]; do
      read -p "[0/3]: " varpay
      tput cuu1 && tput dl1
    done
    if [[ "$varpay" = "0" ]]; then

      menu_inst
    elif [[ "$varpay" = "1" ]]; then
      echo -e "${cor[4]}     Hosts Actuales Dentro del Squid"
      msg -bar
      cat $payload | awk -F "/" '{print $1,$2,$3,$4}'
      msg -bar
      while [[ $hos != \.* ]]; do
        echo -ne "\033[1;93mEscriba el nuevo host: \033[1;32m" && read hos
        tput cuu1 && tput dl1
        [[ $hos = \.* ]] && continue
        echo -e "\033[1;31m Comience con ."
        sleep 5s
        tput cuu1 && tput dl1
      done
      host="$hos/"
      [[ -z $host ]] && return 1
      [[ $(grep -c "^$host" $payload) -eq 1 ]] && :echo -e "${cor[4]}Host ya Exciste${cor[0]}" && return 1
      echo "$host" >>$payload && grep -v "^$" $payload >/tmp/a && mv /tmp/a $payload
      echo -e "${cor[4]}Host Agregado con Exito"
      msg -bar
      cat $payload | awk -F "/" '{print $1,$2,$3,$4}'
      msg -bar
      if [[ ! -f "/etc/init.d/squid" ]]; then
        service squid3 reload
        service squid3 restart

        menu_inst
      else
        /etc/init.d/squid reload
        service squid restart

        menu_inst
      fi

    elif [[ "$varpay" = "2" ]]; then
      echo -e "${cor[4]} Hosts Actuales Dentro del Squid"
      msg -bar
      cat $payload | awk -F "/" '{print $1,$2,$3,$4}'
      msg -bar
      while [[ $hos != \.* ]]; do
        echo -ne "\033[1;93m Digite un Host: \033[1;32m " && read hos
        tput cuu1 && tput dl1
        [[ $hos = \.* ]] && continue
        echo -e "\033[1;31m  Comience con ."
        sleep 5s
        tput cuu1 && tput dl1
      done
      host="$hos/"
      [[ -z $host ]] && return 1
      [[ $(grep -c "^$host" $payload) -ne 1 ]] && !echo -e "${cor[5]}Host No Encontrado" && return 1
      grep -v "^$host" $payload >/tmp/a && mv /tmp/a $payload
      echo -e "${cor[4]}Host Removido Con Exito"
      msg -bar
      cat $payload | awk -F "/" '{print $1,$2,$3,$4}'
      msg -bar
      if [[ ! -f "/etc/init.d/squid" ]]; then
        service squid3 reload
        service squid3 restart
        service squid reload
        service squid restart
      else
        service squid restart
        service squid3 restart
      fi

      menu_inst
    elif [[ "$varpay" = "3" ]]; then
      fun_squid
    fi
  }
  if [[ -e /etc/squid/squid.conf ]]; then
    online_squid
  elif [[ -e /etc/squid3/squid.conf ]]; then
    online_squid
  else
    fun_squid
  fi

}

#--- PROTOCOLO OPENVPN
proto_openvpn() {
  #timedatectl set-timezone UTC
  # Detect Debian users running the script with "sh" instead of bash
  if readlink /proc/$$/exe | grep -q "dash"; then
    echo "Este script se utiliza con bash"
    exit
  fi

  if [[ "$EUID" -ne 0 ]]; then
    echo "Sorry, solo funciona como root"
    exit
  fi

  if [[ ! -e /dev/net/tun ]]; then
    echo "El TUN device no esta disponible
Necesitas habilitar TUN antes de usar este script"
    exit
  fi

  if [[ -e /etc/debian_version ]]; then
    OS=debian
    GROUPNAME=nogroup
    RCLOCAL='/etc/rc.local'
  elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
    OS=centos
    GROUPNAME=nobody
    RCLOCAL='/etc/rc.d/rc.local'
  else
    echo "Tu sistema operativo no esta disponible para este script"
    exit
  fi

  agrega_dns() {
    msg -ama " Escriba el HOST DNS que desea Agregar"
    read -p " [NewDNS]: " SDNS
    cat /etc/hosts | grep -v "$SDNS" >/etc/hosts.bak && mv -f /etc/hosts.bak /etc/hosts
    if [[ -e /etc/opendns ]]; then
      cat /etc/opendns >/tmp/opnbak
      mv -f /tmp/opnbak /etc/opendns
      echo "$SDNS" >>/etc/opendns
    else
      echo "$SDNS" >/etc/opendns
    fi
    [[ -z $NEWDNS ]] && NEWDNS="$SDNS" || NEWDNS="$NEWDNS $SDNS"
    unset SDNS
  }
  mportas() {
    unset portas
    portas_var=$(lsof -V -i -P -n | grep -v "ESTABLISHED" | grep -v "COMMAND")
    while read port; do
      var1=$(echo $port | awk '{print $1}') && var2=$(echo $port | awk '{print $9}' | awk -F ":" '{print $2}')
      [[ "$(echo -e $portas | grep "$var1 $var2")" ]] || portas+="$var1 $var2\n"
    done <<<"$portas_var"
    i=1
    echo -e "$portas"
  }
  dns_fun() {
    case $1 in
    3) dns[$2]='push "dhcp-option DNS 1.0.0.1"' ;;
    4) dns[$2]='push "dhcp-option DNS 1.1.1.1"' ;;
    5) dns[$2]='push "dhcp-option DNS 9.9.9.9"' ;;
    6) dns[$2]='push "dhcp-option DNS 1.1.1.1"' ;;
    7) dns[$2]='push "dhcp-option DNS 80.67.169.40"' ;;
    8) dns[$2]='push "dhcp-option DNS 80.67.169.12"' ;;
    9) dns[$2]='push "dhcp-option DNS 84.200.69.80"' ;;
    10) dns[$2]='push "dhcp-option DNS 84.200.70.40"' ;;
    11) dns[$2]='push "dhcp-option DNS 208.67.222.222"' ;;
    12) dns[$2]='push "dhcp-option DNS 208.67.220.220"' ;;
    13) dns[$2]='push "dhcp-option DNS 8.8.8.8"' ;;
    14) dns[$2]='push "dhcp-option DNS 8.8.4.4"' ;;
    15) dns[$2]='push "dhcp-option DNS 77.88.8.8"' ;;
    16) dns[$2]='push "dhcp-option DNS 77.88.8.1"' ;;
    17) dns[$2]='push "dhcp-option DNS 176.103.130.130"' ;;
    18) dns[$2]='push "dhcp-option DNS 176.103.130.131"' ;;
    esac
  }
  meu_ip() {
    if [[ -e /etc/SCRIPT-LATAM/MEUIPvps ]]; then
      echo "$(cat /etc/SCRIPT-LATAM/MEUIPvps)"
    else
      MEU_IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
      MEU_IP2=$(wget -qO- ipv4.icanhazip.com)
      [[ "$MEU_IP" != "$MEU_IP2" ]] && echo "$MEU_IP2" || echo "$MEU_IP"
      echo "$MEU_IP" >/etc/SCRIPT-LATAM/MEUIPvps
    fi
  }
  IP="$(meu_ip)"

  instala_ovpn2() {
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    echo -e "\033[1;32m              INSTALADOR DE OPENVPN "
    msg -bar
    # OpenVPN setup and first user creation
    echo -e "\033[1;97mSe necesitan ciertos parametros para configurar OpenVPN."
    echo "Configuracion por default solo presiona ENTER."
    echo "Primero, cual es la IPv4 que quieres para OpenVPN"
    echo "Detectando..."
    msg -bar
    # Autodetect IP address and pre-fill for the user
    IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
    read -p "IP address: " -e -i $IP IP
    # If $IP is a private IP address, the server must be behind NAT
    if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
      echo
      echo "Este servidor esta detras de una red NAT?"
      read -p "IP  Publica  / hostname: " -e PUBLICIP
    fi
    msg -bar
    msg -ama "Que protocolo necesitas para las conexiones OpenVPN?"
    msg -bar
    echo "   1) UDP (recomendada)"
    echo "   2) TCP"
    msg -bar
    read -p "Protocolo [1-2]: " -e -i 1 PROTOCOL
    case $PROTOCOL in
    1)
      PROTOCOL=udp
      ;;
    2)
      PROTOCOL=tcp
      ;;
    esac
    msg -bar
    msg -ama "Que puerto necesitas en OpenVPN (Default 1194)?"
    msg -bar
    read -p "Puerto: " -e -i 1194 PORT
    msg -bar
    msg -ama "Cual DNS usaras en tu VPN?"
    msg -bar
    echo "   1) Actuales en el VPS"
    echo "   2) 1.1.1.1"
    echo "   3) Google"
    echo "   4) OpenDNS"
    echo "   5) Verisign"
    msg -bar
    read -p "DNS [1-5]: " -e -i 1 DNS
    #CIPHER
    msg -bar
    msg -ama " Elija que codificacion desea para el canal de datos:"
    msg -bar
    echo "   1) AES-128-CBC"
    echo "   2) AES-192-CBC"
    echo "   3) AES-256-CBC"
    echo "   4) CAMELLIA-128-CBC"
    echo "   5) CAMELLIA-192-CBC"
    echo "   6) CAMELLIA-256-CBC"
    echo "   7) SEED-CBC"
    echo "   8) NONE"
    msg -bar
    while [[ $CIPHER != @([1-8]) ]]; do
      read -p " Cipher [1-7]: " -e -i 1 CIPHER
    done
    case $CIPHER in
    1) CIPHER="cipher AES-128-CBC" ;;
    2) CIPHER="cipher AES-192-CBC" ;;
    3) CIPHER="cipher AES-256-CBC" ;;
    4) CIPHER="cipher CAMELLIA-128-CBC" ;;
    5) CIPHER="cipher CAMELLIA-192-CBC" ;;
    6) CIPHER="cipher CAMELLIA-256-CBC" ;;
    7) CIPHER="cipher SEED-CBC" ;;
    8) CIPHER="cipher none" ;;
    esac
    msg -bar
    msg -ama " Estamos listos para configurar su servidor OpenVPN"
    msg -bar
    read -n1 -r -p "Presiona cualquier tecla para continuar..."
    if [[ "$OS" = 'debian' ]]; then
      apt-get update
      apt-get install openvpn iptables openssl ca-certificates -y
    else
      #
      yum install epel-release -y
      yum install openvpn iptables openssl ca-certificates -y
    fi
    # Get easy-rsa
    EASYRSAURL='https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz'
    wget -O ~/easyrsa.tgz "$EASYRSAURL" 2>/dev/null || curl -Lo ~/easyrsa.tgz "$EASYRSAURL"
    tar xzf ~/easyrsa.tgz -C ~/
    mv ~/EasyRSA-3.0.8/ /etc/openvpn/
    mv /etc/openvpn/EasyRSA-3.0.8/ /etc/openvpn/easy-rsa/
    chown -R root:root /etc/openvpn/easy-rsa/
    rm -f ~/easyrsa.tgz
    cd /etc/openvpn/easy-rsa/
    #
    ./easyrsa init-pki
    ./easyrsa --batch build-ca nopass
    ./easyrsa gen-dh
    ./easyrsa build-server-full server nopass
    EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
    #
    cp pki/ca.crt pki/private/ca.key pki/dh.pem pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn
    #
    chown nobody:$GROUPNAME /etc/openvpn/crl.pem
    #
    openvpn --genkey --secret /etc/openvpn/ta.key
    #
    echo "port $PORT
proto $PROTOCOL
dev tun
sndbuf 0
rcvbuf 0
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-auth ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" >/etc/openvpn/server.conf
    echo 'push "redirect-gateway def1 bypass-dhcp"' >>/etc/openvpn/server.conf
    # DNS
    case $DNS in
    1)
      #
      #
      if grep -q "127.0.0.53" "/etc/resolv.conf"; then
        RESOLVCONF='/run/systemd/resolve/resolv.conf'
      else
        RESOLVCONF='/etc/resolv.conf'
      fi
      #
      grep -v '#' $RESOLVCONF | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
        echo "push \"dhcp-option DNS $line\"" >>/etc/openvpn/server.conf
      done
      ;;
    2)
      echo 'push "dhcp-option DNS 1.1.1.1"' >>/etc/openvpn/server.conf
      echo 'push "dhcp-option DNS 1.0.0.1"' >>/etc/openvpn/server.conf
      ;;
    3)
      echo 'push "dhcp-option DNS 8.8.8.8"' >>/etc/openvpn/server.conf
      echo 'push "dhcp-option DNS 8.8.4.4"' >>/etc/openvpn/server.conf
      ;;
    4)
      echo 'push "dhcp-option DNS 208.67.222.222"' >>/etc/openvpn/server.conf
      echo 'push "dhcp-option DNS 208.67.220.220"' >>/etc/openvpn/server.conf
      ;;
    5)
      echo 'push "dhcp-option DNS 64.6.64.6"' >>/etc/openvpn/server.conf
      echo 'push "dhcp-option DNS 64.6.65.6"' >>/etc/openvpn/server.conf
      ;;
    esac

    echo "keepalive 10 120
${CIPHER}
user nobody
group $GROUPNAME
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify crl.pem" >>/etc/openvpn/server.conf
    updatedb
    PLUGIN=$(locate openvpn-plugin-auth-pam.so | head -1)
    [[ ! -z $(echo ${PLUGIN}) ]] && {
      echo "client-to-client
client-cert-not-required
username-as-common-name
plugin $PLUGIN login" >>/etc/openvpn/server.conf
    }
    #
    echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/30-openvpn-forward.conf
    #
    echo 1 >/proc/sys/net/ipv4/ip_forward
    if pgrep firewalld; then
      #
      #
      #
      #
      firewall-cmd --zone=public --add-port=$PORT/$PROTOCOL
      firewall-cmd --zone=trusted --add-source=10.8.0.0/24
      firewall-cmd --permanent --zone=public --add-port=$PORT/$PROTOCOL
      firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
      #
      firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
      firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
    else
      #
      if [[ "$OS" = 'debian' && ! -e $RCLOCAL ]]; then
        echo '#!/bin/sh -e
exit 0' >$RCLOCAL
      fi
      chmod +x $RCLOCAL
      #
      iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
      sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP" $RCLOCAL
      if iptables -L -n | grep -qE '^(REJECT|DROP)'; then
        #
        #
        #
        iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
        iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
        iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
        sed -i "1 a\iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT" $RCLOCAL
        sed -i "1 a\iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT" $RCLOCAL
        sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
      fi
    fi
    #
    if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$PORT" != '1194' ]]; then
      #
      if ! hash semanage 2>/dev/null; then
        yum install policycoreutils-python -y
      fi
      semanage port -a -t openvpn_port_t -p $PROTOCOL $PORT
    fi
    #
    if [[ "$OS" = 'debian' ]]; then
      #
      if pgrep systemd-journal; then
        systemctl restart openvpn@server.service
      else
        /etc/init.d/openvpn restart
      fi
    else
      if pgrep systemd-journal; then
        systemctl restart openvpn@server.service
        systemctl enable openvpn@server.service
      else
        service openvpn restart
        chkconfig openvpn on
      fi
    fi
    #
    if [[ "$PUBLICIP" != "" ]]; then
      IP=$PUBLICIP
    fi
    #
    echo "# OVPN_ACCESS_SERVER_PROFILE=VPS-MX
client
dev tun
proto $PROTOCOL
sndbuf 0
rcvbuf 0
remote $IP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
${CIPHER}
setenv opt block-outside-dns
key-direction 1
verb 3
auth-user-pass" >/etc/openvpn/client-common.txt
    msg -bar
    msg -ama " Ahora crear una SSH para generar el (.ovpn)!"
    msg -bar
    echo -e "\033[1;32m Configuracion Finalizada!"
    msg -bar

  }

  instala_ovpn() {
    parametros_iniciais() {
      #Verifica o Sistema
      [[ "$EUID" -ne 0 ]] && echo " Lo siento, usted necesita ejecutar esto como ROOT" && exit 1
      [[ ! -e /dev/net/tun ]] && echo " TUN no esta Disponible" && exit 1
      if [[ -e /etc/debian_version ]]; then
        OS="debian"
        VERSION_ID=$(cat /etc/os-release | grep "VERSION_ID")
        IPTABLES='/etc/iptables/iptables.rules'
        [[ ! -d /etc/iptables ]] && mkdir /etc/iptables
        [[ ! -e $IPTABLES ]] && touch $IPTABLES
        SYSCTL='/etc/sysctl.conf'
        [[ "$VERSION_ID" != 'VERSION_ID="7"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="8"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="9"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="14.04"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="16.04"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="18.04"' ]] && [[ "$VERSION_ID" != 'VERSION_ID="17.10"' ]] && {
          echo " Su vercion de Debian / Ubuntu no Soportada."
          while [[ $CONTINUE != @(y|Y|s|S|n|N) ]]; do
            read -p "Continuar ? [y/n]: " -e CONTINUE
          done
          [[ "$CONTINUE" = @(n|N) ]] && exit 1
        }
      else
        msg -ama " Parece que no estas ejecutando este instalador en un sistema Debian o Ubuntu"
        msg -bar
        return 1
      fi
      #Pega Interface
      NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)

    }
    add_repo() {
      #INSTALACAO E UPDATE DO REPOSITORIO
      # Debian 7
      if [[ "$VERSION_ID" = 'VERSION_ID="7"' ]]; then
        echo "deb http://build.openvpn.net/debian/openvpn/stable wheezy main" >/etc/apt/sources.list.d/openvpn.list
        wget -q -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add - >/dev/null 2>&1
      # Debian 8
      elif [[ "$VERSION_ID" = 'VERSION_ID="8"' ]]; then
        echo "deb http://build.openvpn.net/debian/openvpn/stable jessie main" >/etc/apt/sources.list.d/openvpn.list
        wget -q -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add - >/dev/null 2>&1
      # Ubuntu 14.04
      elif [[ "$VERSION_ID" = 'VERSION_ID="14.04"' ]]; then
        echo "deb http://build.openvpn.net/debian/openvpn/stable trusty main" >/etc/apt/sources.list.d/openvpn.list
        wget -q -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add - >/dev/null 2>&1
      # Ubuntu 16.04
      elif [[ "$VERSION_ID" = 'VERSION_ID="16.04"' ]]; then
        echo "deb http://build.openvpn.net/debian/openvpn/stable xenial main" >/etc/apt/sources.list.d/openvpn.list
        wget -q -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add - >/dev/null 2>&1
      # Ubuntu 18.04
      elif [[ "$VERSION_ID" = 'VERSION_ID="18.04"' ]]; then
        apt-get remove openvpn -y >/dev/null 2>&1
        rm -rf /etc/apt/sources.list.d/openvpn.list >/dev/null 2>&1
        echo "deb http://build.openvpn.net/debian/openvpn/stable bionic main" >/etc/apt/sources.list.d/openvpn.list
        wget -q -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add - >/dev/null 2>&1
      fi
    }
    coleta_variaveis() {
      echo -e "\033[1;32m     INSTALADOR DE OPENVPN | VPS-MX By @Kalix1"
      msg -bar
      msg -ne " Confirme su IP"
      read -p ": " -e -i $IP ip
      msg -bar
      msg -ama " Que puerto desea usar?"
      msg -bar
      while true; do
        read -p " Port: " -e -i 1194 PORT
        [[ $(mportas | grep -w "$PORT") ]] || break
        echo -e "\033[1;33m Este puerto esta en uso\033[0m"
        unset PORT
      done
      msg -bar
      echo -e "\033[1;31m Que protocolo desea para las conexiones OPENVPN?"
      echo -e "\033[1;31m A menos que UDP este bloqueado, no utilice TCP (es mas lento)"
      #PROTOCOLO
      while [[ $PROTOCOL != @(UDP|TCP) ]]; do
        read -p " Protocol [UDP/TCP]: " -e -i TCP PROTOCOL
      done
      [[ $PROTOCOL = "UDP" ]] && PROTOCOL=udp
      [[ $PROTOCOL = "TCP" ]] && PROTOCOL=tcp
      #DNS
      msg -bar
      msg -ama " Que DNS desea utilizar?"
      msg -bar
      echo "   1) Usar DNS de sistema "
      echo "   2) Cloudflare"
      echo "   3) Quad"
      echo "   4) FDN"
      echo "   5) DNS.WATCH"
      echo "   6) OpenDNS"
      echo "   7) Google DNS"
      echo "   8) Yandex Basic"
      echo "   9) AdGuard DNS"
      msg -bar
      while [[ $DNS != @([1-9]) ]]; do
        read -p " DNS [1-9]: " -e -i 1 DNS
      done
      #CIPHER
      msg -bar
      msg -ama " Elija que codificacion desea para el canal de datos:"
      msg -bar
      echo "   1) AES-128-CBC"
      echo "   2) AES-192-CBC"
      echo "   3) AES-256-CBC"
      echo "   4) CAMELLIA-128-CBC"
      echo "   5) CAMELLIA-192-CBC"
      echo "   6) CAMELLIA-256-CBC"
      echo "   7) SEED-CBC"
      msg -bar
      while [[ $CIPHER != @([1-7]) ]]; do
        read -p " Cipher [1-7]: " -e -i 1 CIPHER
      done
      case $CIPHER in
      1) CIPHER="cipher AES-128-CBC" ;;
      2) CIPHER="cipher AES-192-CBC" ;;
      3) CIPHER="cipher AES-256-CBC" ;;
      4) CIPHER="cipher CAMELLIA-128-CBC" ;;
      5) CIPHER="cipher CAMELLIA-192-CBC" ;;
      6) CIPHER="cipher CAMELLIA-256-CBC" ;;
      7) CIPHER="cipher SEED-CBC" ;;
      esac
      msg -bar
      msg -ama " Estamos listos para configurar su servidor OpenVPN"
      msg -bar
      read -n1 -r -p " Enter para Continuar ..."
      tput cuu1 && tput dl1
    }
    parametros_iniciais # BREVE VERIFICACAO
    coleta_variaveis    # COLETA VARIAVEIS PARA INSTALAÇÃO
    add_repo            # ATUALIZA REPOSITÓRIO OPENVPN E INSTALA OPENVPN
    # Cria Diretorio
    [[ ! -d /etc/openvpn ]] && mkdir /etc/openvpn
    # Install openvpn
    echo -ne " \033[1;31m[ ! ] apt-get update"
    apt-get update -q >/dev/null 2>&1 && echo -e "\033[1;32m [OK]" || echo -e "\033[1;31m [FAIL]"
    echo -ne " \033[1;31m[ ! ] apt-get install openvpn curl openssl"
    apt-get install -qy openvpn curl >/dev/null 2>&1 && apt-get install openssl ca-certificates -y >/dev/null 2>&1 && echo -e "\033[1;32m [OK]" || echo -e "\033[1;31m [FAIL]"
    SERVER_IP="$(meu_ip)" # IP Address
    [[ -z "${SERVER_IP}" ]] && SERVER_IP=$(ip a | awk -F"[ /]+" '/global/ && !/127.0/ {print $3; exit}')
    echo -ne " \033[1;31m[ ! ] Generating Server Config" # Gerando server.con
    (
      case $DNS in
      1)
        i=0
        grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
          dns[$i]="push \"dhcp-option DNS $line\""
        done
        [[ ! "${dns[@]}" ]] && dns[0]='push "dhcp-option DNS 8.8.8.8"' && dns[1]='push "dhcp-option DNS 8.8.4.4"'
        ;;
      2) dns_fun 3 && dns_fun 4 ;;
      3) dns_fun 5 && dns_fun 6 ;;
      4) dns_fun 7 && dns_fun 8 ;;
      5) dns_fun 9 && dns_fun 10 ;;
      6) dns_fun 11 && dns_fun 12 ;;
      7) dns_fun 13 && dns_fun 14 ;;
      8) dns_fun 15 && dns_fun 16 ;;
      9) dns_fun 17 && dns_fun 18 ;;
      esac
      echo 01 >/etc/openvpn/ca.srl
      while [[ ! -e /etc/openvpn/dh.pem || -z $(cat /etc/openvpn/dh.pem) ]]; do
        openssl dhparam -out /etc/openvpn/dh.pem 2048 &>/dev/null
      done
      while [[ ! -e /etc/openvpn/ca-key.pem || -z $(cat /etc/openvpn/ca-key.pem) ]]; do
        openssl genrsa -out /etc/openvpn/ca-key.pem 2048 &>/dev/null
      done
      chmod 600 /etc/openvpn/ca-key.pem &>/dev/null
      while [[ ! -e /etc/openvpn/ca-csr.pem || -z $(cat /etc/openvpn/ca-csr.pem) ]]; do
        openssl req -new -key /etc/openvpn/ca-key.pem -out /etc/openvpn/ca-csr.pem -subj /CN=OpenVPN-CA/ &>/dev/null
      done
      while [[ ! -e /etc/openvpn/ca.pem || -z $(cat /etc/openvpn/ca.pem) ]]; do
        openssl x509 -req -in /etc/openvpn/ca-csr.pem -out /etc/openvpn/ca.pem -signkey /etc/openvpn/ca-key.pem -days 365 &>/dev/null
      done
      cat >/etc/openvpn/server.conf <<EOF
server 10.8.0.0 255.255.255.0
verb 3
duplicate-cn
key client-key.pem
ca ca.pem
cert client-cert.pem
dh dh.pem
keepalive 10 120
persist-key
persist-tun
comp-lzo
float
push "redirect-gateway def1 bypass-dhcp"
${dns[0]}
${dns[1]}

user nobody
group nogroup

${CIPHER}
proto ${PROTOCOL}
port $PORT
dev tun
status openvpn-status.log
EOF
      updatedb
      PLUGIN=$(locate openvpn-plugin-auth-pam.so | head -1)
      [[ ! -z $(echo ${PLUGIN}) ]] && {
        echo "client-to-client
client-cert-not-required
username-as-common-name
plugin $PLUGIN login" >>/etc/openvpn/server.conf
      }
    ) && echo -e "\033[1;32m [OK]" || echo -e "\033[1;31m [FAIL]"
    echo -ne " \033[1;31m[ ! ] Generating CA Config" # Generate CA Config
    (
      while [[ ! -e /etc/openvpn/client-key.pem || -z $(cat /etc/openvpn/client-key.pem) ]]; do
        openssl genrsa -out /etc/openvpn/client-key.pem 2048 &>/dev/null
      done
      chmod 600 /etc/openvpn/client-key.pem
      while [[ ! -e /etc/openvpn/client-csr.pem || -z $(cat /etc/openvpn/client-csr.pem) ]]; do
        openssl req -new -key /etc/openvpn/client-key.pem -out /etc/openvpn/client-csr.pem -subj /CN=OpenVPN-Client/ &>/dev/null
      done
      while [[ ! -e /etc/openvpn/client-cert.pem || -z $(cat /etc/openvpn/client-cert.pem) ]]; do
        openssl x509 -req -in /etc/openvpn/client-csr.pem -out /etc/openvpn/client-cert.pem -CA /etc/openvpn/ca.pem -CAkey /etc/openvpn/ca-key.pem -days 365 &>/dev/null
      done
    ) && echo -e "\033[1;32m [OK]" || echo -e "\033[1;31m [FAIL]"
    teste_porta() {
      msg -bar
      echo -ne " \033[1;31m ${id} Verificando:"
      sleep 1s
      [[ ! $(mportas | grep "$1") ]] && {
        echo -e "\033[1;33m [FAIL]\033[0m"
      } || {
        echo -e "\033[1;32m [Pass]\033[0m"
        return 1
      }
    }
    msg -bar
    echo -e "\033[1;33m Ahora Necesitamos un Proxy SQUID o PYTHON-OPENVPN"
    echo -e "\033[1;33m Si no existe un proxy en la puerta, un proxy Python sera abierto!"
    msg -bar
    while [[ $? != "1" ]]; do
      read -p " Confirme el Puerto(Proxy) " -e -i 80 PPROXY
      teste_porta $PPROXY
    done
    cat >/etc/openvpn/client-common.txt <<EOF
# OVPN_ACCESS_SERVER_PROFILE=VPS-MX
client
nobind
dev tun
redirect-gateway def1 bypass-dhcp
remote-random
remote ${SERVER_IP} ${PORT} ${PROTOCOL}
http-proxy ${SERVER_IP} ${PPROXY}
$CIPHER
comp-lzo yes
keepalive 10 20
float
auth-user-pass
EOF
    # Iptables
    if [[ ! -f /proc/user_beancounters ]]; then
      INTIP=$(ip a | awk -F"[ /]+" '/global/ && !/127.0/ {print $3; exit}')
      N_INT=$(ip a | awk -v sip="$INTIP" '$0 ~ sip { print $7}')
      iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $N_INT -j MASQUERADE
      iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $SERVER_IP
    else
      iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to-source $SERVER_IP

    fi
    iptables-save >/etc/iptables.conf
    cat >/etc/network/if-up.d/iptables <<EOF
#!/bin/sh
iptables-restore < /etc/iptables.conf
EOF
    chmod +x /etc/network/if-up.d/iptables
    # Enable net.ipv4.ip_forward
    sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|' /etc/sysctl.conf
    echo 1 >/proc/sys/net/ipv4/ip_forward
    # Regras de Firewall
    if pgrep firewalld; then
      if [[ "$PROTOCOL" = 'udp' ]]; then
        firewall-cmd --zone=public --add-port=$PORT/udp
        firewall-cmd --permanent --zone=public --add-port=$PORT/udp
      elif [[ "$PROTOCOL" = 'tcp' ]]; then
        firewall-cmd --zone=public --add-port=$PORT/tcp
        firewall-cmd --permanent --zone=public --add-port=$PORT/tcp
      fi
      firewall-cmd --zone=trusted --add-source=10.8.0.0/24
      firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
    fi
    if iptables -L -n | grep -qE 'REJECT|DROP'; then
      if [[ "$PROTOCOL" = 'udp' ]]; then
        iptables -I INPUT -p udp --dport $PORT -j ACCEPT
      elif [[ "$PROTOCOL" = 'tcp' ]]; then
        iptables -I INPUT -p tcp --dport $PORT -j ACCEPT
      fi
      iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
      iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
      iptables-save >$IPTABLES
    fi
    if hash sestatus 2>/dev/null; then
      if sestatus | grep "Current mode" | grep -qs "enforcing"; then
        if [[ "$PORT" != '1194' ]]; then
          if ! hash semanage 2>/dev/null; then
            yum install policycoreutils-python -y
          fi
          if [[ "$PROTOCOL" = 'udp' ]]; then
            semanage port -a -t openvpn_port_t -p udp $PORT
          elif [[ "$PROTOCOL" = 'tcp' ]]; then
            semanage port -a -t openvpn_port_t -p tcp $PORT
          fi
        fi
      fi
    fi
    #Liberando DNS
    msg -bar
    msg -ama " Ultimo Paso, Configuraciones DNS"
    msg -bar
    while [[ $DDNS != @(n|N) ]]; do
      echo -ne "\033[1;33m"
      read -p " Agergar HOST DNS [S/N]: " -e -i n DDNS
      [[ $DDNS = @(s|S|y|Y) ]] && agrega_dns
    done
    [[ ! -z $NEWDNS ]] && {
      sed -i "/127.0.0.1[[:blank:]]\+localhost/a 127.0.0.1 $NEWDNS" /etc/hosts
      for DENESI in $(echo $NEWDNS); do
        sed -i "/remote ${SERVER_IP} ${PORT} ${PROTOCOL}/a remote ${DENESI} ${PORT} ${PROTOCOL}" /etc/openvpn/client-common.txt
      done
    }
    msg -bar
    # REINICIANDO OPENVPN
    if [[ "$OS" = 'debian' ]]; then
      if pgrep systemd-journal; then
        sed -i 's|LimitNPROC|#LimitNPROC|' /lib/systemd/system/openvpn\@.service
        sed -i 's|/etc/openvpn/server|/etc/openvpn|' /lib/systemd/system/openvpn\@.service
        sed -i 's|%i.conf|server.conf|' /lib/systemd/system/openvpn\@.service
        #systemctl daemon-reload
        (
          systemctl restart openvpn
          systemctl enable openvpn
        ) >/dev/null 2>&1
      else
        /etc/init.d/openvpn restart >/dev/null 2>&1
      fi
    else
      if pgrep systemd-journal; then
        (
          systemctl restart openvpn@server.service
          systemctl enable openvpn@server.service
        ) >/dev/null 2>&1
      else
        (
          service openvpn restart
          chkconfig openvpn on
        ) >/dev/null 2>&1
      fi
    fi
    service squid restart &>/dev/null
    service squid3 restart &>/dev/null
    apt-get install ufw -y >/dev/null 2>&1
    for ufww in $(mportas | awk '{print $2}'); do
      ufw allow $ufww >/dev/null 2>&1
    done
    #Restart OPENVPN
    (
      killall openvpn 2>/dev/null
      systemctl stop openvpn@server.service >/dev/null 2>&1
      service openvpn stop >/dev/null 2>&1
      sleep 0.1s
      cd /etc/openvpn >/dev/null 2>&1
      screen -dmS ovpnscr openvpn --config "server.conf" >/dev/null 2>&1
    ) >/dev/null 2>&1
    echo -e "\033[1;32m Openvpn configurado con EXITO!"
    msg -bar
    msg -ama " Ahora crear una SSH para generar el (.ovpn)!"
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    menu_inst
  }
  edit_ovpn_host() {
    msg -bar3
    msg -ama " CONFIGURACION HOST DNS OPENVPN"
    msg -bar
    while [[ $DDNS != @(n|N) ]]; do
      echo -ne "\033[1;33m"
      read -p " Agregar host [S/N]: " -e -i n DDNS
      [[ $DDNS = @(s|S|y|Y) ]] && agrega_dns
    done
    [[ ! -z $NEWDNS ]] && sed -i "/127.0.0.1[[:blank:]]\+localhost/a 127.0.0.1 $NEWDNS" /etc/hosts
    msg -bar
    msg -ama " Es Necesario el Reboot del Servidor Para"
    msg -ama " Para que las configuraciones sean efectudas"
    msg -bar
  }
  fun_openvpn() {
    [[ -e /etc/openvpn/server.conf ]] && {
      unset OPENBAR
      [[ $(mportas | grep -w "openvpn") ]] && OPENBAR="\033[1;32m ONLINE" || OPENBAR="\033[1;31m OFFLINE"
      clear && clear
      msg -bar
      msg -ama " OPENVPN YA ESTA INSTALADO"
      msg -bar
      echo -e "\033[1;32m [1] >\033[1;36m DESINSTALAR  OPENVPN"
      echo -e "\033[1;32m [2] >\033[1;36m EDITAR CONFIGURACION CLIENTE \033[1;31m(MEDIANTE NANO)"
      echo -e "\033[1;32m [3] >\033[1;36m EDITAR CONFIGURACION SERVIDOR \033[1;31m(MEDIANTE NANO)"
      echo -e "\033[1;32m [4] >\033[1;36m CAMBIAR HOST DE OPENVPN"
      echo -e "\033[1;32m [5] >\033[1;36m INICIAR O PARAR OPENVPN - $OPENBAR"
      msg -bar
      while [[ $xption != @([0|1|2|3|4|5]) ]]; do
        echo -ne "\033[1;33m Opcion: " && read xption
        tput cuu1 && tput dl1
      done
      case $xption in
      1)
        clear
        msg -bar
        echo -ne "\033[1;97m"
        read -p "QUIERES DESINTALAR OPENVPN? [Y/N]: " -e REMOVE
        msg -bar
        if [[ "$REMOVE" = 'y' || "$REMOVE" = 'Y' ]]; then
          PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
          PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)
          if pgrep firewalld; then
            IP=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24 -j SNAT --to ' | cut -d " " -f 10)
            #
            firewall-cmd --zone=public --remove-port=$PORT/$PROTOCOL
            firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
            firewall-cmd --permanent --zone=public --remove-port=$PORT/$PROTOCOL
            firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
            firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
            firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
          else
            IP=$(grep 'iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to ' $RCLOCAL | cut -d " " -f 14)
            iptables -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
            sed -i '/iptables -t nat -A POSTROUTING -s 10.8.0.0\/24 ! -d 10.8.0.0\/24 -j SNAT --to /d' $RCLOCAL
            if iptables -L -n | grep -qE '^ACCEPT'; then
              iptables -D INPUT -p $PROTOCOL --dport $PORT -j ACCEPT
              iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT
              iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
              sed -i "/iptables -I INPUT -p $PROTOCOL --dport $PORT -j ACCEPT/d" $RCLOCAL
              sed -i "/iptables -I FORWARD -s 10.8.0.0\/24 -j ACCEPT/d" $RCLOCAL
              sed -i "/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT/d" $RCLOCAL
            fi
          fi
          if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$PORT" != '1194' ]]; then
            semanage port -d -t openvpn_port_t -p $PROTOCOL $PORT
          fi
          if [[ "$OS" = 'debian' ]]; then
            apt-get remove --purge -y openvpn
          else
            yum remove openvpn -y
          fi
          rm -rf /etc/openvpn
          rm -f /etc/sysctl.d/30-openvpn-forward.conf
          msg -bar
          echo "OpenVPN removido!"
          msg -bar
        else
          msg -bar
          echo "Desinstalacion abortada!"
          msg -bar
        fi
        read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
        menu_inst
        ;;
      2)
        nano /etc/openvpn/client-common.txt
        read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
        menu_inst
        ;;
      3)
        nano /etc/openvpn/server.conf
        read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
        menu_inst
        ;;
      4) edit_ovpn_host ;;
      5)
        [[ $(mportas | grep -w openvpn) ]] && {
          /etc/init.d/openvpn stop >/dev/null 2>&1
          killall openvpn &>/dev/null
          systemctl stop openvpn@server.service &>/dev/null
          service openvpn stop &>/dev/null
          #ps x |grep openvpn |grep -v grep|awk '{print $1}' | while read pid; do kill -9 $pid; done
        } || {
          cd /etc/openvpn
          screen -dmS ovpnscr openvpn --config "server.conf" >/dev/null 2>&1
          cd $HOME
        }
        msg -ama " Procedimiento Hecho con Exito"
        msg -bar
        read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
        menu_inst
        ;;
      0)
        read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
        menu_inst
        ;;
      esac
      read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      menu_inst
    }
    [[ -e /etc/squid/squid.conf ]] && instala_ovpn2 && menu_inst
    [[ -e /etc/squid3/squid.conf ]] && instala_ovpn2 && menu_inst

    instala_ovpn2 || menu_inst
  }

  fun_openvpn
}

#--- PROTOCOLO BADVPN
proto_badvpn() {
  activar_badvpn() {
    mportas() {
      unset portas
      portas_var=$(lsof -V -i tcp -P -n | grep -v "ESTABLISHED" | grep -v "COMMAND" | grep "LISTEN")
      while read port; do
        var1=$(echo $port | awk '{print $1}') && var2=$(echo $port | awk '{print $9}' | awk -F ":" '{print $2}')
        [[ "$(echo -e $portas | grep "$var1 $var2")" ]] || portas+="$var1 $var2\n"
      done <<<"$portas_var"
      i=1
      echo -e "$portas"
    }
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    msg -ama "            INSTALADOR DE BADVPN (UDP)"
    msg -bar
    echo -e "\033[1;97mDigite los puertos a activar de forma secuencial\nEjemplo:\033[1;32m 7300 7200 7100 \033[1;97m| \033[1;93mPuerto recomendado \033[1;32m 7300\n"
    echo -ne "\033[1;97mDigite los Puertos:\033[1;32m " && read -p " " -e -i "7200 7300" portasx
    echo "$portasx" >/etc/SCRIPT-LATAM/PortM/Badvpn.log
    msg -bar
    totalporta=($portasx)
    unset PORT
    for ((i = 0; i < ${#totalporta[@]}; i++)); do
      [[ $(mportas | grep "${totalporta[$i]}") = "" ]] && {
        echo -e "\033[1;33m Puerto Escojido:\033[1;32m ${totalporta[$i]} OK"
        PORT+="${totalporta[$i]}\n"
        screen -dmS badvpn /bin/badvpn-udpgw --listen-addr 127.0.0.1:${totalporta[$i]} --max-clients 1000 --max-connections-for-client 10
      } || {
        echo -e "\033[1;33m Puerto Escojido:\033[1;31m ${totalporta[$i]} FAIL"
      }
    done
    [[ -z $PORT ]] && {
      echo -e "\033[1;31m  No se ha elegido ninguna puerto valido, reintente\033[0m"
      return 1
    }

    msg -bar
    [[ "$(ps x | grep badvpn | grep -v grep | awk '{print $1}')" ]] && msg -verd "        >> BADVPN INSTALADO CON EXITO <<" || msg -ama "               ERROR VERIFIQUE"
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    menu_inst
  }

  desactivar_badvpn() {
    clear && clear
    msg -bar
    echo -e "\033[1;31m            DESISNTALANDO PUERTOS BADVPN "
    msg -bar
    kill -9 $(ps x | grep badvpn | grep -v grep | awk '{print $1'}) >/dev/null 2>&1
    killall badvpn-udpgw >/dev/null 2>&1
    screen -wipe >/dev/null 2>&1
    rm -rf /etc/SCRIPT-LATAM/PortM/Badvpn.log >/dev/null 2>&1
    [[ ! "$(ps x | grep badvpn | grep -v grep | awk '{print $1}')" ]] && echo -e "\033[1;32m        >> BADVPN DESINSTALADO CON EXICO << "
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    menu_inst
  }
  clear && clear
  msg -bar
  msg -tit
  msg -bar
  msg -ama "            INSTALADOR DE BADVPN (UDP)"
  msg -bar
  if [[ ! -e /bin/badvpn-udpgw ]]; then
    wget -O /bin/badvpn-udpgw https://raw.githubusercontent.com/NetVPS/LATAM_Oficial/main/Ejecutables/badvpn-udpgw &>/dev/null
    chmod 777 /bin/badvpn-udpgw
  fi
  echo -ne " \e[1;93m [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;97m INSTALAR UN BADVPN  \e[97m \n"
  echo -ne " \e[1;93m [\e[1;32m2\e[1;93m]\033[1;31m > \033[1;97m DETENER TODOS LOS BADVPN\e[97m \n"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m0\e[1;93m]\033[1;31m > \033[1;97m" && msg -bra "  \e[97m\033[1;41m VOLVER \033[1;37m"
  msg -bar
  echo -ne "\033[1;97mDigite solo el numero segun su respuesta:\e[32m "
  read opcao
  case $opcao in
  1)
    msg -bar
    activar_badvpn

    ;;
  2)
    msg -bar
    desactivar_badvpn
    ;;
  0)
    menu
    ;;
  *)
    echo -e "$ Porfavor use numeros del [0-14]"
    msg -bar
    menu
    ;;
  esac

  #exit 0
}

#--- PROTO SHADOWSOCK NORMAL
proto_shadowsockN() {
  mportas() {
    unset portas
    portas_var=$(lsof -V -i tcp -P -n | grep -v "ESTABLISHED" | grep -v "COMMAND" | grep "LISTEN")
    while read port; do
      var1=$(echo $port | awk '{print $1}') && var2=$(echo $port | awk '{print $9}' | awk -F ":" '{print $2}')
      [[ "$(echo -e $portas | grep "$var1 $var2")" ]] || portas+="$var1 $var2\n"
    done <<<"$portas_var"
    i=1
    echo -e "$portas"
  }
  fun_ip() {
    MEU_IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
    MEU_IP2=$(wget -qO- ipv4.icanhazip.com)
    [[ "$MEU_IP" != "$MEU_IP2" ]] && IP="$MEU_IP2" || IP="$MEU_IP"
  }
  fun_eth() {
    eth=$(ifconfig | grep -v inet6 | grep -v lo | grep -v 127.0.0.1 | grep "encap:Ethernet" | awk '{print $1}')
    [[ $eth != "" ]] && {
      msg -bar
      echo -e "${cor[3]}  Aplicar Sistema Para Mejorar Paquetes SSH?"
      echo -e "${cor[3]}  Opcion Para Usuarios Avanzados"
      msg -bar
      read -p " [S/N]: " -e -i n sshsn
      [[ "$sshsn" = @(s|S|y|Y) ]] && {
        echo -e "${cor[1]} Correccion de problemas de paquetes en SSH..."
        echo -e " Cual es la Tasa de RX"
        echo -ne "[ 1 - 999999999 ]: "
        read rx
        [[ "$rx" = "" ]] && rx="999999999"
        echo -e " Cual es la Tasa de  TX"
        echo -ne "[ 1 - 999999999 ]: "
        read tx
        [[ "$tx" = "" ]] && tx="999999999"
        apt-get install ethtool -y >/dev/null 2>&1
        ethtool -G $eth rx $rx tx $tx >/dev/null 2>&1
      }
      msg -bar
    }
  }

  fun_shadowsocks() {
    [[ -e /etc/shadowsocks.json ]] && {

      clear && clear
      msg -bar
      echo -e "\033[1;31m               DESINSTALANDO SHADOWSOCK"
      msg -bar
      [[ $(ps x | grep ssserver | grep -v grep | awk '{print $1}') != "" ]] && kill -9 $(ps x | grep ssserver | grep -v grep | awk '{print $1}') >/dev/null 2>&1 && ssserver -c /etc/shadowsocks.json -d stop >/dev/null 2>&1
      echo -e "\033[1;32m     >> SHADOWSOCK-N DESINSTALADO CON EXITO << "
      msg -bar
      rm /etc/shadowsocks.json
      return 0
    }
    while true; do
      clear && clear
      msg -bar
      msg -tit
      msg -bar
      msg -ama "      INSTALADOR SHADOWSOCKS | SCRIPT LATAM"
      msg -bar
      echo -e "\033[1;97m Selecione una Criptografia"
      msg -bar
      encript=(aes-256-gcm aes-192-gcm aes-128-gcm aes-256-ctr aes-192-ctr aes-128-ctr aes-256-cfb aes-192-cfb aes-128-cfb camellia-128-cfb camellia-192-cfb camellia-256-cfb chacha20-ietf-poly1305 chacha20-ietf chacha20 rc4-md5)
      for ((s = 0; s < ${#encript[@]}; s++)); do
        echo -e " [${s}] - ${encript[${s}]}"
      done
      msg -bar
      while true; do
        unset cript
        echo -ne "\033[1;97mEscoja una Criptografia:\033[1;32m " && read -p " " -e -i "0" cript
        [[ ${encript[$cript]} ]] && break
        echo -e "Opcion Invalida"
      done
      encriptacao="${encript[$cript]}"
      [[ ${encriptacao} != "" ]] && break
      echo -e "Opcion Invalida"
    done
    #ESCOLHENDO LISTEN
    msg -bar
    echo -e "\033[1;97m Seleccione el puerto para Shadowsocks\033[0m"
    msg -bar
    while true; do
      unset Lport
      echo -ne "\033[1;97m  Puerto:\033[1;32m " && read Lport
      [[ $(mportas | grep "$Lport") = "" ]] && break
      echo -e " ${Lport}: Puerto Invalido"
    done
    #INICIANDO
    msg -bar
    echo -ne "\033[1;97m  Ingrese una contraseña:\033[1;32m " && read Pass
    msg -bar
    echo -e "\033[1;97m            -- Iniciando Instalacion -- "
    msg -bar
    echo -e "\033[1;93m Despaquetando Shadowsock"
    fun_bar 'sudo apt-get install shadowsocks -y'
    echo -e "\033[1;93m Despaquetando libsodium"
    fun_bar 'sudo apt-get install libsodium-dev -y'
    echo -e "\033[1;93m Despaquetando python-pip"
    fun_bar 'sudo apt-get install python-pip -y'
    echo -e "\033[1;93m Despaquetando setups"
    fun_bar 'sudo pip install --upgrade setuptools'
    echo -e "\033[1;93m Actualizando Ficheros"
    fun_bar 'pip install --upgrade pip -y'
    echo -e "\033[1;93m Revisando Ficheros"
    fun_bar 'pip install https://github.com/shadowsocks/shadowsocks/archive/master.zip -U'
    echo -ne '{\n"server":"' >/etc/shadowsocks.json
    echo -ne "0.0.0.0" >>/etc/shadowsocks.json
    echo -ne '",\n"server_port":' >>/etc/shadowsocks.json
    echo -ne "${Lport},\n" >>/etc/shadowsocks.json
    echo -ne '"local_port":1080,\n"password":"' >>/etc/shadowsocks.json
    echo -ne "${Pass}" >>/etc/shadowsocks.json
    echo -ne '",\n"timeout":600,\n"method":"' >>/etc/shadowsocks.json
    echo -ne "${encriptacao}" >>/etc/shadowsocks.json
    echo -ne '"\n}' >>/etc/shadowsocks.json
    ssserver -c /etc/shadowsocks.json -d start >/dev/null 2>&1
    value=$(ps x | grep ssserver | grep -v grep)
    [[ $value != "" ]] && value="\033[1;32m      >> SHADOW SOCK INSTALADO CON EXITO << " || value="\033[1;31m            ERROR"
    msg -bar
    echo -e "${value}"
    msg -bar
    return 0
  }
  fun_shadowsocks
  ufw disable >/dev/null 2>&1
  read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
  menu_inst
}

#--- SHADOWSOCK LIV + OBFS
proto_shadowsockL() {
  mportas() {
    unset portas
    portas_var=$(lsof -V -i tcp -P -n | grep -v "ESTABLISHED" | grep -v "COMMAND" | grep "LISTEN")
    while read port; do
      var1=$(echo $port | awk '{print $1}') && var2=$(echo $port | awk '{print $9}' | awk -F ":" '{print $2}')
      [[ "$(echo -e $portas | grep "$var1 $var2")" ]] || portas+="$var1 $var2\n"
    done <<<"$portas_var"
    i=1
    echo -e "$portas"
  }
  fun_ip() {
    MEU_IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
    MEU_IP2=$(wget -qO- ipv4.icanhazip.com)
    [[ "$MEU_IP" != "$MEU_IP2" ]] && IP="$MEU_IP2" || IP="$MEU_IP"
  }
  fun_eth() {
    eth=$(ifconfig | grep -v inet6 | grep -v lo | grep -v 127.0.0.1 | grep "encap:Ethernet" | awk '{print $1}')
    [[ $eth != "" ]] && {
      msg -bar
      echo -e "${cor[3]} Aplicar Sistema Para Mejorar Paquetes SSH?"
      echo -e "${cor[3]} Opcion Para Usuarios Avanzados"
      msg -bar
      read -p " [S/N]: " -e -i n sshsn
      [[ "$sshsn" = @(s|S|y|Y) ]] && {
        echo -e "${cor[1]} Correccion de problemas de paquetes en SSH..."
        echo -e " Cual es la Tasa de RX"
        echo -ne "[ 1 - 999999999 ]: "
        read rx
        [[ "$rx" = "" ]] && rx="999999999"
        echo -e " Cual es la Tasa de  TX"
        echo -ne "[ 1 - 999999999 ]: "
        read tx
        [[ "$tx" = "" ]] && tx="999999999"
        apt-get install ethtool -y >/dev/null 2>&1
        ethtool -G $eth rx $rx tx $tx >/dev/null 2>&1
      }
      msg -bar
    }
  }

  #--- SHADOW
  instaladossb_fun() {

    red='\033[0;31m'
    green='\033[0;32m'
    yellow='\033[0;33m'
    plain='\033[0m'

    [[ $EUID -ne 0 ]] && echo -e "[${red}Error${plain}] This script must be run as root!" && exit 1

    cur_dir=$(pwd)
    software=(Shadowsocks-Python ShadowsocksR Shadowsocks-Go Shadowsocks-libev)

    libsodium_file="libsodium-1.0.17"
    libsodium_url="https://github.com/jedisct1/libsodium/releases/download/1.0.17/libsodium-1.0.17.tar.gz"

    mbedtls_file="mbedtls-2.16.0"
    mbedtls_url="https://tls.mbed.org/download/mbedtls-2.16.0-gpl.tgz"

    shadowsocks_python_file="shadowsocks-master"
    shadowsocks_python_url="https://github.com/shadowsocks/shadowsocks/archive/master.zip"
    shadowsocks_python_init="/etc/init.d/shadowsocks-python"
    shadowsocks_python_config="/etc/shadowsocks-python/config.json"
    shadowsocks_python_centos="https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocks"
    shadowsocks_python_debian="https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocks-debian"

    shadowsocks_r_file="shadowsocksr-3.2.2"
    shadowsocks_r_url="https://github.com/shadowsocksrr/shadowsocksr/archive/3.2.2.tar.gz"
    shadowsocks_r_init="/etc/init.d/shadowsocks-r"
    shadowsocks_r_config="/etc/shadowsocks-r/config.json"
    shadowsocks_r_centos="https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocksR"
    shadowsocks_r_debian="https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocksR-debian"

    shadowsocks_go_file_64="shadowsocks-server-linux64-1.2.2"
    shadowsocks_go_url_64="https://dl.lamp.sh/shadowsocks/shadowsocks-server-linux64-1.2.2.gz"
    shadowsocks_go_file_32="shadowsocks-server-linux32-1.2.2"
    shadowsocks_go_url_32="https://dl.lamp.sh/shadowsocks/shadowsocks-server-linux32-1.2.2.gz"
    shadowsocks_go_init="/etc/init.d/shadowsocks-go"
    shadowsocks_go_config="/etc/shadowsocks-go/config.json"
    shadowsocks_go_centos="https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocks-go"
    shadowsocks_go_debian="https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocks-go-debian"

    shadowsocks_libev_init="/etc/init.d/shadowsocks-libev"
    shadowsocks_libev_config="/etc/shadowsocks-libev/config.json"
    shadowsocks_libev_centos="https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocks-libev"
    shadowsocks_libev_debian="https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocks-libev-debian"

    # Stream Ciphers
    common_ciphers=(
      aes-256-gcm
      aes-192-gcm
      aes-128-gcm
      aes-256-ctr
      aes-192-ctr
      aes-128-ctr
      aes-256-cfb
      aes-192-cfb
      aes-128-cfb
      camellia-128-cfb
      camellia-192-cfb
      camellia-256-cfb
      xchacha20-ietf-poly1305
      chacha20-ietf-poly1305
      chacha20-ietf
      chacha20
      salsa20
      rc4-md5
    )
    go_ciphers=(
      aes-256-cfb
      aes-192-cfb
      aes-128-cfb
      aes-256-ctr
      aes-192-ctr
      aes-128-ctr
      chacha20-ietf
      chacha20
      salsa20
      rc4-md5
    )
    r_ciphers=(
      none
      aes-256-cfb
      aes-192-cfb
      aes-128-cfb
      aes-256-cfb8
      aes-192-cfb8
      aes-128-cfb8
      aes-256-ctr
      aes-192-ctr
      aes-128-ctr
      chacha20-ietf
      chacha20
      salsa20
      xchacha20
      xsalsa20
      rc4-md5
    )
    # Reference URL:
    # https://github.com/shadowsocksr-rm/shadowsocks-rss/blob/master/ssr.md
    # https://github.com/shadowsocksrr/shadowsocksr/commit/a3cf0254508992b7126ab1151df0c2f10bf82680
    # Protocol
    protocols=(
      origin
      verify_deflate
      auth_sha1_v4
      auth_sha1_v4_compatible
      auth_aes128_md5
      auth_aes128_sha1
      auth_chain_a
      auth_chain_b
      auth_chain_c
      auth_chain_d
      auth_chain_e
      auth_chain_f
    )
    # obfs
    obfs=(
      plain
      http_simple
      http_simple_compatible
      http_post
      http_post_compatible
      tls1.2_ticket_auth
      tls1.2_ticket_auth_compatible
      tls1.2_ticket_fastauth
      tls1.2_ticket_fastauth_compatible
    )
    # libev obfuscating
    obfs_libev=(http tls)
    # initialization parameter
    libev_obfs=""

    disable_selinux() {
      if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
      fi
    }

    check_sys() {
      local checkType=$1
      local value=$2

      local release=''
      local systemPackage=''

      if [[ -f /etc/redhat-release ]]; then
        release="centos"
        systemPackage="yum"
      elif grep -Eqi "debian|raspbian" /etc/issue; then
        release="debian"
        systemPackage="apt"
      elif grep -Eqi "ubuntu" /etc/issue; then
        release="ubuntu"
        systemPackage="apt"
      elif grep -Eqi "centos|red hat|redhat" /etc/issue; then
        release="centos"
        systemPackage="yum"
      elif grep -Eqi "debian|raspbian" /proc/version; then
        release="debian"
        systemPackage="apt"
      elif grep -Eqi "ubuntu" /proc/version; then
        release="ubuntu"
        systemPackage="apt"
      elif grep -Eqi "centos|red hat|redhat" /proc/version; then
        release="centos"
        systemPackage="yum"
      fi

      if [[ "${checkType}" == "sysRelease" ]]; then
        if [ "${value}" == "${release}" ]; then
          return 0
        else
          return 1
        fi
      elif [[ "${checkType}" == "packageManager" ]]; then
        if [ "${value}" == "${systemPackage}" ]; then
          return 0
        else
          return 1
        fi
      fi
    }

    version_ge() {
      test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" == "$1"
    }

    version_gt() {
      test "$(echo "$@" | tr " " "\n" | sort -V | head -n 1)" != "$1"
    }

    check_kernel_version() {
      local kernel_version=$(uname -r | cut -d- -f1)
      if version_gt ${kernel_version} 3.7.0; then
        return 0
      else
        return 1
      fi
    }

    check_kernel_headers() {
      if check_sys packageManager yum; then
        if rpm -qa | grep -q headers-$(uname -r); then
          return 0
        else
          return 1
        fi
      elif check_sys packageManager apt; then
        if dpkg -s linux-headers-$(uname -r) >/dev/null 2>&1; then
          return 0
        else
          return 1
        fi
      fi
      return 1
    }

    getversion() {
      if [[ -s /etc/redhat-release ]]; then
        grep -oE "[0-9.]+" /etc/redhat-release
      else
        grep -oE "[0-9.]+" /etc/issue
      fi
    }

    centosversion() {
      if check_sys sysRelease centos; then
        local code=$1
        local version="$(getversion)"
        local main_ver=${version%%.*}
        if [ "$main_ver" == "$code" ]; then
          return 0
        else
          return 1
        fi
      else
        return 1
      fi
    }

    autoconf_version() {
      if [ ! "$(command -v autoconf)" ]; then
        echo -e "[${green}Info${plain}] \e[1;97mIniciando instalacion de package autoconf"
        if check_sys packageManager yum; then
          yum install -y autoconf >/dev/null 2>&1 || echo -e "[${red}Error:${plain}] Failed to install autoconf"
        elif check_sys packageManager apt; then
          apt-get -y update >/dev/null 2>&1
          apt-get -y install autoconf >/dev/null 2>&1 || echo -e "[${red}Error:${plain}] Failed to install autoconf"
        fi
      fi
      local autoconf_ver=$(autoconf --version | grep autoconf | grep -oE "[0-9.]+")
      if version_ge ${autoconf_ver} 2.67; then
        return 0
      else
        return 1
      fi
    }

    get_ip() {
      local IP=$(ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1)
      [ -z ${IP} ] && IP=$(wget -qO- -t1 -T2 ipv4.icanhazip.com)
      [ -z ${IP} ] && IP=$(wget -qO- -t1 -T2 ipinfo.io/ip)
      echo ${IP}
    }

    get_ipv6() {
      local ipv6=$(wget -qO- -t1 -T2 ipv6.icanhazip.com)
      [ -z ${ipv6} ] && return 1 || return 0
    }

    get_libev_ver() {
      libev_ver=$(wget --no-check-certificate -qO- https://api.github.com/repos/shadowsocks/shadowsocks-libev/releases/latest | grep 'tag_name' | cut -d\" -f4)
      [ -z ${libev_ver} ] && echo -e "[${red}Error${plain}] Get shadowsocks-libev latest version failed" && exit 1
    }

    get_opsy() {
      [ -f /etc/redhat-release ] && awk '{print ($1,$3~/^[0-9]/?$3:$4)}' /etc/redhat-release && return
      [ -f /etc/os-release ] && awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release && return
      [ -f /etc/lsb-release ] && awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release && return
    }

    is_64bit() {
      if [ $(getconf WORD_BIT) = '32' ] && [ $(getconf LONG_BIT) = '64' ]; then
        return 0
      else
        return 1
      fi
    }

    debianversion() {
      if check_sys sysRelease debian; then
        local version=$(get_opsy)
        local code=${1}
        local main_ver=$(echo ${version} | sed 's/[^0-9]//g')
        if [ "${main_ver}" == "${code}" ]; then
          return 0
        else
          return 1
        fi
      else
        return 1
      fi
    }

    download() {
      local filename=$(basename $1)
      if [ -f ${1} ]; then
        echo "${filename} [found]"
      else
        echo "${filename} not found, download now..."
        wget --no-check-certificate -c -t3 -T60 -O ${1} ${2}
        if [ $? -ne 0 ]; then
          echo -e "[${red}Error${plain}] Download ${filename} failed."
          exit 1
        fi
      fi
    }

    download_files() {
      cd ${cur_dir}

      if [ "${selected}" == "1" ]; then
        download "${shadowsocks_python_file}.zip" "${shadowsocks_python_url}"
        if check_sys packageManager yum; then
          download "${shadowsocks_python_init}" "${shadowsocks_python_centos}"
        elif check_sys packageManager apt; then
          download "${shadowsocks_python_init}" "${shadowsocks_python_debian}"
        fi
      elif [ "${selected}" == "2" ]; then
        download "${shadowsocks_r_file}.tar.gz" "${shadowsocks_r_url}"
        if check_sys packageManager yum; then
          download "${shadowsocks_r_init}" "${shadowsocks_r_centos}"
        elif check_sys packageManager apt; then
          download "${shadowsocks_r_init}" "${shadowsocks_r_debian}"
        fi
      elif [ "${selected}" == "3" ]; then
        if is_64bit; then
          download "${shadowsocks_go_file_64}.gz" "${shadowsocks_go_url_64}"
        else
          download "${shadowsocks_go_file_32}.gz" "${shadowsocks_go_url_32}"
        fi
        if check_sys packageManager yum; then
          download "${shadowsocks_go_init}" "${shadowsocks_go_centos}"
        elif check_sys packageManager apt; then
          download "${shadowsocks_go_init}" "${shadowsocks_go_debian}"
        fi
      elif [ "${selected}" == "4" ]; then
        get_libev_ver
        shadowsocks_libev_file="shadowsocks-libev-$(echo ${libev_ver} | sed -e 's/^[a-zA-Z]//g')"
        shadowsocks_libev_url="https://github.com/shadowsocks/shadowsocks-libev/releases/download/${libev_ver}/${shadowsocks_libev_file}.tar.gz"

        download "${shadowsocks_libev_file}.tar.gz" "${shadowsocks_libev_url}"
        if check_sys packageManager yum; then
          download "${shadowsocks_libev_init}" "${shadowsocks_libev_centos}"
        elif check_sys packageManager apt; then
          download "${shadowsocks_libev_init}" "${shadowsocks_libev_debian}"
        fi
      fi

    }

    get_char() {
      SAVEDSTTY=$(stty -g)
      stty -echo
      stty cbreak
      dd if=/dev/tty bs=1 count=1 2>/dev/null
      stty -raw
      stty echo
      stty $SAVEDSTTY
    }

    error_detect_depends() {
      local command=$1
      local depend=$(echo "${command}" | awk '{print $4}')
      echo -e "[${green}Info${plain}] Starting to install package ${depend}"
      ${command} >/dev/null 2>&1
      if [ $? -ne 0 ]; then
        echo -e "[${red}Error${plain}] Failed to install ${red}${depend}${plain}"
        echo "Please visit: https://teddysun.com/486.html and contact."
        exit 1
      fi
    }

    config_firewall() {
      if centosversion 6; then
        /etc/init.d/iptables status >/dev/null 2>&1
        if [ $? -eq 0 ]; then
          iptables -L -n | grep -i ${shadowsocksport} >/dev/null 2>&1
          if [ $? -ne 0 ]; then
            iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport} -j ACCEPT
            iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport} -j ACCEPT
            /etc/init.d/iptables save
            /etc/init.d/iptables restart
          else
            echo -e "[${green}Info${plain}] port ${green}${shadowsocksport}${plain} already be enabled."
          fi
        else
          echo -e "[${yellow}Warning${plain}] iptables looks like not running or not installed, please enable port ${shadowsocksport} manually if necessary."
        fi
      elif centosversion 7; then
        systemctl status firewalld >/dev/null 2>&1
        if [ $? -eq 0 ]; then
          default_zone=$(firewall-cmd --get-default-zone)
          firewall-cmd --permanent --zone=${default_zone} --add-port=${shadowsocksport}/tcp
          firewall-cmd --permanent --zone=${default_zone} --add-port=${shadowsocksport}/udp
          firewall-cmd --reload
        else
          echo -e "[${yellow}Warning${plain}] firewalld looks like not running or not installed, please enable port ${shadowsocksport} manually if necessary."
        fi
      fi
    }

    config_shadowsocks() {

      if check_kernel_version && check_kernel_headers; then
        fast_open="true"
      else
        fast_open="false"
      fi

      if [ "${selected}" == "1" ]; then
        if [ ! -d "$(dirname ${shadowsocks_python_config})" ]; then
          mkdir -p $(dirname ${shadowsocks_python_config})
        fi
        cat >${shadowsocks_python_config} <<-EOF
{
    "server":"0.0.0.0",
    "server_port":${shadowsocksport},
    "local_address":"127.0.0.1",
    "local_port":1080,
    "password":"${shadowsockspwd}",
    "timeout":300,
    "method":"${shadowsockscipher}",
    "fast_open":${fast_open}
}
EOF
      elif [ "${selected}" == "2" ]; then
        if [ ! -d "$(dirname ${shadowsocks_r_config})" ]; then
          mkdir -p $(dirname ${shadowsocks_r_config})
        fi
        cat >${shadowsocks_r_config} <<-EOF
{
    "server":"0.0.0.0",
    "server_ipv6":"::",
    "server_port":${shadowsocksport},
    "local_address":"127.0.0.1",
    "local_port":1080,
    "password":"${shadowsockspwd}",
    "timeout":120,
    "method":"${shadowsockscipher}",
    "protocol":"${shadowsockprotocol}",
    "protocol_param":"",
    "obfs":"${shadowsockobfs}",
    "obfs_param":"",
    "redirect":"",
    "dns_ipv6":false,
    "fast_open":${fast_open},
    "workers":1
}
EOF
      elif [ "${selected}" == "3" ]; then
        if [ ! -d "$(dirname ${shadowsocks_go_config})" ]; then
          mkdir -p $(dirname ${shadowsocks_go_config})
        fi
        cat >${shadowsocks_go_config} <<-EOF
{
    "server":"0.0.0.0",
    "server_port":${shadowsocksport},
    "local_port":1080,
    "password":"${shadowsockspwd}",
    "method":"${shadowsockscipher}",
    "timeout":300
}
EOF
      elif [ "${selected}" == "4" ]; then
        local server_value="\"0.0.0.0\""
        if get_ipv6; then
          server_value="[\"[::0]\",\"0.0.0.0\"]"
        fi

        if [ ! -d "$(dirname ${shadowsocks_libev_config})" ]; then
          mkdir -p $(dirname ${shadowsocks_libev_config})
        fi

        if [ "${libev_obfs}" == "y" ] || [ "${libev_obfs}" == "Y" ]; then
          cat >${shadowsocks_libev_config} <<-EOF
{
    "server":${server_value},
    "server_port":${shadowsocksport},
    "password":"${shadowsockspwd}",
    "timeout":300,
    "user":"nobody",
    "method":"${shadowsockscipher}",
    "fast_open":${fast_open},
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp",
    "plugin":"obfs-server",
    "plugin_opts":"obfs=${shadowsocklibev_obfs}"
}
EOF
        else
          cat >${shadowsocks_libev_config} <<-EOF
{
    "server":${server_value},
    "server_port":${shadowsocksport},
    "password":"${shadowsockspwd}",
    "timeout":300,
    "user":"nobody",
    "method":"${shadowsockscipher}",
    "fast_open":${fast_open},
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp"
}
EOF
        fi

      fi
    }

    install_dependencies() {
      if check_sys packageManager yum; then
        echo -e "[${green}Info${plain}] Checking the EPEL repository..."
        if [ ! -f /etc/yum.repos.d/epel.repo ]; then
          yum install -y epel-release >/dev/null 2>&1
        fi
        [ ! -f /etc/yum.repos.d/epel.repo ] && echo -e "[${red}Error${plain}] Install EPEL repository failed, please check it." && exit 1
        [ ! "$(command -v yum-config-manager)" ] && yum install -y yum-utils >/dev/null 2>&1
        [ x"$(yum-config-manager epel | grep -w enabled | awk '{print $3}')" != x"True" ] && yum-config-manager --enable epel >/dev/null 2>&1
        echo -e "[${green}Info${plain}] Checking the EPEL repository complete..."

        yum_depends=(
          unzip gzip openssl openssl-devel gcc python python-devel python-setuptools pcre pcre-devel libtool libevent
          autoconf automake make curl curl-devel zlib-devel perl perl-devel cpio expat-devel gettext-devel
          libev-devel c-ares-devel git qrencode
        )
        for depend in ${yum_depends[@]}; do
          error_detect_depends "yum -y install ${depend}"
        done
      elif check_sys packageManager apt; then
        apt_depends=(
          gettext build-essential unzip gzip python python-dev python-setuptools curl openssl libssl-dev
          autoconf automake libtool gcc make perl cpio libpcre3 libpcre3-dev zlib1g-dev libev-dev libc-ares-dev git qrencode
        )

        apt-get -y update
        for depend in ${apt_depends[@]}; do
          error_detect_depends "apt-get -y install ${depend}"
        done
      fi
    }

    install_check() {
      if check_sys packageManager yum || check_sys packageManager apt; then
        if centosversion 5; then
          return 1
        fi
        return 0
      else
        return 1
      fi
    }

    install_select() {
      if ! install_check; then
        echo -e "[${red}Error${plain}] Your OS is not supported to run it!"
        echo "Please change to CentOS 6+/Debian 7+/Ubuntu 12+ and try again."
        exit 1
      fi

      while true; do
        selected=4
        case "${selected}" in
        1 | 2 | 3 | 4)
          echo -e "\e[1;97m   ##Este proceso puede demorar unos minutos##"
          msg -bar
          break
          ;;
        *)
          echo -e "[${red}Error${plain}] Please only enter a number [1-4]"
          ;;
        esac
      done
    }

    install_prepare_password() {
      echo -ne "\033[1;97m Digite una contraseña:\033[1;32m" && read -p " " -e -i latam shadowsockspwd
      [ -z "${shadowsockspwd}" ] && shadowsockspwd="latam"
      msg -bar
      echo -e "\e[1;97m Contraseña Digitada:\e[1;31m ${shadowsockspwd}"
      msg -bar
    }

    install_prepare_port() {
      while true; do
        dport=$(shuf -i 9000-19999 -n 1)
        echo -ne "\033[1;97m Ingrese un puerto: [1-65535]:\033[1;32m" && read -p " " -e -i "3000" shadowsocksport
        [ -z "${shadowsocksport}" ] && shadowsocksport="3000"
        expr ${shadowsocksport} + 1 &>/dev/null
        if [ $? -eq 0 ]; then
          if [ ${shadowsocksport} -ge 1 ] && [ ${shadowsocksport} -le 65535 ] && [ ${shadowsocksport:0:1} != 0 ]; then
            msg -bar
            echo -e "\e[1;97m Puerto Digitada:\e[1;31m ${shadowsocksport}"
            msg -bar
            break
          fi
        fi
        echo -e "[${red}Error${plain}] Digite solo numeros [1-65535]"
      done
    }

    install_prepare_cipher() {
      while true; do
        if [[ "${selected}" == "1" || "${selected}" == "4" ]]; then
          for ((i = 1; i <= ${#common_ciphers[@]}; i++)); do
            hint="${common_ciphers[$i - 1]}"
            echo -e "${green}${i}${plain}) ${hint}"
          done
          msg -bar
          echo -ne "\033[1;97m Elige un cifrado \033[1;32m" && read -p " " -e -i 1 pick
          [ -z "$pick" ] && pick=1
          expr ${pick} + 1 &>/dev/null
          if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] Digite solo numeros"
            continue
          fi
          if [[ "$pick" -lt 1 || "$pick" -gt ${#common_ciphers[@]} ]]; then
            echo -e "[${red}Error${plain}] Digite un numero empezando de 1 ${#common_ciphers[@]}"
            continue
          fi
          shadowsockscipher=${common_ciphers[$pick - 1]}
        elif [ "${selected}" == "2" ]; then
          for ((i = 1; i <= ${#r_ciphers[@]}; i++)); do
            hint="${r_ciphers[$i - 1]}"
            echo -e "${green}${i}${plain}) ${hint}"
          done
          msg -bar
          read -p "¿Qué cifrado elegirías?(Default: ${r_ciphers[1]}):" pick
          [ -z "$pick" ] && pick=2
          expr ${pick} + 1 &>/dev/null
          if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] Please enter a number"
            continue
          fi
          if [[ "$pick" -lt 1 || "$pick" -gt ${#r_ciphers[@]} ]]; then
            echo -e "[${red}Error${plain}] Please enter a number between 1 and ${#r_ciphers[@]}"
            continue
          fi
          shadowsockscipher=${r_ciphers[$pick - 1]}
        elif [ "${selected}" == "3" ]; then
          for ((i = 1; i <= ${#go_ciphers[@]}; i++)); do
            hint="${go_ciphers[$i - 1]}"
            echo -e "${green}${i}${plain}) ${hint}"
          done
          msg -bar
          read -p "¿Qué cifrado elegirías?(Default: ${go_ciphers[0]}):" pick
          [ -z "$pick" ] && pick=1
          expr ${pick} + 1 &>/dev/null
          if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] Please enter a number"
            continue
          fi
          if [[ "$pick" -lt 1 || "$pick" -gt ${#go_ciphers[@]} ]]; then
            echo -e "[${red}Error${plain}] Please enter a number between 1 and ${#go_ciphers[@]}"
            continue
          fi
          shadowsockscipher=${go_ciphers[$pick - 1]}
        fi

        msg -bar
        echo -e "\e[1;97m Cifrado Digitada:\e[1;31m ${shadowsockscipher}"
        msg -bar
        break
      done
    }

    install_prepare_protocol() {
      while true; do
        echo -e "Please select protocol for ${software[${selected} - 1]}:"
        for ((i = 1; i <= ${#protocols[@]}; i++)); do
          hint="${protocols[$i - 1]}"
          echo -e "${green}${i}${plain}) ${hint}"
        done
        read -p "Which protocol you'd select(Default: ${protocols[0]}):" protocol
        [ -z "$protocol" ] && protocol=1
        expr ${protocol} + 1 &>/dev/null
        if [ $? -ne 0 ]; then
          echo -e "[${red}Error${plain}] Please enter a number"
          continue
        fi
        if [[ "$protocol" -lt 1 || "$protocol" -gt ${#protocols[@]} ]]; then
          echo -e "[${red}Error${plain}] Please enter a number between 1 and ${#protocols[@]}"
          continue
        fi
        shadowsockprotocol=${protocols[$protocol - 1]}
        echo
        echo "protocol = ${shadowsockprotocol}"
        echo
        break
      done
    }

    install_prepare_obfs() {
      while true; do
        echo -e "Por favor, seleccione obfs para ${software[${selected} - 1]}:"
        msg -bar
        for ((i = 1; i <= ${#obfs[@]}; i++)); do
          hint="${obfs[$i - 1]}"
          echo -e "${green}${i}${plain}) ${hint}"
        done
        msg -bar
        echo -ne "\033[1;97m Qué obfs elegiras (Default ${obfs[0]}):\033[1;32m" && read -p " " -e -i 1 r_obfs
        [ -z "$r_obfs" ] && r_obfs=1
        expr ${r_obfs} + 1 &>/dev/null
        if [ $? -ne 0 ]; then
          echo -e "[${red}Error${plain}] Digite un numero "
          continue
        fi
        if [[ "$r_obfs" -lt 1 || "$r_obfs" -gt ${#obfs[@]} ]]; then
          echo -e "[${red}Error${plain}] Digite un numero apartir de 1 ${#obfs[@]}"
          continue
        fi
        shadowsockobfs=${obfs[$r_obfs - 1]}
        echo
        echo "obfs = ${shadowsockobfs}"
        echo
        break
      done
    }

    install_prepare_libev_obfs() {
      if autoconf_version || centosversion 6; then
        while true; do
          echo -ne "\033[1;97m Instalar simple-obfs [y/n] (default: n):\033[1;32m" && read -p " " -e -i n libev_obfs
          [ -z "$libev_obfs" ] && libev_obfs=n
          case "${libev_obfs}" in
          y | Y | n | N)
            msg -bar
            echo -e "\e[1;97m Tu eligeste =\e[1;31m ${libev_obfs}"
            msg -bar
            break
            ;;
          *)
            echo -e "[${red}Error${plain}] Digite solo [y/n]"
            ;;
          esac
        done

        if [ "${libev_obfs}" == "y" ] || [ "${libev_obfs}" == "Y" ]; then
          while true; do
            echo -e "\e[97m Por favor, seleccione obfs para simple-obfs:"
            msg -bar
            for ((i = 1; i <= ${#obfs_libev[@]}; i++)); do
              hint="${obfs_libev[$i - 1]}"
              echo -e "${green}${i}${plain}) ${hint}"
            done
            msg -bar
            echo -ne "\033[1;97m Qué obfs elegiras (Default ${obfs_libev[0]}):\033[1;32m" && read -p " " -e -i 1 r_libev_obfs
            [ -z "$r_libev_obfs" ] && r_libev_obfs=1
            expr ${r_libev_obfs} + 1 &>/dev/null
            if [ $? -ne 0 ]; then
              echo -e "[${red}Error${plain}] Digite solo numeros"
              continue
            fi
            if [[ "$r_libev_obfs" -lt 1 || "$r_libev_obfs" -gt ${#obfs_libev[@]} ]]; then
              echo -e "[${red}Error${plain}] digite un numero del 1 a ${#obfs_libev[@]}"
              continue
            fi
            shadowsocklibev_obfs=${obfs_libev[$r_libev_obfs - 1]}
            msg -bar
            echo -e "\e[1;97mOBFS elegido = \e[1;31m${shadowsocklibev_obfs}"
            msg -bar
            break
          done
        fi
      else
        echo -e "[${green}Info${plain}] autoconf version is less than 2.67, simple-obfs for ${software[${selected} - 1]} installation has been skipped"
      fi
    }

    install_prepare() {

      if [[ "${selected}" == "1" || "${selected}" == "3" || "${selected}" == "4" ]]; then
        install_prepare_password
        install_prepare_port
        install_prepare_cipher
        if [ "${selected}" == "4" ]; then
          install_prepare_libev_obfs
        fi
      elif [ "${selected}" == "2" ]; then
        install_prepare_password
        install_prepare_port
        install_prepare_cipher
        install_prepare_protocol
        install_prepare_obfs
      fi
      echo -e "\033[1;93m Se instalaran librerias de cifrado, este proceso \n puede demorar varios minutos"
      msg -bar
      echo -e "\033[1;97m       << Presiona enter para Continuar >>"
      char=$(get_char)

    }

    install_libsodium() {
      if [ ! -f /usr/lib/libsodium.a ]; then
        cd ${cur_dir}
        download "${libsodium_file}.tar.gz" "${libsodium_url}"
        tar zxf ${libsodium_file}.tar.gz
        cd ${libsodium_file}
        ./configure --prefix=/usr && make && make install
        if [ $? -ne 0 ]; then
          echo -e "[${red}Error${plain}] ${libsodium_file} install failed."
          install_cleanup
          exit 1
        fi
      else
        echo -e "[${green}Info${plain}] ${libsodium_file} already installed."
      fi
    }

    install_mbedtls() {
      if [ ! -f /usr/lib/libmbedtls.a ]; then
        cd ${cur_dir}
        download "${mbedtls_file}-gpl.tgz" "${mbedtls_url}"
        tar xf ${mbedtls_file}-gpl.tgz
        cd ${mbedtls_file}
        make SHARED=1 CFLAGS=-fPIC
        make DESTDIR=/usr install
        if [ $? -ne 0 ]; then
          echo -e "[${red}Error${plain}] ${mbedtls_file} install failed."
          install_cleanup
          exit 1
        fi
      else
        echo -e "[${green}Info${plain}] ${mbedtls_file} already installed."
      fi
    }

    install_shadowsocks_python() {
      cd ${cur_dir}
      unzip -q ${shadowsocks_python_file}.zip
      if [ $? -ne 0 ]; then
        echo -e "[${red}Error${plain}] unzip ${shadowsocks_python_file}.zip failed, please check unzip command."
        install_cleanup
        exit 1
      fi

      cd ${shadowsocks_python_file}
      python setup.py install --record /usr/local/shadowsocks_python.log

      if [ -f /usr/bin/ssserver ] || [ -f /usr/local/bin/ssserver ]; then
        chmod +x ${shadowsocks_python_init}
        local service_name=$(basename ${shadowsocks_python_init})
        if check_sys packageManager yum; then
          chkconfig --add ${service_name}
          chkconfig ${service_name} on
        elif check_sys packageManager apt; then
          update-rc.d -f ${service_name} defaults
        fi
      else
        echo
        echo -e "[${red}Error${plain}] ${software[0]} install failed."
        echo "Please visit: https://teddysun.com/486.html and contact."
        install_cleanup
        exit 1
      fi
    }

    install_shadowsocks_r() {
      cd ${cur_dir}
      tar zxf ${shadowsocks_r_file}.tar.gz
      mv ${shadowsocks_r_file}/shadowsocks /usr/local/
      if [ -f /usr/local/shadowsocks/server.py ]; then
        chmod +x ${shadowsocks_r_init}
        local service_name=$(basename ${shadowsocks_r_init})
        if check_sys packageManager yum; then
          chkconfig --add ${service_name}
          chkconfig ${service_name} on
        elif check_sys packageManager apt; then
          update-rc.d -f ${service_name} defaults
        fi
      else
        echo
        echo -e "[${red}Error${plain}] ${software[1]} install failed."
        echo "Please visit; https://teddysun.com/486.html and contact."
        install_cleanup
        exit 1
      fi
    }

    install_shadowsocks_go() {
      cd ${cur_dir}
      if is_64bit; then
        gzip -d ${shadowsocks_go_file_64}.gz
        if [ $? -ne 0 ]; then
          echo -e "[${red}Error${plain}] Decompress ${shadowsocks_go_file_64}.gz failed."
          install_cleanup
          exit 1
        fi
        mv -f ${shadowsocks_go_file_64} /usr/bin/shadowsocks-server
      else
        gzip -d ${shadowsocks_go_file_32}.gz
        if [ $? -ne 0 ]; then
          echo -e "[${red}Error${plain}] Decompress ${shadowsocks_go_file_32}.gz failed."
          install_cleanup
          exit 1
        fi
        mv -f ${shadowsocks_go_file_32} /usr/bin/shadowsocks-server
      fi

      if [ -f /usr/bin/shadowsocks-server ]; then
        chmod +x /usr/bin/shadowsocks-server
        chmod +x ${shadowsocks_go_init}

        local service_name=$(basename ${shadowsocks_go_init})
        if check_sys packageManager yum; then
          chkconfig --add ${service_name}
          chkconfig ${service_name} on
        elif check_sys packageManager apt; then
          update-rc.d -f ${service_name} defaults
        fi
      else
        echo
        echo -e "[${red}Error${plain}] ${software[2]} install failed."
        echo "Please visit: https://teddysun.com/486.html and contact."
        install_cleanup
        exit 1
      fi
    }

    install_shadowsocks_libev() {
      cd ${cur_dir}
      tar zxf ${shadowsocks_libev_file}.tar.gz
      cd ${shadowsocks_libev_file}
      ./configure --disable-documentation && make && make install
      if [ $? -eq 0 ]; then
        chmod +x ${shadowsocks_libev_init}
        local service_name=$(basename ${shadowsocks_libev_init})
        if check_sys packageManager yum; then
          chkconfig --add ${service_name}
          chkconfig ${service_name} on
        elif check_sys packageManager apt; then
          update-rc.d -f ${service_name} defaults
        fi
      else
        echo
        echo -e "[${red}Error${plain}] ${software[3]} install failed."
        echo "Please visit: https://teddysun.com/486.html and contact."
        install_cleanup
        exit 1
      fi
    }

    install_shadowsocks_libev_obfs() {
      if [ "${libev_obfs}" == "y" ] || [ "${libev_obfs}" == "Y" ]; then
        cd ${cur_dir}
        git clone https://github.com/shadowsocks/simple-obfs.git
        [ -d simple-obfs ] && cd simple-obfs || echo -e "[${red}Error:${plain}] Failed to git clone simple-obfs."
        git submodule update --init --recursive
        if centosversion 6; then
          if [ ! "$(command -v autoconf268)" ]; then
            echo -e "[${green}Info${plain}] Starting install autoconf268..."
            yum install -y autoconf268 >/dev/null 2>&1 || echo -e "[${red}Error:${plain}] Failed to install autoconf268."
          fi
          # replace command autoreconf to autoreconf268
          sed -i 's/autoreconf/autoreconf268/' autogen.sh
          # replace #include <ev.h> to #include <libev/ev.h>
          sed -i 's@^#include <ev.h>@#include <libev/ev.h>@' src/local.h
          sed -i 's@^#include <ev.h>@#include <libev/ev.h>@' src/server.h
        fi
        ./autogen.sh
        ./configure --disable-documentation
        make
        make install
        if [ ! "$(command -v obfs-server)" ]; then
          echo -e "[${red}Error${plain}] simple-obfs for ${software[${selected} - 1]} install failed."
          echo "Please visit: https://teddysun.com/486.html and contact."
          install_cleanup
          exit 1
        fi
        [ -f /usr/local/bin/obfs-server ] && ln -s /usr/local/bin/obfs-server /usr/bin
      fi
    }

    install_completed_python() {
      clear && clear
      msg -bar
      ${shadowsocks_python_init} start
      msg -bar
      echo -e "Felicidades, ${green}${software[0]}${plain} instalación del servidor completada!"
      echo -e "Tu Server IP        : ${red} $(get_ip) ${plain}"
      echo -e "Tu Server Port      : ${red} ${shadowsocksport} ${plain}"
      echo -e "Tu Password         : ${red} ${shadowsockspwd} ${plain}"
      echo -e "Tu Encryption Method: ${red} ${shadowsockscipher} ${plain}"
    }

    install_completed_r() {
      clear && clear
      msg -bar
      ${shadowsocks_r_init} start
      msg -bar
      echo -e "Felicidades, ${green}${software[1]}${plain} instalación del servidor completada!"
      echo -e "Tu Server IP        : ${red} $(get_ip) ${plain}"
      echo -e "Tu Server Port      : ${red} ${shadowsocksport} ${plain}"
      echo -e "Tu Password         : ${red} ${shadowsockspwd} ${plain}"
      echo -e "Tu Protocol         : ${red} ${shadowsockprotocol} ${plain}"
      echo -e "Tu obfs             : ${red} ${shadowsockobfs} ${plain}"
      echo -e "Tu Encryption Method: ${red} ${shadowsockscipher} ${plain}"
    }

    install_completed_go() {
      clear
      ${shadowsocks_go_init} start
      msg -bar
      echo -e "Felicidades, ${green}${software[2]}${plain} instalación del servidor completada!"
      echo -e "Tu Server IP        : ${red} $(get_ip) ${plain}"
      echo -e "Tu Server Port      : ${red} ${shadowsocksport} ${plain}"
      echo -e "Tu Password         : ${red} ${shadowsockspwd} ${plain}"
      echo -e "Tu Encryption Method: ${red} ${shadowsockscipher} ${plain}"
    }

    install_completed_libev() {
      clear && clear
      msg -bar
      ldconfig
      ${shadowsocks_libev_init} start
      msg -bar
      echo -e "Felicidades, ${green}${software[3]}${plain} instalación del servidor completada!"
      echo -e "Tu Server IP        : ${red} $(get_ip) ${plain}"
      echo -e "Tu Server Port      : ${red} ${shadowsocksport} ${plain}"
      echo -e "Tu Password         : ${red} ${shadowsockspwd} ${plain}"
      if [ "$(command -v obfs-server)" ]; then
        echo -e "Tu obfs             : ${red} ${shadowsocklibev_obfs} ${plain}"
      fi
      echo -e "Tu Encryption Method: ${red} ${shadowsockscipher} ${plain}"
    }

    qr_generate_python() {
      if [ "$(command -v qrencode)" ]; then
        local tmp=$(echo -n "${shadowsockscipher}:${shadowsockspwd}@$(get_ip):${shadowsocksport}" | base64 -w0)
        local qr_code="ss://${tmp}"
        echo
        echo "Tu QR Code: (For Shadowsocks Windows, OSX, Android and iOS clients)"
        echo -e "${green} ${qr_code} ${plain}"
        echo -n "${qr_code}" | qrencode -s8 -o ${cur_dir}/shadowsocks_python_qr.png
        echo "Tu QR Code has been saved as a PNG file path:"
        echo -e "${green} ${cur_dir}/shadowsocks_python_qr.png ${plain}"
      fi
    }

    qr_generate_r() {
      if [ "$(command -v qrencode)" ]; then
        local tmp1=$(echo -n "${shadowsockspwd}" | base64 -w0 | sed 's/=//g;s/\//_/g;s/+/-/g')
        local tmp2=$(echo -n "$(get_ip):${shadowsocksport}:${shadowsockprotocol}:${shadowsockscipher}:${shadowsockobfs}:${tmp1}/?obfsparam=" | base64 -w0)
        local qr_code="ssr://${tmp2}"
        echo
        echo "Tu QR Code: (For ShadowsocksR Windows, Android clients only)"
        echo -e "${green} ${qr_code} ${plain}"
        echo -n "${qr_code}" | qrencode -s8 -o ${cur_dir}/shadowsocks_r_qr.png
        echo "Tu QR Code has been saved as a PNG file path:"
        echo -e "${green} ${cur_dir}/shadowsocks_r_qr.png ${plain}"
      fi
    }

    qr_generate_go() {
      if [ "$(command -v qrencode)" ]; then
        local tmp=$(echo -n "${shadowsockscipher}:${shadowsockspwd}@$(get_ip):${shadowsocksport}" | base64 -w0)
        local qr_code="ss://${tmp}"
        echo
        echo "Tu QR Code: (For Shadowsocks Windows, OSX, Android and iOS clients)"
        echo -e "${green} ${qr_code} ${plain}"
        echo -n "${qr_code}" | qrencode -s8 -o ${cur_dir}/shadowsocks_go_qr.png
        echo "Tu QR Code has been saved as a PNG file path:"
        echo -e "${green} ${cur_dir}/shadowsocks_go_qr.png ${plain}"
      fi
    }

    qr_generate_libev() {
      if [ "$(command -v qrencode)" ]; then
        local tmp=$(echo -n "${shadowsockscipher}:${shadowsockspwd}@$(get_ip):${shadowsocksport}" | base64 -w0)
        local qr_code="ss://${tmp}"
        echo
        echo "Tu BaseCode:"
        echo -e "${green} ${qr_code} ${plain}"
        echo -n "${qr_code}" | qrencode -s8 -o ${cur_dir}/shadowsocks_libev_qr.png
        echo "Tu QR Code has been saved as a PNG file path:"
        echo -e "${green} ${cur_dir}/shadowsocks_libev_qr.png ${plain}"
      fi
    }

    install_main() {
      install_libsodium
      if ! ldconfig -p | grep -wq "/usr/lib"; then
        echo "/usr/lib" >/etc/ld.so.conf.d/lib.conf
      fi
      ldconfig

      if [ "${selected}" == "1" ]; then
        install_shadowsocks_python
        install_completed_python
        qr_generate_python
      elif [ "${selected}" == "2" ]; then
        install_shadowsocks_r
        install_completed_r
        qr_generate_r
      elif [ "${selected}" == "3" ]; then
        install_shadowsocks_go
        install_completed_go
        qr_generate_go
      elif [ "${selected}" == "4" ]; then
        install_mbedtls
        install_shadowsocks_libev
        install_shadowsocks_libev_obfs
        install_completed_libev
        qr_generate_libev
      fi
    }

    install_cleanup() {
      cd ${cur_dir}
      rm -rf simple-obfs
      rm -rf ${libsodium_file} ${libsodium_file}.tar.gz
      rm -rf ${mbedtls_file} ${mbedtls_file}-gpl.tgz
      rm -rf ${shadowsocks_python_file} ${shadowsocks_python_file}.zip
      rm -rf ${shadowsocks_r_file} ${shadowsocks_r_file}.tar.gz
      rm -rf ${shadowsocks_go_file_64}.gz ${shadowsocks_go_file_32}.gz
      rm -rf ${shadowsocks_libev_file} ${shadowsocks_libev_file}.tar.gz
    }

    install_shadowsocks() {
      disable_selinux
      install_select
      install_prepare
      install_dependencies
      download_files
      config_shadowsocks
      if check_sys packageManager yum; then
        config_firewall
      fi
      install_main
      install_cleanup
    }

    uninstall_shadowsocks_python() {
      printf "Estás seguro de desinstalar ${red}${software[0]}${plain}? [y/n]\n"
      read -p "(default: n):" answer
      [ -z ${answer} ] && answer="n"
      if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        ${shadowsocks_python_init} status >/dev/null 2>&1
        if [ $? -eq 0 ]; then
          ${shadowsocks_python_init} stop
        fi
        local service_name=$(basename ${shadowsocks_python_init})
        if check_sys packageManager yum; then
          chkconfig --del ${service_name}
        elif check_sys packageManager apt; then
          update-rc.d -f ${service_name} remove
        fi

        rm -fr $(dirname ${shadowsocks_python_config})
        rm -f ${shadowsocks_python_init}
        rm -f /var/log/shadowsocks.log
        if [ -f /usr/local/shadowsocks_python.log ]; then
          cat /usr/local/shadowsocks_python.log | xargs rm -rf
          rm -f /usr/local/shadowsocks_python.log
        fi
        echo -e "[${green}Info${plain}] ${software[0]} uninstall success"
      else
        echo
        echo -e "[${green}Info${plain}] ${software[0]} uninstall cancelled, nothing to do..."
        echo
      fi
    }

    uninstall_shadowsocks_r() {
      printf "Estás seguro de desinstalar ${red}${software[1]}${plain}? [y/n]\n"
      read -p "(default: n):" answer
      [ -z ${answer} ] && answer="n"
      if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        ${shadowsocks_r_init} status >/dev/null 2>&1
        if [ $? -eq 0 ]; then
          ${shadowsocks_r_init} stop
        fi
        local service_name=$(basename ${shadowsocks_r_init})
        if check_sys packageManager yum; then
          chkconfig --del ${service_name}
        elif check_sys packageManager apt; then
          update-rc.d -f ${service_name} remove
        fi
        rm -fr $(dirname ${shadowsocks_r_config})
        rm -f ${shadowsocks_r_init}
        rm -f /var/log/shadowsocks.log
        rm -fr /usr/local/shadowsocks
        echo -e "[${green}Info${plain}] ${software[1]} uninstall success"
      else
        echo
        echo -e "[${green}Info${plain}] ${software[1]} uninstall cancelled, nothing to do..."
        echo
      fi
    }

    uninstall_shadowsocks_go() {
      printf "Estás seguro de desinstalar ${red}${software[2]}${plain}? [y/n]\n"
      read -p "(default: n):" answer
      [ -z ${answer} ] && answer="n"
      if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        ${shadowsocks_go_init} status >/dev/null 2>&1
        if [ $? -eq 0 ]; then
          ${shadowsocks_go_init} stop
        fi
        local service_name=$(basename ${shadowsocks_go_init})
        if check_sys packageManager yum; then
          chkconfig --del ${service_name}
        elif check_sys packageManager apt; then
          update-rc.d -f ${service_name} remove
        fi
        rm -fr $(dirname ${shadowsocks_go_config})
        rm -f ${shadowsocks_go_init}
        rm -f /usr/bin/shadowsocks-server
        echo -e "[${green}Info${plain}] ${software[2]} uninstall success"
      else
        echo
        echo -e "[${green}Info${plain}] ${software[2]} uninstall cancelled, nothing to do..."
        echo
      fi
    }

    uninstall_shadowsocks_libev() {
      printf "Estás seguro de desinstalar ${red}${software[3]}${plain}? [y/n]\n"
      read -p "(default: n):" answer
      [ -z ${answer} ] && answer="n"
      if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        ${shadowsocks_libev_init} status >/dev/null 2>&1
        if [ $? -eq 0 ]; then
          ${shadowsocks_libev_init} stop
        fi
        local service_name=$(basename ${shadowsocks_libev_init})
        if check_sys packageManager yum; then
          chkconfig --del ${service_name}
        elif check_sys packageManager apt; then
          update-rc.d -f ${service_name} remove
        fi
        rm -fr $(dirname ${shadowsocks_libev_config})
        rm -f /usr/local/bin/ss-local
        rm -f /usr/local/bin/ss-tunnel
        rm -f /usr/local/bin/ss-server
        rm -f /usr/local/bin/ss-manager
        rm -f /usr/local/bin/ss-redir
        rm -f /usr/local/bin/ss-nat
        rm -f /usr/local/bin/obfs-local
        rm -f /usr/local/bin/obfs-server
        rm -f /usr/local/lib/libshadowsocks-libev.a
        rm -f /usr/local/lib/libshadowsocks-libev.la
        rm -f /usr/local/include/shadowsocks.h
        rm -f /usr/local/lib/pkgconfig/shadowsocks-libev.pc
        rm -f /usr/local/share/man/man1/ss-local.1
        rm -f /usr/local/share/man/man1/ss-tunnel.1
        rm -f /usr/local/share/man/man1/ss-server.1
        rm -f /usr/local/share/man/man1/ss-manager.1
        rm -f /usr/local/share/man/man1/ss-redir.1
        rm -f /usr/local/share/man/man1/ss-nat.1
        rm -f /usr/local/share/man/man8/shadowsocks-libev.8
        rm -fr /usr/local/share/doc/shadowsocks-libev
        rm -f ${shadowsocks_libev_init}
        echo -e "[${green}Info${plain}] ${software[3]} uninstall success"
      else
        echo
        echo -e "[${green}Info${plain}] ${software[3]} uninstall cancelled, nothing to do..."
        echo
      fi
    }

    uninstall_shadowsocks() {
      while true; do
        echo "¿Qué servidor de Shadowsocks quieres desinstalar?"
        msg -bar
        for ((i = 1; i <= ${#software[@]}; i++)); do
          hint="${software[$i - 1]}"
          echo -e "${green}${i}${plain}) ${hint}"
        done
        msg -bar
        read -p "Por favor, introduzca un número[1-4]:" un_select
        case "${un_select}" in
        1 | 2 | 3 | 4)
          msg -bar
          echo "Tu eliges = ${software[${un_select} - 1]}"
          msg -bar
          break
          ;;
        *)
          echo -e "[${red}Error${plain}] Please only enter a number [1-4]"
          ;;
        esac
      done

      if [ "${un_select}" == "1" ]; then
        if [ -f ${shadowsocks_python_init} ]; then
          uninstall_shadowsocks_python
        else
          echo -e "[${red}Error${plain}] ${software[${un_select} - 1]} not installed, please check it and try again."
          echo
          exit 1
        fi
      elif [ "${un_select}" == "2" ]; then
        if [ -f ${shadowsocks_r_init} ]; then
          uninstall_shadowsocks_r
        else
          echo -e "[${red}Error${plain}] ${software[${un_select} - 1]} not installed, please check it and try again."
          echo
          exit 1
        fi
      elif [ "${un_select}" == "3" ]; then
        if [ -f ${shadowsocks_go_init} ]; then
          uninstall_shadowsocks_go
        else
          echo -e "[${red}Error${plain}] ${software[${un_select} - 1]} not installed, please check it and try again."
          echo
          exit 1
        fi
      elif [ "${un_select}" == "4" ]; then
        if [ -f ${shadowsocks_libev_init} ]; then
          uninstall_shadowsocks_libev
        else
          echo -e "[${red}Error${plain}] ${software[${un_select} - 1]} not installed, please check it and try again."
          echo
          exit 1
        fi
      fi
    }

    # Initialization step
    action=$1
    [ -z $1 ] && action=install
    case "${action}" in
    install | uninstall)
      ${action}_shadowsocks
      ;;
    *)
      echo "Arguments error! [${action}]"
      echo "Usage: $(basename $0) [install|uninstall]"
      ;;
    esac

  }

  fun_shadowsocks() {
    [[ -e /etc/shadowsocks-libev/config.json ]] && {
      [[ $(ps ax | grep ss-server | grep -v grep | awk '{print $1}') != "" ]] && kill -9 $(ps ax | grep ss-server | grep -v grep | awk '{print $1}') >/dev/null 2>&1 && ss-server -c /etc/shadowsocks-libev/config.json -d stop >/dev/null 2>&1
      clear && clear
      msg -bar
      echo -e "\033[1;31m          DESINSTALAR SHADOWSOCK-LIB"
      msg -bar
      fun_bar "rm /etc/shadowsocks-libev/config.json "
      msg -bar
      echo -e "\033[1;32m   >> SHADOWSOCK-LIB DESINSTALADO CON EXITO <<"
      msg -bar

      return 0
    }
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    echo -e "\033[1;93m INSTALADOR SHADOWSOCK-LIBEV+(obfs) | SCRIPT LATAM"
    msg -bar
    instaladossb_fun

    rm -rf Instalador-Shadowsocks-libev.sh
    value=$(ps ax | grep ss-server | grep -v grep)
    [[ $value != "" ]] && value="\033[1;32m  >> SHADOWSOCK LIB INSTALADO CON EXITO <<" || value="\033[1;31mERROR"
    msg -bar
    echo -e "${value}"
    msg -bar
    return 0
  }
  fun_shadowsocks

  read -t 180 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
  menu_inst

}

#--- PROTO WEBSOCKET EDITABLE
proto_websockete() {

  activar_websokete() {
    mportas() {
      unset portas
      portas_var=$(lsof -V -i tcp -P -n | grep -v "ESTABLISHED" | grep -v "COMMAND" | grep "LISTEN")
      while read port; do
        var1=$(echo $port | awk '{print $1}') && var2=$(echo $port | awk '{print $9}' | awk -F ":" '{print $2}')
        [[ "$(echo -e $portas | grep "$var1 $var2")" ]] || portas+="$var1 $var2\n"
      done <<<"$portas_var"
      i=1
      echo -e "$portas"
    }
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    echo -e "\033[1;33m  INSTALADOR DE WEBSOCKET EDITABLE | SCRIPT LATAM \033[1;37m"
    msg -bar
    porta_socket=
    while [[ -z $porta_socket || ! -z $(mportas | grep -w $porta_socket) ]]; do
      echo -ne "\033[1;97m Digite el Puerto para el Websoket:\033[1;92m" && read -p " " -e -i "8081" porta_socket
    done
    msg -bar
    echo -ne "\033[1;97m Introduzca el texto de estado plano o en HTML:\n \033[1;31m" && read -p " " -e -i "By SCRIP | LATAM" texto_soket
    msg -bar
    echo -ne "\033[1;97m Digite algun puerto de anclaje\n Puede ser un SSH/DROPBEAR/SSL/OPENVPN:\033[1;92m" && read -p " " -e -i "443" puetoantla
    msg -bar
    echo -ne "\033[1;97m Estatus de encabezado (200,101,404,500,etc):\033[1;92m" && read -p " " -e -i "200" rescabeza
    msg -bar
    (
      less <<PYTHON >/etc/SCRIPT-LATAM/filespy/PDirect-$porta_socket.py
import socket, threading, thread, select, signal, sys, time, getopt

# Listen
LISTENING_ADDR = '0.0.0.0'
if sys.argv[1:]:
  LISTENING_PORT = sys.argv[1]
else:
  LISTENING_PORT = '$porta_socket' 
#Pass
PASS = ''

# CONST
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:$puetoantla'
RESPONSE = 'HTTP/1.1 $rescabeza <strong>$texto_soket</strong>\r\nContent-length: 0\r\n\r\nHTTP/1.1 $rescabeza Connection established\r\n\r\n'
#RESPONSE = 'HTTP/1.1 200 Hello_World!\r\nContent-length: 0\r\n\r\nHTTP/1.1 200 Connection established\r\n\r\n'  # lint:ok

class Server(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
        self.threadsLock = threading.Lock()
        self.logLock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        intport = int(self.port)
        self.soc.bind((self.host, intport))
        self.soc.listen(0)
        self.running = True

        try:
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                except socket.timeout:
                    continue

                conn = ConnectionHandler(c, self, addr)
                conn.start()
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()

    def printLog(self, log):
        self.logLock.acquire()
        print log
        self.logLock.release()

    def addConn(self, conn):
        try:
            self.threadsLock.acquire()
            if self.running:
                self.threads.append(conn)
        finally:
            self.threadsLock.release()

    def removeConn(self, conn):
        try:
            self.threadsLock.acquire()
            self.threads.remove(conn)
        finally:
            self.threadsLock.release()

    def close(self):
        try:
            self.running = False
            self.threadsLock.acquire()

            threads = list(self.threads)
            for c in threads:
                c.close()
        finally:
            self.threadsLock.release()


class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = ''
        self.server = server
        self.log = 'Connection: ' + str(addr)

    def close(self):
        try:
            if not self.clientClosed:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except:
            pass
        finally:
            self.clientClosed = True

        try:
            if not self.targetClosed:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except:
            pass
        finally:
            self.targetClosed = True

    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)

            hostPort = self.findHeader(self.client_buffer, 'X-Real-Host')

            if hostPort == '':
                hostPort = DEFAULT_HOST

            split = self.findHeader(self.client_buffer, 'X-Split')

            if split != '':
                self.client.recv(BUFLEN)

            if hostPort != '':
                passwd = self.findHeader(self.client_buffer, 'X-Pass')
				
                if len(PASS) != 0 and passwd == PASS:
                    self.method_CONNECT(hostPort)
                elif len(PASS) != 0 and passwd != PASS:
                    self.client.send('HTTP/1.1 400 WrongPass!\r\n\r\n')
                elif hostPort.startswith('127.0.0.1') or hostPort.startswith('localhost'):
                    self.method_CONNECT(hostPort)
                else:
                    self.client.send('HTTP/1.1 403 Forbidden!\r\n\r\n')
            else:
                print '- No X-Real-Host!'
                self.client.send('HTTP/1.1 400 NoXRealHost!\r\n\r\n')

        except Exception as e:
            self.log += ' - error: ' + e.strerror
            self.server.printLog(self.log)
	    pass
        finally:
            self.close()
            self.server.removeConn(self)

    def findHeader(self, head, header):
        aux = head.find(header + ': ')

        if aux == -1:
            return ''

        aux = head.find(':', aux)
        head = head[aux+2:]
        aux = head.find('\r\n')

        if aux == -1:
            return ''

        return head[:aux];

    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i+1:])
            host = host[:i]
        else:
            if self.method=='CONNECT':
                port = $puetoantla
            else:
                port = sys.argv[1]

        (soc_family, soc_type, proto, _, address) = socket.getaddrinfo(host, port)[0]

        self.target = socket.socket(soc_family, soc_type, proto)
        self.targetClosed = False
        self.target.connect(address)

    def method_CONNECT(self, path):
        self.log += ' - CONNECT ' + path

        self.connect_target(path)
        self.client.sendall(RESPONSE)
        self.client_buffer = ''

        self.server.printLog(self.log)
        self.doCONNECT()

    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            (recv, _, err) = select.select(socs, [], socs, 3)
            if err:
                error = True
            if recv:
                for in_ in recv:
		    try:
                        data = in_.recv(BUFLEN)
                        if data:
			    if in_ is self.target:
				self.client.send(data)
                            else:
                                while data:
                                    byte = self.target.send(data)
                                    data = data[byte:]

                            count = 0
			else:
			    break
		    except:
                        error = True
                        break
            if count == TIMEOUT:
                error = True
            if error:
                break


def print_usage():
    print 'Usage: proxy.py -p <port>'
    print '       proxy.py -b <bindAddr> -p <port>'
    print '       proxy.py -b 0.0.0.0 -p 80'

def parse_args(argv):
    global LISTENING_ADDR
    global LISTENING_PORT
    
    try:
        opts, args = getopt.getopt(argv,"hb:p:",["bind=","port="])
    except getopt.GetoptError:
        print_usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print_usage()
            sys.exit()
        elif opt in ("-b", "--bind"):
            LISTENING_ADDR = arg
        elif opt in ("-p", "--port"):
            LISTENING_PORT = int(arg)


def main(host=LISTENING_ADDR, port=LISTENING_PORT):
    print "\n:-------PythonProxy-------:\n"
    print "Listening addr: " + LISTENING_ADDR
    print "Listening port: " + str(LISTENING_PORT) + "\n"
    print ":-------------------------:\n"
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print 'Stopping...'
            server.close()
            break

 #######    parse_args(sys.argv[1:])
if __name__ == '__main__':
    main()

PYTHON
    ) >$HOME/proxy.log

    chmod +x /etc/SCRIPT-LATAM/filespy/PDirect.py
    screen -dmS pydic-"$porta_socket" python /etc/SCRIPT-LATAM/filespy/PDirect-$porta_socket.py && echo "$porta_socket" >>/etc/SCRIPT-LATAM/PortM/PDirect.log
    [[ "$(ps x | grep pydic-"$porta_socket" | grep -v grep | awk -F "pts" '{print $1}')" ]] && msg -verd "       >> WEBSOCKET INSTALADO CON EXITO <<" || msg -ama "               ERROR VERIFIQUE"
    msg -bar
  }

  desactivar_websokete() {
    clear && clear
    msg -bar
    echo -e "\033[1;31m              DESINSTALAR WEBSOKET's "
    msg -bar
    for portdic in $(cat /etc/SCRIPT-LATAM/PortM/PDirect.log); do
      echo -e "\e[1;93m Puertos Activos: \e[1;32m$portdic"
    done
    msg -bar
    echo -ne "\033[1;97m Digite el Puero a Desisntalar: \e[1;32m" && read portselect
    screen -wipe >/dev/null 2>&1
    screen -S pydic-"$portselect" -p 0 -X quit
    rm -rf /etc/SCRIPT-LATAM/filespy/PDirect-$portselect.py >/dev/null 2>&1
    sed -i '/'$portselect'/d' /etc/SCRIPT-LATAM/PortM/PDirect.log >/dev/null 2>&1
    msg -bar
    [[ ! "$(ps x | grep pydic-"$portselect" | grep -v grep | awk '{print $1}')" ]] && echo -e "\033[1;32m      >> WEBSOCKET DESINSTALADO CON EXITO << "
    msg -bar
  }

  clear && clear
  msg -bar
  msg -tit
  msg -bar
  echo -e "\033[1;33m INSTALADOR DE WEBSOCKET EDITABLE | SCRIPT LATAM \033[1;37m"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;97m INSTALAR UN PROXY  \e[97m \n"
  echo -ne " \e[1;93m [\e[1;32m2\e[1;93m]\033[1;31m > \033[1;97m DETENER UN PROXY WEBSOCKET's \e[97m \n"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m0\e[1;93m]\033[1;31m > \033[1;97m" && msg -bra "  \e[97m\033[1;41m VOLVER \033[1;37m"
  msg -bar
  echo -ne "\033[1;97mDigite solo el numero segun su respuesta:\e[32m "
  read opcao
  case $opcao in
  1)
    msg -bar
    activar_websokete
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    ;;
  2)
    msg -bar
    desactivar_websokete
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    ;;
  esac
  menu_inst

}

#--- PROXY OPENVPN
proto_popenvpn() {
  activar_openvpn() {
    mportas() {
      unset portas
      portas_var=$(lsof -V -i tcp -P -n | grep -v "ESTABLISHED" | grep -v "COMMAND" | grep "LISTEN")
      while read port; do
        var1=$(echo $port | awk '{print $1}') && var2=$(echo $port | awk '{print $9}' | awk -F ":" '{print $2}')
        [[ "$(echo -e $portas | grep "$var1 $var2")" ]] || portas+="$var1 $var2\n"
      done <<<"$portas_var"
      i=1
      echo -e "$portas"
    }
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    echo -e "\033[1;33m     INSTALADOR DE PROXY OPENVPN | SCRIPT LATAM \033[1;37m"
    msg -bar
    porta_socket=
    while [[ -z $porta_socket || ! -z $(mportas | grep -w $porta_socket) ]]; do
      echo -ne "\033[1;97m Digite el Puerto para el Websoket:\033[1;92m" && read -p " " -e -i "8081" porta_socket
    done
    msg -bar
    echo -ne "\033[1;97m Introduzca el texto de estado plano o en HTML:\n \033[1;31m" && read -p " " -e -i "By SCRIP | LATAM" texto_soket
    msg -bar
    screen -dmS popenvpn-"$porta_socket" python /etc/SCRIPT-LATAM/filespy/POpen.py "$porta_socket" "$texto_soket" && echo ""$porta_socket"" >>/etc/SCRIPT-LATAM/PortM/POpen.log
    [[ "$(ps x | grep POpen.py | grep -v grep | awk '{print $1}')" ]] && msg -verd "     >> PROXY OPENVPN INSTALADO CON EXITO <<" || msg -ama "               ERROR VERIFIQUE"
    msg -bar
  }

  desactivar_popen() {
    clear && clear
    msg -bar
    echo -e "\033[1;31m            DESINSTALAR PROXY OPENVPN "
    msg -bar
    echo -e "\033[1;97m Procesando ...."
    rm -rf /etc/SCRIPT-LATAM/PortM/POpen.log >/dev/null 2>&1
    fun_bar "kill -9 $(ps x | grep POpen.py | grep -v grep | awk '{print $1'}) >/dev/null 2>&1"
    msg -bar
    [[ ! "$(ps x | grep POpen.py | grep -v grep | awk '{print $1}')" ]] && echo -e "\033[1;32m    >> PROXY OPENVPN DESINSTALADO CON EXITO << "
    msg -bar
  }

  clear && clear
  msg -bar
  msg -tit
  msg -bar
  echo -e "\033[1;33m     INSTALADOR DE PROXY OPENVPN | SCRIPT LATAM \033[1;37m"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;97m INSTALAR UN PROXY  \e[97m \n"
  echo -ne " \e[1;93m [\e[1;32m2\e[1;93m]\033[1;31m > \033[1;97m DETENER TODOS LOS PROXY OPENVPN \e[97m \n"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m0\e[1;93m]\033[1;31m > \033[1;97m" && msg -bra "  \e[97m\033[1;41m VOLVER \033[1;37m"
  msg -bar
  echo -ne "\033[1;97mDigite solo el numero segun su respuesta:\e[32m "
  read opcao
  case $opcao in
  1)
    msg -bar
    activar_openvpn
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    ;;
  2)
    msg -bar
    desactivar_popen
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    ;;
  esac
  menu_inst

}

#--- PROXY PUBLICO
proto_ppublico() {

  activar_ppublico() {
    mportas() {
      unset portas
      portas_var=$(lsof -V -i tcp -P -n | grep -v "ESTABLISHED" | grep -v "COMMAND" | grep "LISTEN")
      while read port; do
        var1=$(echo $port | awk '{print $1}') && var2=$(echo $port | awk '{print $9}' | awk -F ":" '{print $2}')
        [[ "$(echo -e $portas | grep "$var1 $var2")" ]] || portas+="$var1 $var2\n"
      done <<<"$portas_var"
      i=1
      echo -e "$portas"
    }
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    echo -e "\033[1;33m     INSTALADOR DE PROXY PUBLICO | SCRIPT LATAM \033[1;37m"
    msg -bar
    porta_socket=
    while [[ -z $porta_socket || ! -z $(mportas | grep -w $porta_socket) ]]; do
      echo -ne "\033[1;97m Digite el Puerto para el P. Publico:\033[1;92m" && read -p " " -e -i "8082" porta_socket
    done
    msg -bar
    echo -ne "\033[1;97m Introduzca el texto de estado plano o en HTML:\n \033[1;31m" && read -p " " -e -i "By SCRIP | LATAM" texto_soket
    msg -bar
    screen -dmS ppublico-"$porta_socket" python /etc/SCRIPT-LATAM/filespy/PPub.py "$porta_socket" "$texto_soket" && echo ""$porta_socket"" >>/etc/SCRIPT-LATAM/PortM/PPub.log
    [[ "$(ps x | grep PPub.py | grep -v grep | awk '{print $1}')" ]] && msg -verd "     >> PROXY PUBLICO INSTALADO CON EXITO <<" || msg -ama "               ERROR VERIFIQUE"
    msg -bar
  }

  desactivar_ppublico() {
    clear && clear
    msg -bar
    echo -e "\033[1;31m            DESINSTALAR PROXY PUBLICO "
    msg -bar
    echo -e "\033[1;97m Procesando ...."
    rm -rf /etc/SCRIPT-LATAM/PortM/PPub.log >/dev/null 2>&1
    fun_bar "kill -9 $(ps x | grep PPub.py | grep -v grep | awk '{print $1'}) >/dev/null 2>&1"
    msg -bar
    [[ ! "$(ps x | grep PPub.py | grep -v grep | awk '{print $1}')" ]] && echo -e "\033[1;32m    >> PROXY PUBLICO DESINSTALADO CON EXITO << "
    msg -bar
  }

  clear && clear
  msg -bar
  msg -tit
  msg -bar
  echo -e "\033[1;33m     INSTALADOR DE PROXY PUBLICO | SCRIPT LATAM \033[1;37m"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;97m INSTALAR UN PROXY PUBLICO  \e[97m \n"
  echo -ne " \e[1;93m [\e[1;32m2\e[1;93m]\033[1;31m > \033[1;97m DETENER TODOS LOS PROXY PUBLICOS \e[97m \n"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m0\e[1;93m]\033[1;31m > \033[1;97m" && msg -bra "  \e[97m\033[1;41m VOLVER \033[1;37m"
  msg -bar
  echo -ne "\033[1;97mDigite solo el numero segun su respuesta:\e[32m "
  read opcao
  case $opcao in
  1)
    msg -bar
    activar_ppublico
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    ;;
  2)
    msg -bar
    desactivar_ppublico
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    ;;
  esac
  menu_inst

}

#--- PROTOCOLO PRIVADO
proto_pprivado() {
  activar_pprivado() {
    meu_ip() {
      MEU_IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
      MEU_IP2=$(wget -qO- ipv4.icanhazip.com)
      [[ "$MEU_IP" != "$MEU_IP2" ]] && echo "$MEU_IP2" || echo "$MEU_IP"
    }
    IP=(meu_ip)
    mportas() {
      unset portas
      portas_var=$(lsof -V -i tcp -P -n | grep -v "ESTABLISHED" | grep -v "COMMAND" | grep "LISTEN")
      while read port; do
        var1=$(echo $port | awk '{print $1}') && var2=$(echo $port | awk '{print $9}' | awk -F ":" '{print $2}')
        [[ "$(echo -e $portas | grep "$var1 $var2")" ]] || portas+="$var1 $var2\n"
      done <<<"$portas_var"
      i=1
      echo -e "$portas"
    }
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    echo -e "\033[1;33m     INSTALADOR DE PROXY PRIVADO | SCRIPT LATAM \033[1;37m"
    msg -bar
    porta_socket=
    while [[ -z $porta_socket || ! -z $(mportas | grep -w $porta_socket) ]]; do
      echo -ne "\033[1;97m Digite el Puerto para el P. Privado:\033[1;92m" && read -p " " -e -i "8083" porta_socket
    done
    msg -bar
    echo -ne "\033[1;97m Introduzca el texto de estado plano o en HTML:\n \033[1;31m" && read -p " " -e -i "By SCRIP | LATAM" texto_soket
    msg -bar
    screen -dmS pprivado-"$porta_socket" python3 /etc/SCRIPT-LATAM/filespy/PPriv.py "$porta_socket" "$texto_soket" "$IP" && echo ""$porta_socket"" >>/etc/SCRIPT-LATAM/PortM/PPriv.log
    [[ "$(ps x | grep PPriv.py | grep -v grep | awk '{print $1}')" ]] && msg -verd "     >> PROXY PRIVADO INSTALADO CON EXITO <<" || msg -ama "               ERROR VERIFIQUE"
    msg -bar
  }

  desactivar_pprivado() {
    clear && clear
    msg -bar
    echo -e "\033[1;31m            DESINSTALAR PROXY PRIVADO "
    msg -bar
    echo -e "\033[1;97m Procesando ...."
    rm -rf /etc/SCRIPT-LATAM/PortM/PPriv.log >/dev/null 2>&1
    fun_bar "kill -9 $(ps x | grep PPriv.py | grep -v grep | awk '{print $1'}) >/dev/null 2>&1"
    msg -bar
    [[ ! "$(ps x | grep PPriv.py | grep -v grep | awk '{print $1}')" ]] && echo -e "\033[1;32m    >> PROXY PUBLICO DESINSTALADO CON EXITO << "
    msg -bar
  }

  clear && clear
  msg -bar
  msg -tit
  msg -bar
  echo -e "\033[1;33m     INSTALADOR DE PROXY PRIVADO | SCRIPT LATAM \033[1;37m"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;97m INSTALAR UN PROXY PRIVADO  \e[97m \n"
  echo -ne " \e[1;93m [\e[1;32m2\e[1;93m]\033[1;31m > \033[1;97m DETENER TODOS LOS PROXY PRIVADOS \e[97m \n"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m0\e[1;93m]\033[1;31m > \033[1;97m" && msg -bra "  \e[97m\033[1;41m VOLVER \033[1;37m"
  msg -bar
  echo -ne "\033[1;97mDigite solo el numero segun su respuesta:\e[32m "
  read opcao
  case $opcao in
  1)
    msg -bar
    activar_pprivado
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    ;;
  2)
    msg -bar
    desactivar_pprivado
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    ;;
  esac
  menu_inst

}

#--- GETTUNEL
proto_pgettunel() {
  activar_gettunel() {
    meu_ip() {
      MEU_IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
      MEU_IP2=$(wget -qO- ipv4.icanhazip.com)
      [[ "$MEU_IP" != "$MEU_IP2" ]] && echo "$MEU_IP2" || echo "$MEU_IP"
    }
    IP=(meu_ip)
    mportas() {
      unset portas
      portas_var=$(lsof -V -i tcp -P -n | grep -v "ESTABLISHED" | grep -v "COMMAND" | grep "LISTEN")
      while read port; do
        var1=$(echo $port | awk '{print $1}') && var2=$(echo $port | awk '{print $9}' | awk -F ":" '{print $2}')
        [[ "$(echo -e $portas | grep "$var1 $var2")" ]] || portas+="$var1 $var2\n"
      done <<<"$portas_var"
      i=1
      echo -e "$portas"
    }
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    echo -e "\033[1;33m     INSTALADOR DE GETTUNEL | SCRIPT LATAM \033[1;37m"
    msg -bar
    porta_socket=
    while [[ -z $porta_socket || ! -z $(mportas | grep -w $porta_socket) ]]; do
      echo -ne "\033[1;97m Digite el Puerto para GETUNNEL\033[1;92m" && read -p " " -e -i "8085" porta_socket
    done
    msg -bar
    echo -ne "\033[1;97m Digite una contraseña:\n \033[1;31m" && read -p " " -e -i "SCRIP-LATAM" passg
    echo "$passg" >/etc/SCRIPT-LATAM/filespy/pwd.pwd
    msg -bar
    while read service; do
      [[ -z $service ]] && break
      echo "127.0.0.1:$(echo $service | cut -d' ' -f2)=$(echo $service | cut -d' ' -f1)"
    done <<<"$(mportas)"
    screen -dmS getpy python /etc/SCRIPT-LATAM/filespy/PGet.py -b "0.0.0.0:porta_socket" -p "/etc/SCRIPT-LATAM/filespy/pwd.pwd"
    [[ "$(ps x | grep PGet.py | grep -v grep | awk '{print $1}')" ]] && msg -verd "      >> GETTUNEL INSTALADO CON EXITO <<" || msg -ama "               ERROR VERIFIQUE"
    msg -bar
  }

  desactivar_gettunel() {
    clear && clear
    msg -bar
    echo -e "\033[1;31m                DESINSTALAR GETTUNEL  "
    msg -bar
    echo -e "\033[1;97m Procesando ...."
    fun_bar "kill -9 $(ps x | grep PGet.py | grep -v grep | awk '{print $1'}) >/dev/null 2>&1"
    msg -bar
    [[ ! "$(ps x | grep PGet.py | grep -v grep | awk '{print $1}')" ]] && echo -e "\033[1;32m      >> GETTUNEL DESINSTALADO CON EXITO << "
    msg -bar
  }

  clear && clear
  msg -bar
  msg -tit
  msg -bar
  echo -e "\033[1;33m       INSTALADOR DE GETTUNEL | SCRIPT LATAM \033[1;37m"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;97m INSTALAR GETTUNEL  \e[97m \n"
  echo -ne " \e[1;93m [\e[1;32m2\e[1;93m]\033[1;31m > \033[1;97m DETENER GETTUNEL \e[97m \n"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m0\e[1;93m]\033[1;31m > \033[1;97m" && msg -bra "  \e[97m\033[1;41m VOLVER \033[1;37m"
  msg -bar
  echo -ne "\033[1;97mDigite solo el numero segun su respuesta:\e[32m "
  read opcao
  case $opcao in
  1)
    msg -bar
    activar_gettunel
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    ;;
  2)
    msg -bar
    desactivar_gettunel
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    ;;
  esac
  menu_inst

}

#--- PROTOCOLO TPOVER
proto_ptcpover() {
  activar_tcpover() {
    meu_ip() {
      MEU_IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
      MEU_IP2=$(wget -qO- ipv4.icanhazip.com)
      [[ "$MEU_IP" != "$MEU_IP2" ]] && echo "$MEU_IP2" || echo "$MEU_IP"
    }
    IP=(meu_ip)
    mportas() {
      unset portas
      portas_var=$(lsof -V -i tcp -P -n | grep -v "ESTABLISHED" | grep -v "COMMAND" | grep "LISTEN")
      while read port; do
        var1=$(echo $port | awk '{print $1}') && var2=$(echo $port | awk '{print $9}' | awk -F ":" '{print $2}')
        [[ "$(echo -e $portas | grep "$var1 $var2")" ]] || portas+="$var1 $var2\n"
      done <<<"$portas_var"
      i=1
      echo -e "$portas"
    }
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    echo -e "\033[1;33m     INSTALADOR DE TCPOVER | SCRIPT LATAM \033[1;37m"
    msg -bar
    porta_socket=
    while [[ -z $porta_socket || ! -z $(mportas | grep -w $porta_socket) ]]; do
      echo -ne "\033[1;97m Digite el Puerto para el TCPOVER:\033[1;92m" && read -p " " -e -i "8888" porta_socket
    done
    msg -bar
    echo -ne "\033[1;97m Digite una banner txt:\n \033[1;31m" && read -p " " -e -i "SCRIP-LATAM" passg
    msg -bar
    while read service; do
      [[ -z $service ]] && break
      echo "127.0.0.1:$(echo $service | cut -d' ' -f2)=$(echo $service | cut -d' ' -f1)"
    done <<<"$(mportas)"
    [[ -e $HOME/socks ]] && rm -rf $HOME/socks >/dev/null 2>&1
    [[ -d $HOME/socks ]] && rm -rf $HOME/socks >/dev/null 2>&1
    cd $HOME && mkdir socks >/dev/null 2>&1
    cd socks
    patch="https://raw.githubusercontent.com/NetVPS/LATAM_Oficial/main/Ejecutables/backsocz.zip"
    arq="backsocz.zip"
    wget $patch >/dev/null 2>&1
    unzip $arq >/dev/null 2>&1
    mv -f /root/socks/backsocz/./ssh /etc/ssh/sshd_config && service ssh restart 1>/dev/null 2>/dev/null
    mv -f /root/socks/backsocz/sckt$(python3 --version | awk '{print $2}' | cut -d'.' -f1,2) /usr/sbin/sckt
    mv -f /root/socks/backsocz/scktcheck /bin/scktcheck
    chmod +x /bin/scktcheck
    chmod +x /usr/sbin/sckt
    rm -rf $HOME/root/socks
    cd $HOME
    screen -dmS sokz scktcheck "$porta_socket" "$passg" >/dev/null 2>&1
    [[ "$(ps x | grep scktcheck | grep -v grep | awk '{print $1}')" ]] && msg -verd "         >> TCPOVER INSTALADO CON EXITO <<" || msg -ama "               ERROR VERIFIQUE"
    msg -bar
  }

  desactivar_gettunel() {
    clear && clear
    msg -bar
    echo -e "\033[1;31m                DESINSTALAR TCPOVER  "
    msg -bar
    echo -e "\033[1;97m Procesando ...."
    fun_bar "kill -9 $(ps x | grep scktcheck | grep -v grep | awk '{print $1'}) >/dev/null 2>&1"
    msg -bar
    [[ ! "$(ps x | grep scktcheck | grep -v grep | awk '{print $1}')" ]] && echo -e "\033[1;32m       >> TCPOVER DESINSTALADO CON EXITO << "
    msg -bar
  }

  clear && clear
  msg -bar
  msg -tit
  msg -bar
  echo -e "\033[1;33m       INSTALADOR DE GETTUNEL | SCRIPT LATAM \033[1;37m"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;97m INSTALAR TCPOVER  \e[97m \n"
  echo -ne " \e[1;93m [\e[1;32m2\e[1;93m]\033[1;31m > \033[1;97m DETENER TCPOVER \e[97m \n"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m0\e[1;93m]\033[1;31m > \033[1;97m" && msg -bra "  \e[97m\033[1;41m VOLVER \033[1;37m"
  msg -bar
  echo -ne "\033[1;97mDigite solo el numero segun su respuesta:\e[32m "
  read opcao
  case $opcao in
  1)
    msg -bar
    activar_tcpover
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    ;;
  2)
    msg -bar
    desactivar_gettunel
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    ;;
  esac
  menu_inst

}

#--- SLOWN DNS
proto_slowndns() {
  mkdir -p /etc/SCRIPT-LATAM/temp/SlowDNS/install >/dev/null 2>&1
  mkdir -p /etc/SCRIPT-LATAM/temp/SlowDNS/Key >/dev/null 2>&1
  SlowDNSinstall="/etc/SCRIPT-LATAM/temp/SlowDNS/install"
  SlowDNSconf="/etc/SCRIPT-LATAM/temp/SlowDNS/Key"
  info() {

    nodata() {
      msg -bar
      echo -e "\e[1;91m        NOSE CUENTA CON REGISTRO DE SLOWDNS"
      return 1
    }
    echo -e "\e[1;97m        INFORMACION DE SU CONECCION SLOWDNS"
    [[ -e ${SlowDNSconf}/domain_ns ]] && msg -ama "Su NS (Nameserver): $(cat ${SlowDNSconf}/domain_ns)" || nodata
    [[ -e ${SlowDNSconf}/server.pub ]] && msg -ama "Su Llave: $(cat ${SlowDNSconf}/server.pub)"
  }

  drop_port() {
    local portasVAR=$(lsof -V -i tcp -P -n | grep -v "ESTABLISHED" | grep -v "COMMAND" | grep "LISTEN")
    local NOREPEAT
    local reQ
    local Port
    unset DPB
    while read port; do
      reQ=$(echo ${port} | awk '{print $1}')
      Port=$(echo {$port} | awk '{print $9}' | awk -F ":" '{print $2}')
      [[ $(echo -e $NOREPEAT | grep -w "$Port") ]] && continue
      NOREPEAT+="$Port\\n"

      case ${reQ} in
      sshd | dropbear | trojan | stunnel4 | stunnel | python | python3 | v2ray | xray) DPB+=" $reQ:$Port" ;;
      *) continue ;;
      esac
    done <<<"${portasVAR}"
  }

  ini_slow() {
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    msg -bra "               INSTALADOR SLOWDNS"
    msg -bar
    drop_port
    n=1
    for i in $DPB; do
      proto=$(echo $i | awk -F ":" '{print $1}')
      proto2=$(printf '%-12s' "$proto")
      port=$(echo $i | awk -F ":" '{print $2}')
      echo -e " \e[1;93m [\e[1;32m$n\e[1;93m]\033[1;31m $(msg -verm2 ">") $(msg -ama "$proto2")$(msg -azu "$port")"
      drop[$n]=$port
      num_opc="$n"
      let n++
    done
    msg -bar
    opc=$(selection_fun $num_opc)
    echo "${drop[$opc]}" >${SlowDNSconf}/puerto
    PORT=$(cat ${SlowDNSconf}/puerto)
    msg -bra "              INSTALADOR SLOWDNS"
    msg -bar
    echo -e " $(msg -ama "Puerto de coneccion atraves de SlowDNS:") $(msg -verd "$PORT")"
    msg -bar

    unset NS
    while [[ -z $NS ]]; do
      echo -ne "\e[1;93m Tu dominio NS: \e[1;31m" && read NS
      tput cuu1 && tput dl1
    done
    echo "$NS" >${SlowDNSconf}/domain_ns
    echo -e " $(msg -ama "Tu dominio NS:") $(msg -verd "$NS")"
    msg -bar

    if [[ ! -e ${SlowDNSinstall}/dns-server ]]; then
      msg -ama " Descargando ejecutable SlowDNS"
      if wget -O ${SlowDNSinstall}/dns-server https://raw.githubusercontent.com/NetVPS/LATAM_Oficial/main/Ejecutables/dns-server &>/dev/null; then
        chmod +x ${SlowDNSinstall}/dns-server
        msg -verd "[OK]"
      else
        msg -verm "[fail]"
        msg -bar
        msg -ama "No se pudo descargar el binario"
        msg -verm "Instalacion canselada"
      fi
      msg -bar
    fi

    [[ -e "${SlowDNSconf}/server.pub" ]] && pub=$(cat ${SlowDNSconf}/server.pub)

    if [[ ! -z "$pub" ]]; then
      echo -ne "\e[1;93m Usar clave existente [S/N]: \e[1;32m" && read ex_key

      case $ex_key in
      s | S | y | Y)
        tput cuu1 && tput dl1
        echo -e " $(msg -ama "Tu clave:") $(msg -verd "$(cat ${SlowDNSconf}/server.pub)")"
        ;;
      n | N)
        tput cuu1 && tput dl1
        rm -rf ${SlowDNSconf}/server.key
        rm -rf ${SlowDNSconf}/server.pub
        ${SlowDNSinstall}/dns-server -gen-key -privkey-file ${SlowDNSconf}/server.key -pubkey-file ${SlowDNSconf}/server.pub &>/dev/null
        echo -e " $(msg -ama "Tu clave:") $(msg -verd "$(cat ${SlowDNSconf}/server.pub)")"
        ;;
      *) ;;
      esac
    else
      rm -rf ${SlowDNSconf}/server.key
      rm -rf ${SlowDNSconf}/server.pub
      ${SlowDNSinstall}/dns-server -gen-key -privkey-file ${SlowDNSconf}/server.key -pubkey-file ${SlowDNSconf}/server.pub &>/dev/null
      echo -e " $(msg -ama "Tu clave:") $(msg -verd "$(cat ${SlowDNSconf}/server.pub)")"
    fi
    msg -bar
    msg -ama "   Iniciando SlowDNS...."

    iptables -I INPUT -p udp --dport 5300 -j ACCEPT
    iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
    echo "nameserver 1.1.1.1 " >/etc/resolv.conf
    echo "nameserver 1.0.0.1 " >>/etc/resolv.conf

    if screen -dmS slowdns ${SlowDNSinstall}/dns-server -udp :5300 -privkey-file ${SlowDNSconf}/server.key $NS 127.0.0.1:$PORT; then
      msg -verd "              >> INSTALADO CON EXITO <<"
    else
      msg -verm "Con fallo!!!"
    fi

  }

  reset_slow() {
    clear && clear
    msg -bar
    msg -ama "                REINICIANDO SLOWDNS...."
    screen -S slowdns -p 0 -X quit
    [[ -e ${SlowDNSconf}/domain_ns ]] && NS=$(cat ${SlowDNSconf}/domain_ns)
    [[ -e ${SlowDNSconf}/puerto ]] && PORT=$(cat ${SlowDNSconf}/puerto)
    screen -dmS slowdns ${SlowDNSinstall}/dns-server -udp :5300 -privkey-file /root/server.key $NS 127.0.0.1:$PORT
    msg -verd "              >> REINICIADO CON EXITO << "

  }
  stop_slow() {

    echo -e "\e[1;31m                DESISNTALAR SLOWDNS"
    screen -S slowdns -p 0 -X quit
    msg -verd "            >> DESINSTALADO CON EXITO << "

  }
  clear && clear
  msg -bar
  msg -tit
  msg -bar
  echo -e "\e[1;93m                INSTALADOR SLOWNDNS"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;97m INSTALAR SLOWDNS\e[97m \n"
  echo -ne " \e[1;93m [\e[1;32m2\e[1;93m]\033[1;31m > \033[1;97m REINICIAR SLOWDNS \e[97m \n"
  echo -ne " \e[1;93m [\e[1;32m3\e[1;93m]\033[1;31m > \033[1;97m INFORMACON \e[97m \n"
  echo -ne " \e[1;93m [\e[1;32m4\e[1;93m]\033[1;31m > \033[1;97m DETENER SLOWNDNS \e[97m \n"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m0\e[1;93m]\033[1;31m > \033[1;97m" && msg -bra "  \e[97m\033[1;41m VOLVER \033[1;37m"
  msg -bar
  echo -ne "\033[1;97mDigite solo el numero segun su respuesta:\e[32m "
  read opcao
  tput cuu1 && tput dl1
  case $opcao in

  1)
    ini_slow
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    proto_slowndns
    ;;
  2)
    reset_slow
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    proto_slowndns
    ;;
  3)
    info
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    proto_slowndns
    ;;
  4)
    stop_slow
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    proto_slowndns
    ;;
  *)
    menu_inst
    ;;
  esac

}

#--- PROTOCOLO SSLH
sshl_install() {
  clear && clear
  declare -A cor=([0]="\033[1;37m" [1]="\033[1;34m" [2]="\033[1;31m" [3]="\033[1;33m" [4]="\033[1;32m")
  mportas() {
    unset portas
    portas_var=$(lsof -V -i tcp -P -n | grep -v "ESTABLISHED" | grep -v "COMMAND" | grep "LISTEN")
    while read port; do
      var1=$(echo $port | awk '{print $1}') && var2=$(echo $port | awk '{print $9}' | awk -F ":" '{print $2}')
      [[ "$(echo -e $portas | grep "$var1 $var2")" ]] || portas+="$var1 $var2\n"
    done <<<"$portas_var"
    i=1
    echo -e "$portas"
  }
  sslh_inicial() {
    clear && clear
    [[ $(dpkg --get-selections | grep -w "sslh" | head -1) ]] && {
      msg -bar
      echo -e "\033[1;31m                 DESINSTALANDO SSLH"
      msg -bar
      service sslh stop >/dev/null 2>&1
      fun_bar "apt-get purge sslh -y"
      msg -bar
      echo -e "\033[1;32m        >> SSLH DESINSTALADO  CON EXITO <<"
      msg -bar
      return 0
    }
    msg -bar
    msg -tit
    msg -bar
    echo -e "\033[1;93m           INSTALADOR SSLH SCRIPT LATAM"
    msg -bar
    echo -e "\033[1;32m                 Instalando SSLH"
    msg -bar
    echo -e "\033[1;97m A continuacion se le pedira tipo de instalacion\nescojer \033[1;31mstandalone \033[1;97my dar ENTER"
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m  Presiona enter para Continuar \n'
    msg -bar
    clear && clear
    apt-get install sslh -y
    msg -bar
    msg -verd "              >> INSTALADO CON EXITO <<"
    msg -bar
    return 0
  }

  edit_sslh() {
    clear && clear
    service sslh stop >/dev/null 2>&1
    msg -bar
    msg -tit
    msg -bar
    echo -e "\033[1;32m              CONFIGURAR E INICIAR SSLH"
    msg -bar
    while true; do
      echo -ne "\033[1;97m Puerto principal SSLH:\033[1;32m" && read -p " " -e -i "443" SSLHPORT
      [[ $(mportas | grep -w "$SSLHPORT") ]] || break
      echo -e "\033[1;33m Este Puerto esta en uso usar Otro"
      sleep 5s
      tput cuu1 && tput dl1
      tput cuu1 && tput dl1
      unset SSLPORT
    done
    #SELECC PORT SSH
    portssh() {
      echo 'DAEMON=/usr/sbin/sslh' >/etc/default/sslh
      echo 'Run=yes' >>/etc/default/sslh
      chmod +x /etc/default/sslh
      echo -ne "\033[1;97m -- > \033[1;93m Cual es su Puerto SSH:\033[1;32m" && read -p " " -e -i "22" SSHPORT
      PORTSSHF="--ssh 127.0.0.1:$SSHPORT"
    }
    portssl() {
      echo -ne "\033[1;97m -- > \033[1;93m Cual es su Puerto SSL:\033[1;32m" && read -p " " -e -i "442" SSLPORT
      PORTSSLF="--ssl 127.0.0.1:$SSLPORT"
    }
    portopenvpn() {
      echo -ne "\033[1;97m -- > \033[1;93m Cual es su Puerto SSL:\033[1;32m" && read -p " " -e -i "1194" OPENVPNPORT
      PORTOPENVPNF="--openvpn 127.0.0.1:$OPENVPNPORT"
    }
    portauto() {
      echo -ne "\033[1;97m -- > \033[1;93m Cual es su Puerto AUTOMATICO:\033[1;32m" && read -p " " -e -i "80" AUTOMATICO
      AUTOMATICO="--anyprot 127.0.0.1:$AUTOMATICO"
    }
    echo -ne "\n\e[1;96m Agregar Port SSH\e[1;93m [\033[1;97m s \033[1;93m| \033[1;97mn \033[1;93m]\033[1;97m: \e[1;32m" && read portssh
    echo 'DAEMON=/usr/sbin/sslh' >/etc/default/sslh
    echo 'Run=yes' >>/etc/default/sslh
    chmod +x /etc/default/sslh
    [[ "$portssh" = "s" || "$portssh" = "S" ]] && portssh
    echo -ne "\e[1;96m Agregar Port SSL\e[1;93m [\033[1;97m s \033[1;93m| \033[1;97mn \033[1;93m]\033[1;97m: \e[1;32m" && read portssl
    [[ "$portssl" = "s" || "$portssl" = "S" ]] && portssl
    echo -ne "\e[1;96m Agregar Port OPENVPN\e[1;93m [\033[1;97m s \033[1;93m| \033[1;97mn \033[1;93m]\033[1;97m: \e[1;32m" && read portopenvpn
    [[ "$portopenvpn" = "s" || "$portopenvpn" = "S" ]] && portopenvpn
    echo -ne "\e[1;96m Agregar Port AUTOMATICO\e[1;93m [\033[1;97m s \033[1;93m| \033[1;97mn \033[1;93m]\033[1;97m: \e[1;32m" && read portauto
    [[ "$portauto" = "s" || "$portauto" = "S" ]] && portauto

    echo 'DAEMON_OPTS="--user sslh --listen 0.0.0.0:'$SSLHPORT' '$PORTSSHF' '$PORTSSLF' '$PORTOPENVPNF' '$AUTOMATICO' --pidfile /var/run/sslh/sslh.pid"' >>/etc/default/sslh
    service sslh restart
    sleep 3s
    msg -bar
    SSLH=$(ps -ef | grep "/var/run/sslh/sslh.pid" | grep -v grep | awk -F "pts" '{print $1}')
    [[ -z ${SSLH} ]] && SSLH="\033[1;31m               >> FALLO << " || SSLH="\033[1;32m           >> SSLH INSTALADO CON EXITO << "
    echo -e "$SSLH"
    msg -bar
    return 0
  }

  clear && clear
  msg -bar
  msg -tit
  msg -bar
  echo -e "\e[1;93m          INSTALADOR DE SSLH | SCRIPT LATAM"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;97m INSTALAR | DESISNTALAR SSLH \e[97m \n"
  echo -ne " \e[1;93m [\e[1;32m2\e[1;93m]\033[1;31m > \033[1;97m EDITAR PUERTOS SSLH\e[97m \n"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m0\e[1;93m]\033[1;31m > \033[1;97m" && msg -bra "  \e[97m\033[1;41m VOLVER \033[1;37m"
  msg -bar
  echo -ne "\033[1;97mDigite solo el numero segun su respuesta:\e[32m "
  read opcao
  case $opcao in
  1)
    msg -bar
    sslh_inicial
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    sshl_install
    ;;
  2)
    msg -bar
    edit_sslh
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    sshl_install
    ;;
  esac
  menu_inst
}
##-->>PROTOCOLO UDP SERVER
udp_serverr() {

  activar_badvpn() {
    mportas() {
      unset portas
      portas_var=$(lsof -V -i tcp -P -n | grep -v "ESTABLISHED" | grep -v "COMMAND" | grep "LISTEN")
      while read port; do
        var1=$(echo $port | awk '{print $1}') && var2=$(echo $port | awk '{print $9}' | awk -F ":" '{print $2}')
        [[ "$(echo -e $portas | grep "$var1 $var2")" ]] || portas+="$var1 $var2\n"
      done <<<"$portas_var"
      i=1
      echo -e "$portas"
    }
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    msg -ama "            INSTALADOR DE UDP-REQUEST"
    msg -bar
    echo -e "\033[1;97mDigite los puertos a activar de forma secuencial\nEjemplo:\033[1;32m 53 5300 5200 \033[1;97m| \033[1;93mPuerto recomendado \033[1;32m 5300\n"
    echo -ne "\033[1;97mDigite los Puertos:\033[1;32m " && read -p " " -e -i "53 5300" portasx
    echo "$portasx" >/etc/SCRIPT-LATAM/PortM/UDP-server.log
    msg -bar
    totalporta=($portasx)
    unset PORT
    for ((i = 0; i < ${#totalporta[@]}; i++)); do
      [[ $(mportas | grep "${totalporta[$i]}") = "" ]] && {
        PORT+="${totalporta[$i]}\n"
        ip_nat=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n 1p)
        interfas=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | grep "$ip_nat" | awk {'print $NF'})
        ip_publica=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<<"$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
        cat <<EOF >/etc/systemd/system/UDPserver.service
[Unit]
Description=UDPserver Service by LATAM
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root
ExecStart=/usr/bin/udpServer -ip=$ip_publica -net=$interfas -exclude=${totalporta[$i]} -mode=system
Restart=always
RestartSec=3s

[Install]
WantedBy=multi-user.target6
EOF

        systemctl start UDPserver &>/dev/null
        echo -e "\033[1;33m Puerto Escojido:\033[1;32m ${totalporta[$i]} OK"
      } || {
        echo -e "\033[1;33m Puerto Escojido:\033[1;31m ${totalporta[$i]} FAIL"
      }
    done
    [[ -z $PORT ]] && {
      echo -e "\033[1;31m  No se ha elegido ninguna puerto valido, reintente\033[0m"
      return 1
    }
    sleep 3s
    msg -bar

    [[ "$(ps x | grep /usr/bin/udpServer | grep -v grep | awk '{print $1}')" ]] && msg -verd "        >> UDP-SERVER INSTALADO CON EXITO <<" || msg -ama "               ERROR VERIFIQUE"
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    menu_inst
  }

  desactivar_badvpn() {
    clear && clear
    msg -bar
    echo -e "\033[1;31m            DESISNTALANDO PUERTOS UDP-SERVER "
    msg -bar
    systemctl stop UDPserver &>/dev/null
    systemctl disable UDPserver &>/dev/null
    rm -rf /etc/systemd/system/UDPserver.service &>/dev/null
    rm -rf /usr/bin/udpServer
    rm -rf /etc/SCRIPT-LATAM/PortM/UDP-server.log
    [[ ! "$(ps x | grep "/usr/bin/udpServer" | grep -v grep | awk '{print $1}')" ]] && echo -e "\033[1;32m        >> UDP-SERVER DESINSTALADO CON EXICO << "
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    menu_inst
  }

  clear && clear
  msg -bar
  msg -tit
  msg -bar
  msg -ama "            INSTALADOR DE UDP-REQUEST"
  msg -bar
  if [[ ! -e /usr/bin/udpServer ]]; then
    wget -O /usr/bin/udpServer 'https://bitbucket.org/iopmx/udprequestserver/downloads/udpServer' &>/dev/null
    chmod +x /usr/bin/udpServer
  fi
  echo -ne " \e[1;93m [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;97m INSTALAR UDP-SERVER  \e[97m \n"
  echo -ne " \e[1;93m [\e[1;32m2\e[1;93m]\033[1;31m > \033[1;97m DETENER TODOS LOS UDP-SERVER\e[97m \n"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m0\e[1;93m]\033[1;31m > \033[1;97m" && msg -bra "  \e[97m\033[1;41m VOLVER \033[1;37m"
  msg -bar
  echo -ne "\033[1;97mDigite solo el numero segun su respuesta:\e[32m "
  read opcao
  case $opcao in
  1)
    msg -bar
    activar_badvpn
    ;;
  2)
    msg -bar
    desactivar_badvpn
    ;;
  0)
    menu
    ;;
  *)
    echo -e "$ Porfavor use numeros del [0-14]"
    msg -bar
    menu
    ;;
  esac

  #exit 0
}
server_psiphones() {

  install_psiphone() {

    clear && clear
    if ps aux | grep 'psiphond' | grep -v grep >/dev/null; then
      echo "El proceso psiphond ya está activo."
      exit 1
    fi

    msg -bar
    msg -tit
    msg -bar
    msg -ama "            INSTALADOR DE SERVR-PSIPHONE"
    msg -bar
    echo -e "\033[1;97m Ingrese los puertos segun su necesidad\033[1;97m\n"
    #echo -e "\033[1;97mDigite los puertos a activar \033[1;97m | \033[1;93mPuerto recomendados \033[1;32m 5300\n"
    #echo -ne "\033[1;97mDigite los Puertos:\033[1;32m " && read -p " " -e -i "22" portasx
    #echo "$portasx" >/etc/SCRIPT-LATAM/PortM/UDP-server.log

    #tput cuu1 && tput dl1

    rm -rf /root/psi
    kill $(ps aux | grep 'psiphond' | awk '{print $2}') 1>/dev/null 2>/dev/null
    killall psiphond 1>/dev/null 2>/dev/null
    mkdir -p /root/psi
    cd /root/psi
    ship=$(wget -qO- ifconfig.me)
    wget -O /root/psi/psiphond https://raw.githubusercontent.com/Psiphon-Labs/psiphon-tunnel-core-binaries/master/psiphond/psiphond &>/dev/null
    chmod +rwx /root/psi/psiphond
    echo -ne "\033[1;97m Escribe el puerto para Psiphon SSH:\033[32m " && read -p " " -e -i "3001" sh
    echo -ne "\033[1;97m Escribe el puerto para Psiphon OSSH:\033[32m " && read -p " " -e -i "3002" osh
    echo -ne "\033[1;97m Escribe el puerto para Psiphon FRONTED-MEEK:\033[32m " && read -p " " -e -i "443" fm
    echo -ne "\033[1;97m Escribe el puerto para Psiphon WEB:\033[32m " && read -p " " -e -i "3000" wb
    #echo -ne "\033[1;97m Escribe el puerto para Psiphon UNFRONTED-MEEK:\033[32m " && read umo
    #./psiphond --ipaddress $ship --protocol SSH:$sh --protocol OSSH:$osh --protocol FRONTED-MEEK-OSSH:$fm --protocol UNFRONTED-MEEK-OSSH:$umo generate
    ./psiphond --ipaddress $ship --web $wb --protocol SSH:$sh --protocol OSSH:$osh --protocol FRONTED-MEEK-OSSH:$fm generate
    
    chmod 666 psiphond.config
    chmod 666 psiphond-traffic-rules.config
    chmod 666 psiphond-osl.config
    chmod 666 psiphond-tactics.config
    chmod 666 server-entry.dat
    cat server-entry.dat >/root/psi.txt
    screen -dmS psiserver ./psiphond run
    cd /root
    psi=$(cat /root/psi.txt)
    echo -e "\033[1;33m LA CONFIGURACION DE TU SERVIDOR ES:\033[0m"
    msg -bar
    echo -e "\033[1;32m $psi \033[0m"
    msg -bar
    echo -e "\033[1;33m PROTOCOLOS HABILITADOS:\033[0m"
    echo -e "\033[1;33m → SSH:\033[1;32m $sh \033[0m"
    echo -e "\033[1;33m → OSSH:\033[1;32m $osh \033[0m"
    echo -e "\033[1;33m → FRONTED-MEEK-OSSH:\033[1;32m $fm \033[0m"
    #echo -e "\033[1;33m → UNFRONTED-MEEK-OSSH:\033[1;32m $umo \033[0m"
    echo -e "\033[1;33m → WEB:\033[1;32m $wb \033[0m"
    msg -bar
    echo -e "\033[1;33m DIRECTORIO DE ARCHIVOS:\033[1;32m /root/psi \033[0m"
    msg -bar
    [[ "$(ps x | grep psiserver | grep -v grep | awk '{print $1}')" ]] && msg -verd "    >> SERVIDOR-PSIPHONE INSTALADO CON EXITO <<" || msg -ama "                  ERROR VERIFIQUE"
    msg -bar
    read -t 120 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    menu_inst
  }
  desactivar_psiphone() {
    clear && clear
    msg -bar
    echo -e "\033[1;31m            DESISNTALANDO PUERTOS UDP-SERVER "
    msg -bar
    rm -rf /root/psi
    kill $(ps aux | grep 'psiphond' | awk '{print $2}') 1>/dev/null 2>/dev/null
    killall psiphond 1>/dev/null 2>/dev/null
    [[ "$(ps x | grep psiserver | grep -v grep | awk '{print $1}')" ]] && echo -e "\033[1;32m        >> UDP-SERVER DESINSTALADO CON EXICO << "
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    menu_inst
  }
  clear && clear
  msg -bar
  msg -tit
  msg -bar
  msg -ama "            INSTALADOR DE PSIPHONE-SERVER"
  msg -bar
  if [[ ! -e /bin/psiphond ]]; then
    curl -o /bin/psiphond https://raw.githubusercontent.com/Psiphon-Labs/psiphon-tunnel-core-binaries/master/psiphond/psiphond &>/dev/null
    chmod 777 /bin/psiphond
  fi
  echo -ne " \e[1;93m [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;97m INSTALAR SERVER-PSIPHONE  \e[97m \n"
  echo -ne " \e[1;93m [\e[1;32m2\e[1;93m]\033[1;31m > \033[1;97m DETENER SERVER-PSIPHONE \e[97m \n"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m0\e[1;93m]\033[1;31m > \033[1;97m" && msg -bra "  \e[97m\033[1;41m VOLVER \033[1;37m"
  msg -bar
  echo -ne "\033[1;97mDigite solo el numero segun su respuesta:\e[32m "
  read opcao
  case $opcao in
  1)
    msg -bar
    install_psiphone
    ;;
  2)
    msg -bar
    desactivar_psiphone
    ;;
  0)
    menu
    ;;
  *)
    echo -e "$ Porfavor use numeros del [0-2]"
    msg -bar
    menu
    ;;
  esac

  #exit 0

}
#--- MENU DE PROTOCOLOS
menu_inst() {
  clear && clear
  msg -bar
  msg -tit
  msg -bar
  msg -ama "                 MENU DE PROTOCOLOS "
  msg -bar
  DROPBEAR=$(ps x | grep "dropbear" | grep -v "grep" | awk -F "pts" '{print $1}')
  [[ -z ${DROPBEAR} ]] && DROPBEAR="\033[1;97m[\033[1;31m OFF \033[1;97m]" || DROPBEAR="\033[1;97m[\033[1;32m ACTIVO \033[1;97m]"
  SSL=$(ps x | grep "stunnel4" | grep -v "grep" | awk -F "pts" '{print $1}')
  [[ -z ${SSL} ]] && SSL="\033[1;97m[\033[1;31m OFF \033[1;97m]" || SSL="\033[1;97m[\033[1;32m ACTIVO \033[1;97m]"
  SQUID=$(ps x | grep "squid" | grep -v "grep" | awk -F "pts" '{print $1}')
  [[ -z ${SQUID} ]] && SQUID="\033[1;97m[\033[1;31m OFF \033[1;97m]" || SQUID="\033[1;97m[\033[1;32m ACTIVO \033[1;97m]"
  OPENVPN=$(ps x | grep "openvpn" | grep -v grep | awk -F "pts" '{print $1}')
  [[ -z ${OPENVPN} ]] && OPENVPN="\033[1;97m[\033[1;31m OFF \033[1;97m]" || OPENVPN="\033[1;97m[\033[1;32m ACTIVO \033[1;97m]"
  BADVPN=$(ps x | grep "badvpn" | grep -v "grep" | awk -F "pts" '{print $1}')
  [[ -z ${BADVPN} ]] && BADVPN="\033[1;97m[\033[1;31m OFF \033[1;97m]" || BADVPN="\033[1;97m[\033[1;32m ACTIVO \033[1;97m]"
  SHADOWN=$(ps x | grep "ssserver" | grep -v "grep" | awk -F "pts" '{print $1}')
  [[ -z ${SHADOWN} ]] && SHADOWN="\033[1;97m[\033[1;31m OFF \033[1;97m]" || SHADOWN="\033[1;97m[\033[1;32m ACTIVO \033[1;97m]"
  SHADOWL=$(ps x | grep "ss-server" | grep -v grep | awk -F "pts" '{print $1}')
  [[ -z ${SHADOWL} ]] && SHADOWL="\033[1;97m[\033[1;31m OFF \033[1;97m]" || SHADOWL="\033[1;97m[\033[1;32m ACTIVO \033[1;97m]"
  WEBSOKETE=$(ps x | grep "pydic-*" | grep -v grep | awk -F "pts" '{print $1}')
  [[ -z ${WEBSOKETE} ]] && WEBSOKETE="\033[1;97m[\033[1;31m OFF \033[1;97m]" || WEBSOKETE="\033[1;97m[\033[1;32m ACTIVO \033[1;97m]"
  POPENVPN=$(ps x | grep "POpen.py" | grep -v grep | awk -F "pts" '{print $1}')
  [[ -z ${POPENVPN} ]] && POPENVPN="\033[1;97m[\033[1;31m OFF \033[1;97m]" || POPENVPN="\033[1;97m[\033[1;32m ACTIVO \033[1;97m]"
  PPUBLICO=$(ps x | grep "PPub.py" | grep -v grep | awk -F "pts" '{print $1}')
  [[ -z ${PPUBLICO} ]] && PPUBLICO="\033[1;97m[\033[1;31m OFF \033[1;97m]" || PPUBLICO="\033[1;97m[\033[1;32m ACTIVO \033[1;97m]"
  PPRIVADO=$(ps x | grep "PPriv.py" | grep -v grep | awk -F "pts" '{print $1}')
  [[ -z ${PPRIVADO} ]] && PPRIVADO="\033[1;97m[\033[1;31m OFF \033[1;97m]" || PPRIVADO="\033[1;97m[\033[1;32m ACTIVO \033[1;97m]"
  PGETTUNEL=$(ps x | grep "PGet.py" | grep -v grep | awk -F "pts" '{print $1}')
  [[ -z ${PGETTUNEL} ]] && PGETTUNEL="\033[1;97m[\033[1;31m OFF \033[1;97m]" || PGETTUNEL="\033[1;97m[\033[1;32m ACTIVO \033[1;97m]"
  POVER=$(ps x | grep "scktcheck" | grep -v grep | awk -F "pts" '{print $1}')
  [[ -z ${POVER} ]] && POVER="\033[1;97m[\033[1;31m OFF \033[1;97m]" || POVER="\033[1;97m[\033[1;32m ACTIVO \033[1;97m]"
  SLOWDNS=$(ps x | grep "slowdns" | grep -v grep | awk -F "pts" '{print $1}')
  [[ -z ${SLOWDNS} ]] && SLOWDNS="\033[1;97m[\033[1;31m OFF \033[1;97m]" || SLOWDNS="\033[1;97m[\033[1;32m ACTIVO \033[1;97m]"
  SSLH=$(ps -ef | grep "/var/run/sslh/sslh.pid" | grep -v grep | awk -F "pts" '{print $1}')
  [[ -z ${SSLH} ]] && SSLH="\033[1;97m[\033[1;31m OFF \033[1;97m]" || SSLH="\033[1;97m[\033[1;32m ACTIVO \033[1;97m]"
  UDPREQ=$(ps x | grep "/usr/bin/udpServer" | grep -v "grep" | awk -F "pts" '{print $1}')
  [[ -z ${UDPREQ} ]] && UDPREQ="\033[1;97m[\033[1;31m OFF \033[1;97m]" || UDPREQ="\033[1;97m[\033[1;32m ACTIVO \033[1;97m]"
  PSIPHON=$(ps x | grep "psiserver" | grep -v "grep" | awk -F "pts" '{print $1}')
  [[ -z ${PSIPHON} ]] && PSIPHON="\033[1;97m[\033[1;31m OFF \033[1;97m]" || PSIPHON="\033[1;97m[\033[1;32m ACTIVO \033[1;97m]"

  local Numb=1
  echo -ne "\e[1;93m  [\e[1;32m$Numb\e[1;93m]\033[1;31m > \033[1;97m" && echo -e "\033[1;97mBADVPN ----------------------  $BADVPN"
  script[$Numb]="pbadvpn"
  let Numb++
  echo -ne "\e[1;93m  [\e[1;32m$Numb\e[1;93m]\033[1;31m > \033[1;97m" && echo -e "\033[1;97mDROPBEAR --------------------  $DROPBEAR"
  script[$Numb]="pdropbear"
  let Numb++
  echo -ne "\e[1;93m  [\e[1;32m$Numb\e[1;93m]\033[1;31m > \033[1;97m" && echo -e "\033[1;97mSSL -------------------------  $SSL"
  script[$Numb]="pssl"
  let Numb++
  echo -ne "\e[1;93m  [\e[1;32m$Numb\e[1;93m]\033[1;31m > \033[1;97m" && echo -e "\033[1;97mSQUID -----------------------  $SQUID"
  script[$Numb]="psquid"
  let Numb++
  echo -ne "\e[1;93m  [\e[1;32m$Numb\e[1;93m]\033[1;31m > \033[1;97m" && echo -e "\033[1;97mOPENVPN ---------------------  $OPENVPN"
  script[$Numb]="popenvpn"
  let Numb++
  echo -ne "\e[1;93m  [\e[1;32m$Numb\e[1;93m]\033[1;31m > \033[1;97m" && echo -e "\033[1;97mSHADOWSOCK NORMAL -----------  $SHADOWN"
  script[$Numb]="pshadowsockN"
  let Numb++
  echo -ne "\e[1;93m  [\e[1;32m$Numb\e[1;93m]\033[1;31m > \033[1;97m" && echo -e "\033[1;97mSHADOWSOCK LIV +OBFS --------  $SHADOWL"
  script[$Numb]="pshadowsockL"
  let Numb++
  echo -ne "\e[1;93m  [\e[1;32m$Numb\e[1;93m]\033[1;31m > \033[1;97m" && echo -e "\033[1;97mSLOWDNS ---------------------  $SLOWDNS"
  script[$Numb]="slowdns"
  let Numb++
  echo -ne "\e[1;93m  [\e[1;32m$Numb\e[1;93m]\033[1;31m > \033[1;97m" && echo -e "\033[1;97mGETTUNEL --------------------  $PGETTUNEL"
  script[$Numb]="pgettunel"
  let Numb++
  echo -ne "\e[1;93m [\e[1;32m$Numb\e[1;93m]\033[1;31m > \033[1;97m" && echo -e "\033[1;97mTCP-OVER --------------------  $POVER"
  script[$Numb]="ptcpover"
  let Numb++
  echo -ne "\e[1;93m [\e[1;32m$Numb\e[1;93m]\033[1;31m > \033[1;97m" && echo -e "\033[1;97mSSLH ------------------------  $SSLH"
  script[$Numb]="sslh"
  let Numb++
  echo -ne "\e[1;93m [\e[1;32m$Numb\e[1;93m]\033[1;31m > \033[1;97m" && echo -e "\033[1;97mUDP-REQUEST -----------------  $UDPREQ"
  script[$Numb]="udpserverr"
  let Numb++
  echo -ne "\e[1;93m [\e[1;32m$Numb\e[1;93m]\033[1;31m > \033[1;97m" && echo -e "\033[1;97mSERVIDOR PSIPHONE -----------  $PSIPHON"
  script[$Numb]="spsiphone"
  echo -ne "\e[0;0m\e[1;90m═════════════════════ \e[0;0m\e[1;93mPROXY´S \e[0;0m\e[1;90m══════════════════════\n"
  let Numb++
  echo -ne "\e[1;93m [\e[1;32m$Numb\e[1;93m]\033[1;31m > \033[1;97m" && echo -e "\033[1;97mWEBSOKET STATUS EDITABLE ----  $WEBSOKETE"
  script[$Numb]="pwebsokete"
  let Numb++
  echo -ne "\e[1;93m [\e[1;32m$Numb\e[1;93m]\033[1;31m > \033[1;97m" && echo -e "\033[1;97mPROXY OPENVPN ---------------  $POPENVPN"
  script[$Numb]="pro-openvpn"
  let Numb++
  echo -ne "\e[1;93m [\e[1;32m$Numb\e[1;93m]\033[1;31m > \033[1;97m" && echo -e "\033[1;97mPROXY PUBLICO ---------------  $PPUBLICO"
  script[$Numb]="ppublico"
  let Numb++
  echo -ne "\e[1;93m [\e[1;32m$Numb\e[1;93m]\033[1;31m > \033[1;97m" && echo -e "\033[1;97mPROXY PRIVADO ---------------  $PPRIVADO"
  script[$Numb]="pprivado"
  let Numb++
  msg -bar2
  echo -e "    \e[97m\033[1;41m ENTER SIN RESPUESTA REGRESA A MENU ANTERIOR \033[0;97m"
  script[0]="voltar"
  msg -bar2
  selection=$(selection_fun $Numb)
  [[ -e "${SCPfrm}/${script[$selection]}" ]] && {
    ${SCPfrm}/${script[$selection]}
  } || {
    case ${script[$selection]} in
    "pdropbear") proto_dropbear ;;
    "pssl") proto_ssl ;;
    "psquid") proto_squid ;;
    "popenvpn") proto_openvpn ;;
    "pbadvpn") proto_badvpn ;;
    "pshadowsockN") proto_shadowsockN ;;
    "pshadowsockL") proto_shadowsockL ;;
    "pwebsokete") proto_websockete ;;
    "pro-openvpn") proto_popenvpn ;;
    "ppublico") proto_ppublico ;;
    "pprivado") proto_pprivado ;;
    "pgettunel") proto_pgettunel ;;
    "ptcpover") proto_ptcpover ;;
    "slowdns") proto_slowndns ;;
    "sslh") sshl_install ;;
    "udpserverr") udp_serverr ;;
    "spsiphone") server_psiphones ;;
    *) return 0 ;;
    esac
  }
}

#--- CONTROLADOR V2RAY
control_v2ray() {
  err_fun() {
    case $1 in
    1)
      msg -verm "Usuario Nulo"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    2)
      msg -verm "Nombre muy corto (MIN: 2 CARACTERES)"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    3)
      msg -verm "Nombre muy grande (MAX: 5 CARACTERES)"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    4)
      msg -verm "Contraseña Nula"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    5)
      msg -verm "Contraseña muy corta"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    6)
      msg -verm "Contraseña muy grande"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    7)
      msg -verm "Duracion Nula"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    8)
      msg -verm "Duracion invalida utilize numeros"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    9)
      msg -verm "Duracion maxima y de un año"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    11)
      msg -verm "Limite Nulo"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    12)
      msg -verm "Limite invalido utilize numeros"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    13)
      msg -verm "Limite maximo de 999"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    14)
      msg -verm "Usuario Ya Existe"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    15)
      msg -verm "(Solo numeros) GB = Min: 1gb Max: 1000gb"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    16)
      msg -verm "Solo numeros"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    17)
      msg -verm "Sin Informacion - Para Cancelar Digite CRTL + C"
      sleep 4s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    esac
  }

  intallv2ray() {
    clear && clear
    msg -bar
    echo -e " \e[1;32m          >>> SE INSTALARA V2RAY <<< " | pv -qL 10
    msg -bar
    source <(curl -sL https://raw.githubusercontent.com/NetVPS/LATAM_Oficial/main/Ejecutables/v2ray.sh)
    v2ray update
    mailfix=$(cat /dev/urandom | tr -dc '[:alnum:]' | head -c 10)
    curl https://get.acme.sh | sh -s email=$mailfix@gmail.com
    #service v2ray restart
    msg -ama "Intalado con EXITO!"
    USRdatabase="/etc/SCRIPT-LATAM/RegV2ray"
    [[ ! -e ${USRdatabase} ]] && touch ${USRdatabase}
    sort ${USRdatabase} | uniq >${USRdatabase}tmp
    mv -f ${USRdatabase}tmp ${USRdatabase}
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    control_v2ray
  }
  protocolv2ray() {
    msg -ama "Escojer opcion 3 y poner el dominio de nuestra IP!"
    msg -bar
    v2ray stream
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    control_v2ray
  }
  tls() {
    msg -ama "Activar o Desactivar TLS!"
    msg -bar
    v2ray tls
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    control_v2ray
  }
  portv() {
    msg -ama "Cambiar Puerto v2ray!"
    msg -bar
    v2ray port
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    control_v2ray
  }
  stats() {
    msg -ama "Estadisticas de Consumo!"
    msg -bar
    v2ray stats
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    control_v2ray
  }
  unistallv2() {
    source <(curl -sL https://multi.netlify.app/v2ray.sh) --remove >/dev/null 2>&1
    rm -rf /etc/SCRIPT-LATAM/RegV2ray >/dev/null 2>&1
    rm -rf /etc/SCRIPT-LATAM/v2ray/* >/dev/null 2>&1
    echo -e "\033[1;92m             V2RAY DESINSTALADO CON EXITO"
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    control_v2ray
  }
  infocuenta() {
    v2ray info
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    control_v2ray
  }
  addusr() {
    clear
    clear
    msg -bar
    msg -tit
    msg -bar
    msg -ama "             AGREGAR USUARIO | UUID V2RAY"
    msg -bar
    ##DAIS
    valid=$(date '+%C%y-%m-%d' -d " +31 days")
    ##CORREO
    MAILITO=$(cat /dev/urandom | tr -dc '[:alnum:]' | head -c 10)
    ##ADDUSERV2RAY
    UUID=$(uuidgen)
    sed -i '13i\           \{' /etc/v2ray/config.json
    sed -i '14i\           \"alterId": 0,' /etc/v2ray/config.json
    sed -i '15i\           \"id": "'$UUID'",' /etc/v2ray/config.json
    sed -i '16i\           \"email": "'$MAILITO'@gmail.com"' /etc/v2ray/config.json
    sed -i '17i\           \},' /etc/v2ray/config.json
    echo ""
    while true; do
      echo -ne "\e[91m >> Digita un Nombre: \033[1;92m"
      read -p " " nick
      nick="$(echo $nick | sed -e 's/[^a-z0-9 -]//ig')"
      if [[ -z $nick ]]; then
        err_fun 17 && continue
      elif [[ "${#nick}" -lt "2" ]]; then
        err_fun 2 && continue
      elif [[ "${#nick}" -gt "6" ]]; then
        err_fun 3 && continue
      fi
      break
    done
    echo -e "\e[91m >> Agregado UUID: \e[92m$UUID "
    while true; do
      echo -ne "\e[91m >> Duracion de UUID (Dias):\033[1;92m " && read diasuser
      if [[ -z "$diasuser" ]]; then
        err_fun 17 && continue
      elif [[ "$diasuser" != +([0-9]) ]]; then
        err_fun 8 && continue
      elif [[ "$diasuser" -gt "360" ]]; then
        err_fun 9 && continue
      fi
      break
    done
    #Lim
    [[ $(cat /etc/passwd | grep $1: | grep -vi [a-z]$1 | grep -v [0-9]$1 >/dev/null) ]] && return 1
    valid=$(date '+%C%y-%m-%d' -d " +$diasuser days") && datexp=$(date "+%F" -d " + $diasuser days")
    echo -e "\e[91m >> Expira el : \e[92m$datexp "
    ##Registro
    echo "  $UUID | $nick | $valid " >>/etc/SCRIPT-LATAM/RegV2ray
    Fecha=$(date +%d-%m-%y-%R)
    cp /etc/SCRIPT-LATAM/RegV2ray /etc/SCRIPT-LATAM/v2ray/RegV2ray-"$Fecha"
    cp /etc/SCRIPT-LATAM/RegV2ray /etc/v2ray/config.json-"$Fecha"
    v2ray restart >/dev/null 2>&1
    echo ""
    v2ray info >/etc/SCRIPT-LATAM/v2ray/confuuid.log
    lineP=$(sed -n '/'${UUID}'/=' /etc/SCRIPT-LATAM/v2ray/confuuid.log)
    numl1=4
    let suma=$lineP+$numl1
    sed -n ${suma}p /etc/SCRIPT-LATAM/v2ray/confuuid.log
    echo ""
    msg -bar
    echo -e "\e[92m             UUID AGREGEGADO CON EXITO "
    msg -bar
    read -t 120 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    control_v2ray
  }

  delusr() {
    clear
    clear
    invaliduuid() {
      msg -bar
      echo -e "\e[91m                    UUID INVALIDO \n$(msg -bar)"
      msg -ne "Enter Para Continuar" && read enter
      control_v2ray
    }
    msg -bar
    msg -tit
    msg -bar
    msg -ama "             ELIMINAR USUARIO | UUID V2RAY"
    msg -bar
    echo -e "\e[1;97m               USUARIOS REGISTRADOS"
    echo -e "\e[1;33m$(cat /etc/SCRIPT-LATAM/RegV2ray | cut -d '|' -f2,1)"
    msg -bar
    echo -ne "\e[91m >> Digita el usuario a eliminar:\n \033[1;92m " && read userv
    uuidel=$(cat /etc/SCRIPT-LATAM/RegV2ray | grep -w "$userv" | cut -d'|' -f1 | tr -d " \t\n\r")
    [[ $(sed -n '/'${uuidel}'/=' /etc/v2ray/config.json | head -1) ]] || invaliduuid
    lineP=$(sed -n '/'${uuidel}'/=' /etc/v2ray/config.json)
    linePre=$(sed -n '/'${uuidel}'/=' /etc/SCRIPT-LATAM/RegV2ray)
    sed -i "${linePre}d" /etc/SCRIPT-LATAM/RegV2ray
    numl1=2
    let resta=$lineP-$numl1
    sed -i "${resta}d" /etc/v2ray/config.json
    sed -i "${resta}d" /etc/v2ray/config.json
    sed -i "${resta}d" /etc/v2ray/config.json
    sed -i "${resta}d" /etc/v2ray/config.json
    sed -i "${resta}d" /etc/v2ray/config.json
    v2ray restart >/dev/null 2>&1
    msg -bar
    echo -e "\e[1;32m            USUARIO ELIMINADO CON EXITO"
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    control_v2ray
  }

  mosusr_kk() {
    clear
    clear
    msg -bar
    msg -tit
    msg -bar
    msg -ama "         USUARIOS REGISTRADOS | UUID V2RAY"
    msg -bar
    # usersss=$(cat /etc/SCRIPT-LATAM/RegV2ray|cut -d '|' -f1)
    # cat /etc/SCRIPT-LATAM/RegV2ray|cut -d'|' -f3
    VPSsec=$(date +%s)
    local HOST="/etc/SCRIPT-LATAM/RegV2ray"
    local HOST2="/etc/SCRIPT-LATAM/RegV2ray"
    local RETURN="$(cat $HOST | cut -d'|' -f2)"
    local IDEUUID="$(cat $HOST | cut -d'|' -f1)"
    if [[ -z $RETURN ]]; then
      echo -e "----- NINGUN USER REGISTRADO -----"
      msg -ne "Enter Para Continuar" && read enter
      control_v2ray

    else
      i=1
      echo -e "\e[97m                 UUID                | USER | DIAS\e[93m"
      msg -bar
      while read hostreturn; do
        DateExp="$(cat /etc/SCRIPT-LATAM/RegV2ray | grep -w "$hostreturn" | cut -d'|' -f3)"
        if [[ ! -z $DateExp ]]; then
          DataSec=$(date +%s --date="$DateExp")
          [[ "$VPSsec" -gt "$DataSec" ]] && EXPTIME="\e[91m[EXPIRADO]\e[97m" || EXPTIME="\e[92m[$(($(($DataSec - $VPSsec)) / 86400))]"
        else
          EXPTIME="\e[91m[ S/R ]"
        fi
        usris="$(cat /etc/SCRIPT-LATAM/RegV2ray | grep -w "$hostreturn" | cut -d'|' -f2)"
        local contador_secuencial+="\e[93m$hostreturn \e[97m|\e[93m$usris\e[97m|\e[93m $EXPTIME \n"
        if [[ $i -gt 30 ]]; then
          echo -e "$contador_secuencial"
          unset contador_secuencial
          unset i
        fi
        let i++
      done <<<"$IDEUUID"

      [[ ! -z $contador_secuencial ]] && {
        linesss=$(cat /etc/SCRIPT-LATAM/RegV2ray | wc -l)
        echo -e "$contador_secuencial \n \e[1;97mNumero de Registrados: $linesss"
      }
    fi
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    control_v2ray
  }

  limpiador_activador() {
    unset PIDGEN
    PIDGEN=$(ps aux | grep -v grep | grep "limv2ray")
    if [[ ! $PIDGEN ]]; then
      screen -dmS limv2ray watch -n 21600 /etc/SCRIPT-LATAM/menu.sh "exlimv2ray"
    else
      #killall screen
      screen -S limv2ray -p 0 -X quit
    fi
    unset PID_GEN
    PID_GEN=$(ps x | grep -v grep | grep "limv2ray")
    [[ ! $PID_GEN ]] && PID_GEN="\e[91m [ DESACTIVADO ] " || PID_GEN="\e[92m [ ACTIVADO ] "
    statgen="$(echo $PID_GEN)"
    clear
    clear
    msg -bar
    msg -tit
    msg -bar
    msg -ama "          ELIMINAR EXPIRADOS | UUID V2RAY"
    msg -bar
    echo -e "\e[1;97m     SE LIMPIARAN EXPIRADOS CADA 6 hrs"
    msg -bar
    echo -e "                    $statgen "
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    control_v2ray

  }

  changepath() {
    clear
    clear
    msg -bar
    msg -tit
    msg -ama "             CAMBIAR NOMBRE DEL PATH"
    msg -bar
    echo -e "\e[97m               USUARIOS REGISTRADOS"
    echo -ne "\e[91m >> Digita un nombre corto para el path:\n \033[1;92m " && read nombrepat
    NPath=$(sed -n '/'path'/=' /etc/v2ray/config.json)
    sed -i "${NPath}d" /etc/v2ray/config.json
    sed -i ''${NPath}'i\          \"path": "/'${nombrepat}'/",' /etc/v2ray/config.json
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    control_v2ray
  }

  backup_fun() {
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    msg -ama " BACKUP BASE DE USUARIOS / JSON GENERAL (WEBSOCKET)"
    msg -bar
    menu_func "CREAR BACKUP" "RESTAURAR BACKUP" "CAMBIAR HOST/CRT"
    echo -ne ""$(msg -bar)"   \n$(msg -verd "  [0]") $(msg -verm2 "╚⊳ ")" && msg -bra "  \e[1;97m\033[1;41m VOLVER \033[1;37m"
    msg -bar
    unset selection
    while [[ ${selection} != @([0-3]) ]]; do
      echo -ne "\033[1;37mSeleccione una Opcion: " && read selection
      tput cuu1 && tput dl1
    done
    case ${selection} in
    1)
      cp /etc/v2ray/config.json $HOME/config.json
      cp /etc/SCRIPT-LATAM/RegV2ray $HOME/RegV2ray
      msg -azu "Procedimiento Hecho con Exito, Guardado en:"
      echo ""
      echo -e "\033[1;31mBACKUP > [\033[1;32m$HOME/config.json\033[1;31m]"
      echo -e "\033[1;31mBACKUP > [\033[1;32m$HOME/RegV2ray\033[1;31m]"
      ;;
    2)
      echo -ne "\033[1;37m Ubique los files la carpeta root\n"
      msg -bar
      read -t 20 -n 1 -rsp $'\033[1;39m   Enter Para Proceder o CTRL + C para Cancelar\n'
      echo ""
      cp /root/config.json /etc/v2ray/config.json
      cp /root/RegV2ray /etc/SCRIPT-LATAM/RegV2ray
      echo -e "\033[1;31mRESTAURADO > [\033[1;32m/etc/v2ray/config.json \033[1;31m]"
      echo -e "\033[1;31mRESTAURADO > [\033[1;32m/etc/SCRIPT-LATAM/RegV2ray \033[1;31m]"
      ;;
    3)
      echo -ne "\033[1;37m           EDITAR HOST,SUDOMINIO,KEY,CRT\n"
      msg -bar
      read -t 20 -n 1 -rsp $'\033[1;39m   Enter Para Proceder o CTRL + C para Cancelar\n'
      echo -ne "\e[91m >> Digita el sub.dominio usado anteriormente:\n \033[1;92m " && read nombrehost
      ##CER
      Ncert=$(sed -n '/'certificateFile'/=' /etc/v2ray/config.json)
      sed -i "${Ncert}d" /etc/v2ray/config.json
      sed -i ''${Ncert}'i\              \"certificateFile": "/root/.acme.sh/'${nombrehost}'_ecc/fullchain.cer",' /etc/v2ray/config.json
      ##KEY
      Nkey=$(sed -n '/'keyFile'/=' /etc/v2ray/config.json)
      sed -i "${Nkey}d" /etc/v2ray/config.json
      sed -i ''${Nkey}'i\              \"keyFile": "/root/.acme.sh/'${nombrehost}'_ecc/'${nombrehost}'.key"' /etc/v2ray/config.json
      ##HOST
      Nhost=$(sed -n '/'Host'/=' /etc/v2ray/config.json)
      sed -i "${Nhost}d" /etc/v2ray/config.json
      sed -i ''${Nhost}'i\           \"Host": "'${nombrehost}'"' /etc/v2ray/config.json
      ##DOM
      Ndom=$(sed -n '/'domain'/=' /etc/v2ray/config.json)
      sed -i "${Ndom}d" /etc/v2ray/config.json
      sed -i ''${Ndom}'i\           \"domain": "'${nombrehost}'"' /etc/v2ray/config.json
      echo -e "\033[1;31m HOST Y CRT ,KEY RESTAURADO > [\033[1;32m $nombrehost \033[1;31m]"
      ;;
    0)
      read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      control_v2ray
      exit 0
      ;;
    esac
    echo ""
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    control_v2ray
  }

  pid_inst2() {
    [[ $1 = "" ]] && echo -e "\033[1;31m[OFF]" && return 0
    unset portas
    portas_var=$(lsof -V -i -P -n | grep -v "ESTABLISHED" | grep -v "COMMAND")
    i=0
    while read port; do
      var1=$(echo $port | awk '{print $1}') && var2=$(echo $port | awk '{print $9}' | awk -F ":" '{print $2}')
      [[ "$(echo -e ${portas[@]} | grep "$var1 $var2")" ]] || {
        portas[$i]="$var1 $var2\n"
        let i++
      }
    done <<<"$portas_var"
    [[ $(echo "${portas[@]}" | grep "$1") ]] && echo -e "\033[1;32m[ Servicio Activo ]" || echo -e "\033[1;31m[ Servicio Desactivado ]"
  }

  clear && clear
  PID_GEN=$(ps x | grep -v grep | grep "limv2ray")
  [[ ! $PID_GEN ]] && PID_GEN="\e[91m [ DESACTIVADO ] " || PID_GEN="\e[92m [ ACTIVADO ] "
  statgen="$(echo $PID_GEN)"
  msg -bar
  msg -tit
  msg -bar
  echo -e "\e[1;93m       CONTROLADOR DE V2RAY (WEBSOCKET+TLS) "
  msg -bar
  echo -e "        \e[97mEstado actual: $(pid_inst2 v2ray)"
  msg -bar
  ## INSTALADOR
  echo -ne " \e[1;93m [\e[1;32m1\e[1;93m]\033[1;31m > \033[1;97mINSTALAR V2RAY " && echo -ne " \e[1;93m [\e[1;32m2\e[1;93m]\033[1;31m > \033[1;97mCAMBIAR PROTOCOLO \n"
  echo -ne " \e[1;93m [\e[1;32m3\e[1;93m]\033[1;31m > \033[1;97mACTIVAR TLS " && echo -ne "    \e[1;93m [\e[1;32m4\e[1;93m]\033[1;31m > \033[1;97mCAMBIAR PUERTO \n"
  echo -ne " \e[1;93m [\e[1;32m5\e[1;93m]\033[1;31m > " && echo -e "\033[1;97mCAMBIAR NOMBRRE DE PATH"
  echo -e "\033[38;5;239m══════════════\e[100m\e[97m  ADMINISTRAR CUENTAS  \e[0m\e[38;5;239m══════════════"
  echo -ne " \e[1;93m [\e[1;32m6\e[1;93m]\033[1;31m > " && echo -e "\033[1;97mAGREGAR USUARIO UUID "
  echo -ne " \e[1;93m [\e[1;32m7\e[1;93m]\033[1;31m > " && echo -e "\033[1;97mELIMINAR USUARIO UUID"
  echo -ne " \e[1;93m [\e[1;32m8\e[1;93m]\033[1;31m > " && echo -e "\033[1;97mMOSTAR USUARIOS REGISTRADOS"
  echo -ne " \e[1;93m [\e[1;32m9\e[1;93m]\033[1;31m > " && echo -e "\033[1;97mINFORMACION DE CUENTAS"
  echo -ne "\e[1;93m [\e[1;32m10\e[1;93m]\033[1;31m > " && echo -e "\033[1;97mESTADISTICAS DE CONSUMO "
  echo -ne "\e[1;93m [\e[1;32m11\e[1;93m]\033[1;31m > " && echo -e "\033[1;97mLIMPIADOR DE EXPIRADOS --- $statgen"
  echo -ne "\e[1;93m [\e[1;32m12\e[1;93m]\033[1;31m > " && echo -e "\033[1;97mBACKUP / BASE USER Y JSON"
  echo -ne "\e[1;93m [\e[1;32m13\e[1;93m]\033[1;31m > " && echo -e "\033[1;31mDESINSTALAR V2RAY"
  msg -bar
  echo -ne " \e[1;93m [\e[1;32m0\e[1;93m]\033[1;31m > " && echo -e "\e[97m\033[1;41m VOLVER \033[0;37m"
  msg -bar

  # while [[ ${arquivoonlineadm} != @(0|[1-99]) ]]; do
  # read -p "Seleccione una Opcion [0-12]: " arquivoonlineadm
  # tput cuu1 && tput dl1
  # done
  selection=$(selection_fun 14)
  case ${selection} in
  1) intallv2ray ;;
  2) protocolv2ray ;;
  3) tls ;;
  4) portv ;;
  5) changepath ;;
  6) addusr ;;
  7) delusr ;;
  8) mosusr_kk ;;
  9) infocuenta ;;
  10) stats ;;
  11) limpiador_activador ;;
  12) backup_fun ;;
  13) unistallv2 ;;
  0) menu ;;
  esac
  exit 0
}

#--- CONTROLADOR SSR
controlador_ssr() {

  clear
  clear
  msg -bar
  PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
  export PATH
  #SCPfrm="/etc/ger-frm" && [[ ! -d ${SCPfrm} ]] && mkdir ${SCPfrm}
  BARRA1="\e[0;31m--------------------------------------------------------------------\e[0m"
  #SCPinst="/etc/ger-inst" && [[ ! -d ${SCPfrm} ]] && mkdir ${SCPfrm}
  sh_ver="1.0.26"
  filepath=$(
    cd "$(dirname "$0")"
    pwd
  )
  file=$(echo -e "${filepath}" | awk -F "$0" '{print $1}')
  ssr_folder="/usr/local/shadowsocksr"
  config_file="${ssr_folder}/config.json"
  config_user_file="${ssr_folder}/user-config.json"
  config_user_api_file="${ssr_folder}/userapiconfig.py"
  config_user_mudb_file="${ssr_folder}/mudb.json"
  ssr_log_file="${ssr_folder}/ssserver.log"
  Libsodiumr_file="/usr/local/lib/libsodium.so"
  Libsodiumr_ver_backup="1.0.16"
  Server_Speeder_file="/serverspeeder/bin/serverSpeeder.sh"
  LotServer_file="/appex/bin/serverSpeeder.sh"
  BBR_file="${file}/bbr.sh"
  jq_file="${ssr_folder}/jq"

  Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
  Info="${Green_font_prefix}[ INFORMACION ]${Font_color_suffix}"
  Error="${Red_font_prefix}[# ERROR #]${Font_color_suffix}"
  Tip="${Green_font_prefix}[ NOTA ]${Font_color_suffix}"
  Separator_1="——————————————————————————————"

  check_root() {
    [[ $EUID != 0 ]] && echo -e "${Error} La cuenta actual no es ROOT (no tiene permiso ROOT), no puede continuar la operacion, por favor ${Green_background_prefix} sudo su ${Font_color_suffix} Venga a ROOT (le pedire que ingrese la contraseña de la cuenta actual despues de la ejecucion)" && exit 1
  }
  check_sys() {
    if [[ -f /etc/redhat-release ]]; then
      release="centos"
    elif cat /etc/issue | grep -q -E -i "debian"; then
      release="debian"
    elif cat /etc/issue | grep -q -E -i "ubuntu"; then
      release="ubuntu"
    elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
      release="centos"
    elif cat /proc/version | grep -q -E -i "debian"; then
      release="debian"
    elif cat /proc/version | grep -q -E -i "ubuntu"; then
      release="ubuntu"
    elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
      release="centos"
    fi
    bit=$(uname -m)
  }
  check_pid() {
    PID=$(ps -ef | grep -v grep | grep server.py | awk '{print $2}')
  }
  check_crontab() {
    [[ ! -e "/usr/bin/crontab" ]] && echo -e "${Error}Falta de dependencia Crontab, Por favor, intente instalar manualmente CentOS: yum install crond -y , Debian/Ubuntu: apt-get install cron -y !" && exit 1
  }
  SSR_installation_status() {
    [[ ! -e ${ssr_folder} ]] && echo -e "${Error}\nShadowsocksR No se encontro la instalacion\n$(msg -bar)" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
  }
  Server_Speeder_installation_status() {
    [[ ! -e ${Server_Speeder_file} ]] && echo -e "${Error}No instalado (Server Speeder), Por favor compruebe!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
  }
  LotServer_installation_status() {
    [[ ! -e ${LotServer_file} ]] && echo -e "${Error}No instalado LotServer, Por favor revise!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
  }
  BBR_installation_status() {
    if [[ ! -e ${BBR_file} ]]; then
      echo -e "${Error} No encontre el script de BBR, comience a descargar ..."
      cd "${file}"
      if ! wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/bbr.sh; then
        echo -e "${Error} BBR script descargar!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
      else
        echo -e "${Info} BBR script descarga completa!"
        chmod +x bbr.sh
      fi
    fi
  }
  #Establecer reglas de firewall
  Add_iptables() {
    if [[ ! -z "${ssr_port}" ]]; then
      iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssr_port} -j ACCEPT
      iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssr_port} -j ACCEPT
      ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssr_port} -j ACCEPT
      ip6tables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssr_port} -j ACCEPT
    fi
  }
  Del_iptables() {
    if [[ ! -z "${port}" ]]; then
      iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
      iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
      ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
      ip6tables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
    fi
  }
  Save_iptables() {
    if [[ ${release} == "centos" ]]; then
      service iptables save
      service ip6tables save
    else
      iptables-save >/etc/iptables.up.rules
      ip6tables-save >/etc/ip6tables.up.rules
    fi
  }
  Set_iptables() {
    if [[ ${release} == "centos" ]]; then
      service iptables save
      service ip6tables save
      chkconfig --level 2345 iptables on
      chkconfig --level 2345 ip6tables on
    else
      iptables-save >/etc/iptables.up.rules
      ip6tables-save >/etc/ip6tables.up.rules
      echo -e '#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules\n/sbin/ip6tables-restore < /etc/ip6tables.up.rules' >/etc/network/if-pre-up.d/iptables
      chmod +x /etc/network/if-pre-up.d/iptables
    fi
  }
  #Leer la informaci�n de configuraci�n
  Get_IP() {
    ip=$(wget -qO- -t1 -T2 ipinfo.io/ip)
    if [[ -z "${ip}" ]]; then
      ip=$(wget -qO- -t1 -T2 api.ip.sb/ip)
      if [[ -z "${ip}" ]]; then
        ip=$(wget -qO- -t1 -T2 members.3322.org/dyndns/getip)
        if [[ -z "${ip}" ]]; then
          ip="VPS_IP"
        fi
      fi
    fi
  }
  Get_User_info() {
    Get_user_port=$1
    user_info_get=$(python mujson_mgr.py -l -p "${Get_user_port}")
    match_info=$(echo "${user_info_get}" | grep -w "### user ")
    if [[ -z "${match_info}" ]]; then
      echo -e "${Error}La adquisicion de informacion del usuario fallo ${Green_font_prefix}[Puerto: ${ssr_port}]${Font_color_suffix} " && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    fi
    user_name=$(echo "${user_info_get}" | grep -w "user :" | sed 's/[[:space:]]//g' | awk -F ":" '{print $NF}')
    msg -bar
    port=$(echo "${user_info_get}" | grep -w "port :" | sed 's/[[:space:]]//g' | awk -F ":" '{print $NF}')
    msg -bar
    password=$(echo "${user_info_get}" | grep -w "passwd :" | sed 's/[[:space:]]//g' | awk -F ":" '{print $NF}')
    msg -bar
    method=$(echo "${user_info_get}" | grep -w "method :" | sed 's/[[:space:]]//g' | awk -F ":" '{print $NF}')
    msg -bar
    protocol=$(echo "${user_info_get}" | grep -w "protocol :" | sed 's/[[:space:]]//g' | awk -F ":" '{print $NF}')
    msg -bar
    protocol_param=$(echo "${user_info_get}" | grep -w "protocol_param :" | sed 's/[[:space:]]//g' | awk -F ":" '{print $NF}')
    msg -bar
    [[ -z ${protocol_param} ]] && protocol_param="0(Ilimitado)"
    msg -bar
    obfs=$(echo "${user_info_get}" | grep -w "obfs :" | sed 's/[[:space:]]//g' | awk -F ":" '{print $NF}')
    msg -bar
    #transfer_enable=$(echo "${user_info_get}"|grep -w "transfer_enable :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}'|awk -F "ytes" '{print $1}'|sed 's/KB/ KB/;s/MB/ MB/;s/GB/ GB/;s/TB/ TB/;s/PB/ PB/')
    #u=$(echo "${user_info_get}"|grep -w "u :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
    #d=$(echo "${user_info_get}"|grep -w "d :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
    forbidden_port=$(echo "${user_info_get}" | grep -w "Puerto prohibido :" | sed 's/[[:space:]]//g' | awk -F ":" '{print $NF}')
    [[ -z ${forbidden_port} ]] && forbidden_port="Permitir todo"
    msg -bar
    speed_limit_per_con=$(echo "${user_info_get}" | grep -w "speed_limit_per_con :" | sed 's/[[:space:]]//g' | awk -F ":" '{print $NF}')
    msg -bar
    speed_limit_per_user=$(echo "${user_info_get}" | grep -w "speed_limit_per_user :" | sed 's/[[:space:]]//g' | awk -F ":" '{print $NF}')
    msg -bar
    Get_User_transfer "${port}"
  }
  Get_User_transfer() {
    transfer_port=$1
    #echo "transfer_port=${transfer_port}"
    all_port=$(${jq_file} '.[]|.port' ${config_user_mudb_file})
    #echo "all_port=${all_port}"
    port_num=$(echo "${all_port}" | grep -nw "${transfer_port}" | awk -F ":" '{print $1}')
    #echo "port_num=${port_num}"
    port_num_1=$(expr ${port_num} - 1)
    #echo "port_num_1=${port_num_1}"
    transfer_enable_1=$(${jq_file} ".[${port_num_1}].transfer_enable" ${config_user_mudb_file})
    #echo "transfer_enable_1=${transfer_enable_1}"
    u_1=$(${jq_file} ".[${port_num_1}].u" ${config_user_mudb_file})
    #echo "u_1=${u_1}"
    d_1=$(${jq_file} ".[${port_num_1}].d" ${config_user_mudb_file})
    #echo "d_1=${d_1}"
    transfer_enable_Used_2_1=$(expr ${u_1} + ${d_1})
    #echo "transfer_enable_Used_2_1=${transfer_enable_Used_2_1}"
    transfer_enable_Used_1=$(expr ${transfer_enable_1} - ${transfer_enable_Used_2_1})
    #echo "transfer_enable_Used_1=${transfer_enable_Used_1}"

    if [[ ${transfer_enable_1} -lt 1024 ]]; then
      transfer_enable="${transfer_enable_1} B"
    elif [[ ${transfer_enable_1} -lt 1048576 ]]; then
      transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1024'}')
      transfer_enable="${transfer_enable} KB"
    elif [[ ${transfer_enable_1} -lt 1073741824 ]]; then
      transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1048576'}')
      transfer_enable="${transfer_enable} MB"
    elif [[ ${transfer_enable_1} -lt 1099511627776 ]]; then
      transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1073741824'}')
      transfer_enable="${transfer_enable} GB"
    elif [[ ${transfer_enable_1} -lt 1125899906842624 ]]; then
      transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1099511627776'}')
      transfer_enable="${transfer_enable} TB"
    fi
    #echo "transfer_enable=${transfer_enable}"
    if [[ ${u_1} -lt 1024 ]]; then
      u="${u_1} B"
    elif [[ ${u_1} -lt 1048576 ]]; then
      u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1024'}')
      u="${u} KB"
    elif [[ ${u_1} -lt 1073741824 ]]; then
      u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1048576'}')
      u="${u} MB"
    elif [[ ${u_1} -lt 1099511627776 ]]; then
      u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1073741824'}')
      u="${u} GB"
    elif [[ ${u_1} -lt 1125899906842624 ]]; then
      u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1099511627776'}')
      u="${u} TB"
    fi
    #echo "u=${u}"
    if [[ ${d_1} -lt 1024 ]]; then
      d="${d_1} B"
    elif [[ ${d_1} -lt 1048576 ]]; then
      d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1024'}')
      d="${d} KB"
    elif [[ ${d_1} -lt 1073741824 ]]; then
      d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1048576'}')
      d="${d} MB"
    elif [[ ${d_1} -lt 1099511627776 ]]; then
      d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1073741824'}')
      d="${d} GB"
    elif [[ ${d_1} -lt 1125899906842624 ]]; then
      d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1099511627776'}')
      d="${d} TB"
    fi
    #echo "d=${d}"
    if [[ ${transfer_enable_Used_1} -lt 1024 ]]; then
      transfer_enable_Used="${transfer_enable_Used_1} B"
    elif [[ ${transfer_enable_Used_1} -lt 1048576 ]]; then
      transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1024'}')
      transfer_enable_Used="${transfer_enable_Used} KB"
    elif [[ ${transfer_enable_Used_1} -lt 1073741824 ]]; then
      transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1048576'}')
      transfer_enable_Used="${transfer_enable_Used} MB"
    elif [[ ${transfer_enable_Used_1} -lt 1099511627776 ]]; then
      transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1073741824'}')
      transfer_enable_Used="${transfer_enable_Used} GB"
    elif [[ ${transfer_enable_Used_1} -lt 1125899906842624 ]]; then
      transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1099511627776'}')
      transfer_enable_Used="${transfer_enable_Used} TB"
    fi
    #echo "transfer_enable_Used=${transfer_enable_Used}"
    if [[ ${transfer_enable_Used_2_1} -lt 1024 ]]; then
      transfer_enable_Used_2="${transfer_enable_Used_2_1} B"
    elif [[ ${transfer_enable_Used_2_1} -lt 1048576 ]]; then
      transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1024'}')
      transfer_enable_Used_2="${transfer_enable_Used_2} KB"
    elif [[ ${transfer_enable_Used_2_1} -lt 1073741824 ]]; then
      transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1048576'}')
      transfer_enable_Used_2="${transfer_enable_Used_2} MB"
    elif [[ ${transfer_enable_Used_2_1} -lt 1099511627776 ]]; then
      transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1073741824'}')
      transfer_enable_Used_2="${transfer_enable_Used_2} GB"
    elif [[ ${transfer_enable_Used_2_1} -lt 1125899906842624 ]]; then
      transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1099511627776'}')
      transfer_enable_Used_2="${transfer_enable_Used_2} TB"
    fi
    #echo "transfer_enable_Used_2=${transfer_enable_Used_2}"
  }
  urlsafe_base64() {
    date=$(echo -n "$1" | base64 -w0)
    echo -e "${date}"
  }
  ss_link_qr() {
    SSbase64=$(urlsafe_base64 "${method}:${password}@${ip}:${port}")
    SSurl="ss://${SSbase64}"
    SSQRcode="http://www.codigos-qr.com/qr/php/qr_img.php?d=${SSurl}"
    ss_link=" SS    Link :\n ${Green_font_prefix}${SSurl}${Font_color_suffix} \n Codigo QR SS:\n ${Green_font_prefix}${SSQRcode}${Font_color_suffix}"
  }
  ssr_link_qr() {

    SSRprotocol=$(echo ${protocol} | sed 's/_compatible//g')
    SSRobfs=$(echo ${obfs} | sed 's/_compatible//g')
    SSRPWDbase64=$(urlsafe_base64 "${password}")
    SSRbase64=$(urlsafe_base64 "${ip}:${port}:${SSRprotocol}:${method}:${SSRobfs}:${SSRPWDbase64}/?obfsparam=")
    SSRurl="ssr://${SSRbase64}"
    SSRQRcode="http://www.codigos-qr.com/qr/php/qr_img.php?d=${SSRurl}"
    ssr_link=" SSR   Link :\n ${Red_font_prefix}${SSRurl}${Font_color_suffix} \n Codigo QR SSR:\n ${Red_font_prefix}${SSRQRcode}${Font_color_suffix}"
  }
  ss_ssr_determine() {
    protocol_suffix=$(echo ${protocol} | awk -F "_" '{print $NF}')
    obfs_suffix=$(echo ${obfs} | awk -F "_" '{print $NF}')
    if [[ ${protocol} = "origin" ]]; then
      if [[ ${obfs} = "plain" ]]; then
        ss_link_qr
        ssr_link=""
      else
        if [[ ${obfs_suffix} != "compatible" ]]; then
          ss_link=""
        else
          ss_link_qr
        fi
      fi
    else
      if [[ ${protocol_suffix} != "compatible" ]]; then
        ss_link=""
      else
        if [[ ${obfs_suffix} != "compatible" ]]; then
          if [[ ${obfs_suffix} = "plain" ]]; then
            ss_link_qr
          else
            ss_link=""
          fi
        else
          ss_link_qr
        fi
      fi
    fi
    ssr_link_qr
  }
  # Display configuration information
  View_User() {
    clear
    SSR_installation_status
    List_port_user
    while true; do
      echo -e "\e[93mIngrese el puerto de usuario para ver la informacion\nmas detallada"
      msg -bar
      echo -ne "\033[97m (Predeterminado: cancelar): \033[1;32m" && read View_user_port
      [[ -z "${View_user_port}" ]] && echo -e "Cancelado ...\n$(msg -bar)" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
      View_user=$(cat "${config_user_mudb_file}" | grep '"port": '"${View_user_port}"',')
      if [[ ! -z ${View_user} ]]; then
        Get_User_info "${View_user_port}"
        View_User_info
        break
      else
        echo -e "${Error} Por favor ingrese el puerto correcto !"
      fi
    done
    read -p "Enter para continuar" enter
  }
  View_User_info() {
    ip=$(cat ${config_user_api_file} | grep "SERVER_PUB_ADDR = " | awk -F "[']" '{print $2}')
    [[ -z "${ip}" ]] && Get_IP
    ss_ssr_determine
    clear
    echo -e " Usuario [${user_name}] Informacion de Cuenta:"
    msg -bar

    echo -e " IP : ${Green_font_prefix}${ip}${Font_color_suffix}"

    echo -e " Puerto : ${Green_font_prefix}${port}${Font_color_suffix}"

    echo -e " Contraseña : ${Green_font_prefix}${password}${Font_color_suffix}"

    echo -e " Encriptacion : ${Green_font_prefix}${method}${Font_color_suffix}"

    echo -e " Protocol : ${Red_font_prefix}${protocol}${Font_color_suffix}"

    echo -e " Obfs : ${Red_font_prefix}${obfs}${Font_color_suffix}"

    echo -e " Limite de dispositivos: ${Green_font_prefix}${protocol_param}${Font_color_suffix}"

    echo -e " Velocidad de subproceso Unico: ${Green_font_prefix}${speed_limit_per_con} KB/S${Font_color_suffix}"

    echo -e " Velocidad Maxima del Usuario: ${Green_font_prefix}${speed_limit_per_user} KB/S${Font_color_suffix}"

    echo -e " Puertos Prohibido: ${Green_font_prefix}${forbidden_port} ${Font_color_suffix}"

    echo -e " Consumo de sus Datos:\n Carga: ${Green_font_prefix}${u}${Font_color_suffix} + Descarga: ${Green_font_prefix}${d}${Font_color_suffix} = ${Green_font_prefix}${transfer_enable_Used_2}${Font_color_suffix}"

    echo -e " Trafico Restante: ${Green_font_prefix}${transfer_enable_Used} ${Font_color_suffix}"
    msg -bar
    echo -e " Trafico Total del Usuario: ${Green_font_prefix}${transfer_enable} ${Font_color_suffix}"
    msg -bar
    echo -e "${ss_link}"
    msg -bar
    echo -e "${ssr_link}"
    msg -bar
    echo -e " ${Green_font_prefix} Nota: ${Font_color_suffix}
 En el navegador, abra el enlace del codigo QR, puede\n ver la imagen del codigo QR."
    msg -bar
  }
  #Configuracion de la informacion de configuracion
  Set_config_user() {
    msg -bar
    echo -ne "\e[1;93m  [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;97mIngrese un nombre de usuario\n"
    msg -bar
    read -p "(Predeterminado: LATAM):" ssr_user
    [[ -z "${ssr_user}" ]] && ssr_user="LATAM"
    echo && echo -e "	Nombre de usuario : ${Green_font_prefix}${ssr_user}${Font_color_suffix}" && echo
  }
  Set_config_port() {
    msg -bar
    while true; do
      echo -e "\e[1;93m  [\e[1;32m2\e[1;93m]\033[1;31m > \e[1;97mPor favor ingrese un Puerto "
      msg -bar
      read -p "(Predeterminado: 2525):" ssr_port
      [[ -z "$ssr_port" ]] && ssr_port="2525"
      expr ${ssr_port} + 0 &>/dev/null
      if [[ $? == 0 ]]; then
        if [[ ${ssr_port} -ge 1 ]] && [[ ${ssr_port} -le 65535 ]]; then
          echo && echo -e "	Port : ${Green_font_prefix}${ssr_port}${Font_color_suffix}" && echo
          break
        else
          echo -e "${Error} Por favor ingrese el numero correcto (1-65535)"
        fi
      else
        echo -e "${Error} Por favor ingrese el numero correcto (1-65535)"
      fi
    done
  }
  Set_config_password() {
    msg -bar
    echo -e "\e[1;93m  [\e[1;32m3\e[1;93m]\033[1;31m > \e[1;97mPor favor ingrese una contrasena para el Usuario"
    msg -bar
    read -p "(Predeterminado: LATAM):" ssr_password
    [[ -z "${ssr_password}" ]] && ssr_password="LATAM"
    echo && echo -e "	contrasena : ${Green_font_prefix}${ssr_password}${Font_color_suffix}" && echo
  }
  Set_config_method() {
    msg -bar
    echo -e "\e[1;93m  [\e[1;32m4\e[1;93m]\033[1;31m > \e[1;97mSeleccione tipo de Encriptacion 
$(msg -bar)
 ${Green_font_prefix} 1.${Font_color_suffix} Ninguno
 ${Green_font_prefix} 2.${Font_color_suffix} rc4
 ${Green_font_prefix} 3.${Font_color_suffix} rc4-md5
 ${Green_font_prefix} 4.${Font_color_suffix} rc4-md5-6
 ${Green_font_prefix} 5.${Font_color_suffix} aes-128-ctr
 ${Green_font_prefix} 6.${Font_color_suffix} aes-192-ctr
 ${Green_font_prefix} 7.${Font_color_suffix} aes-256-ctr
 ${Green_font_prefix} 8.${Font_color_suffix} aes-128-cfb
 ${Green_font_prefix} 9.${Font_color_suffix} aes-192-cfb
 ${Green_font_prefix}10.${Font_color_suffix} aes-256-cfb
 ${Green_font_prefix}11.${Font_color_suffix} aes-128-cfb8
 ${Green_font_prefix}12.${Font_color_suffix} aes-192-cfb8
 ${Green_font_prefix}13.${Font_color_suffix} aes-256-cfb8
 ${Green_font_prefix}14.${Font_color_suffix} salsa20
 ${Green_font_prefix}15.${Font_color_suffix} chacha20
 ${Green_font_prefix}16.${Font_color_suffix} chacha20-ietf
 
 ${Red_font_prefix}17.${Font_color_suffix} xsalsa20
 ${Red_font_prefix}18.${Font_color_suffix} xchacha20
$(msg -bar)
 ${Tip} Para salsa20/chacha20-*:\n Porfavor instale libsodium:\n Opcion 4 en menu principal SSRR"
    msg -bar
    read -p "(Predeterminado: 16. chacha20-ietf):" ssr_method
    msg -bar
    [[ -z "${ssr_method}" ]] && ssr_method="16"
    if [[ ${ssr_method} == "1" ]]; then
      ssr_method="Ninguno"
    elif [[ ${ssr_method} == "2" ]]; then
      ssr_method="rc4"
    elif [[ ${ssr_method} == "3" ]]; then
      ssr_method="rc4-md5"
    elif [[ ${ssr_method} == "4" ]]; then
      ssr_method="rc4-md5-6"
    elif [[ ${ssr_method} == "5" ]]; then
      ssr_method="aes-128-ctr"
    elif [[ ${ssr_method} == "6" ]]; then
      ssr_method="aes-192-ctr"
    elif [[ ${ssr_method} == "7" ]]; then
      ssr_method="aes-256-ctr"
    elif [[ ${ssr_method} == "8" ]]; then
      ssr_method="aes-128-cfb"
    elif [[ ${ssr_method} == "9" ]]; then
      ssr_method="aes-192-cfb"
    elif [[ ${ssr_method} == "10" ]]; then
      ssr_method="aes-256-cfb"
    elif [[ ${ssr_method} == "11" ]]; then
      ssr_method="aes-128-cfb8"
    elif [[ ${ssr_method} == "12" ]]; then
      ssr_method="aes-192-cfb8"
    elif [[ ${ssr_method} == "13" ]]; then
      ssr_method="aes-256-cfb8"
    elif [[ ${ssr_method} == "14" ]]; then
      ssr_method="salsa20"
    elif [[ ${ssr_method} == "15" ]]; then
      ssr_method="chacha20"
    elif [[ ${ssr_method} == "16" ]]; then
      ssr_method="chacha20-ietf"
    elif [[ ${ssr_method} == "17" ]]; then
      ssr_method="xsalsa20"
    elif [[ ${ssr_method} == "18" ]]; then
      ssr_method="xchacha20"
    else
      ssr_method="aes-256-cfb"
    fi
    echo && echo -e "	Encriptacion: ${Green_font_prefix}${ssr_method}${Font_color_suffix}" && echo
  }
  Set_config_protocol() {
    msg -bar
    echo -e "\e[1;93m  [\e[1;32m5\e[1;93m]\033[1;31m > \e[1;97mPor favor, seleccione un Protocolo
$(msg -bar)
 ${Green_font_prefix}1.${Font_color_suffix} origin
 ${Green_font_prefix}2.${Font_color_suffix} auth_sha1_v4
 ${Green_font_prefix}3.${Font_color_suffix} auth_aes128_md5
 ${Green_font_prefix}4.${Font_color_suffix} auth_aes128_sha1
 ${Green_font_prefix}5.${Font_color_suffix} auth_chain_a
 ${Green_font_prefix}6.${Font_color_suffix} auth_chain_b

 ${Red_font_prefix}7.${Font_color_suffix} auth_chain_c
 ${Red_font_prefix}8.${Font_color_suffix} auth_chain_d
 ${Red_font_prefix}9.${Font_color_suffix} auth_chain_e
 ${Red_font_prefix}10.${Font_color_suffix} auth_chain_f
$(msg -bar)
 ${Tip}\n Si selecciona el protocolo de serie auth_chain_ *:\n Se recomienda establecer el metodo de cifrado en ninguno"
    msg -bar
    read -p "(Predterminado: 1. origin):" ssr_protocol
    msg -bar
    [[ -z "${ssr_protocol}" ]] && ssr_protocol="1"
    if [[ ${ssr_protocol} == "1" ]]; then
      ssr_protocol="origin"
    elif [[ ${ssr_protocol} == "2" ]]; then
      ssr_protocol="auth_sha1_v4"
    elif [[ ${ssr_protocol} == "3" ]]; then
      ssr_protocol="auth_aes128_md5"
    elif [[ ${ssr_protocol} == "4" ]]; then
      ssr_protocol="auth_aes128_sha1"
    elif [[ ${ssr_protocol} == "5" ]]; then
      ssr_protocol="auth_chain_a"
    elif [[ ${ssr_protocol} == "6" ]]; then
      ssr_protocol="auth_chain_b"
    elif [[ ${ssr_protocol} == "7" ]]; then
      ssr_protocol="auth_chain_c"
    elif [[ ${ssr_protocol} == "8" ]]; then
      ssr_protocol="auth_chain_d"
    elif [[ ${ssr_protocol} == "9" ]]; then
      ssr_protocol="auth_chain_e"
    elif [[ ${ssr_protocol} == "10" ]]; then
      ssr_protocol="auth_chain_f"
    else
      ssr_protocol="origin"
    fi
    echo && echo -e "	Protocolo : ${Green_font_prefix}${ssr_protocol}${Font_color_suffix}" && echo
    if [[ ${ssr_protocol} != "origin" ]]; then
      if [[ ${ssr_protocol} == "auth_sha1_v4" ]]; then
        read -p "Set protocol plug-in to compatible mode(_compatible)?[Y/n]" ssr_protocol_yn
        [[ -z "${ssr_protocol_yn}" ]] && ssr_protocol_yn="y"
        [[ $ssr_protocol_yn == [Yy] ]] && ssr_protocol=${ssr_protocol}"_compatible"
        echo
      fi
    fi
  }
  Set_config_obfs() {
    msg -bar
    echo -e "\e[1;93m  [\e[1;32m6\e[1;93m]\033[1;31m > \e[1;97mPor favor, seleccione el metodo OBFS
$(msg -bar)
 ${Green_font_prefix}1.${Font_color_suffix} plain
 ${Green_font_prefix}2.${Font_color_suffix} http_simple
 ${Green_font_prefix}3.${Font_color_suffix} http_post
 ${Green_font_prefix}4.${Font_color_suffix} random_head
 ${Green_font_prefix}5.${Font_color_suffix} tls1.2_ticket_auth
$(msg -bar)
  Si elige tls1.2_ticket_auth, entonces el cliente puede\n  elegir tls1.2_ticket_fastauth!"
    msg -bar
    read -p "(Predeterminado: 5. tls1.2_ticket_auth):" ssr_obfs
    [[ -z "${ssr_obfs}" ]] && ssr_obfs="5"
    if [[ ${ssr_obfs} == "1" ]]; then
      ssr_obfs="plain"
    elif [[ ${ssr_obfs} == "2" ]]; then
      ssr_obfs="http_simple"
    elif [[ ${ssr_obfs} == "3" ]]; then
      ssr_obfs="http_post"
    elif [[ ${ssr_obfs} == "4" ]]; then
      ssr_obfs="random_head"
    elif [[ ${ssr_obfs} == "5" ]]; then
      ssr_obfs="tls1.2_ticket_auth"
    else
      ssr_obfs="tls1.2_ticket_auth"
    fi
    echo && echo -e "	obfs : ${Green_font_prefix}${ssr_obfs}${Font_color_suffix}" && echo
    msg -bar
    if [[ ${ssr_obfs} != "plain" ]]; then
      read -p "Configurar modo Compatible (Para usar SS)? [y/n]: " ssr_obfs_yn
      [[ -z "${ssr_obfs_yn}" ]] && ssr_obfs_yn="y"
      [[ $ssr_obfs_yn == [Yy] ]] && ssr_obfs=${ssr_obfs}"_compatible"
    fi
  }
  Set_config_protocol_param() {
    msg -bar
    while true; do
      echo -e "\e[1;93m  [\e[1;32m7\e[1;93m]\033[1;31m > \e[1;97mLimitar Cantidad de Dispositivos Simultaneos\n  ${Green_font_prefix} auth_*La serie no es compatible con la version original. ${Font_color_suffix}"
      msg -bar
      echo -e "${Tip} Limite de numero de dispositivos:\n Es el numero de clientes que usaran la cuenta\n el minimo recomendado 2."
      msg -bar
      read -p "(Predeterminado: Ilimitado):" ssr_protocol_param
      [[ -z "$ssr_protocol_param" ]] && ssr_protocol_param="" && echo && break
      expr ${ssr_protocol_param} + 0 &>/dev/null
      if [[ $? == 0 ]]; then
        if [[ ${ssr_protocol_param} -ge 1 ]] && [[ ${ssr_protocol_param} -le 9999 ]]; then
          echo && echo -e "	Limite del dispositivo: ${Green_font_prefix}${ssr_protocol_param}${Font_color_suffix}" && echo
          break
        else
          echo -e "${Error} Por favor ingrese el numero correcto (1-9999)"
        fi
      else
        echo -e "${Error} Por favor ingrese el numero correcto (1-9999)"
      fi
    done
  }
  Set_config_speed_limit_per_con() {
    msg -bar
    while true; do
      echo -e "\e[1;93m  [\e[1;32m8\e[1;93m]\033[1;31m > \e[1;97mIntroduzca un Limite de Velocidad x Hilo (en KB/S)"
      msg -bar
      read -p "(Predterminado: Ilimitado):" ssr_speed_limit_per_con
      msg -bar
      [[ -z "$ssr_speed_limit_per_con" ]] && ssr_speed_limit_per_con=0 && echo && break
      expr ${ssr_speed_limit_per_con} + 0 &>/dev/null
      if [[ $? == 0 ]]; then
        if [[ ${ssr_speed_limit_per_con} -ge 1 ]] && [[ ${ssr_speed_limit_per_con} -le 131072 ]]; then
          echo && echo -e "	Velocidad de Subproceso Unico: ${Green_font_prefix}${ssr_speed_limit_per_con} KB/S${Font_color_suffix}" && echo
          break
        else
          echo -e "${Error} Por favor ingrese el numero correcto (1-131072)"
        fi
      else
        echo -e "${Error} Por favor ingrese el numero correcto (1-131072)"
      fi
    done
  }
  Set_config_speed_limit_per_user() {
    msg -bar
    while true; do
      echo -e "\e[1;93m  [\e[1;32m9\e[1;93m]\033[1;31m > \e[1;97mIntroduzca un Limite de Velocidad Maxima (en KB/S)"
      msg -bar
      echo -e "${Tip} Limite de Velocidad Maxima del Puerto :\n Es la velocidad maxima que ira el Usuario."
      msg -bar
      read -p "(Predeterminado: Ilimitado):" ssr_speed_limit_per_user
      [[ -z "$ssr_speed_limit_per_user" ]] && ssr_speed_limit_per_user=0 && echo && break
      expr ${ssr_speed_limit_per_user} + 0 &>/dev/null
      if [[ $? == 0 ]]; then
        if [[ ${ssr_speed_limit_per_user} -ge 1 ]] && [[ ${ssr_speed_limit_per_user} -le 131072 ]]; then
          echo && echo -e "	Velocidad Maxima del Usuario : ${Green_font_prefix}${ssr_speed_limit_per_user} KB/S${Font_color_suffix}" && echo
          break
        else
          echo -e "${Error} Por favor ingrese el numero correcto (1-131072)"
        fi
      else
        echo -e "${Error} Por favor ingrese el numero correcto (1-131072)"
      fi
    done
  }
  Set_config_transfer() {
    msg -bar
    while true; do
      echo -e "\e[1;93m  [\e[1;32m10\e[1;93m]\033[1;31m > \e[1;97mIngrese Cantidad Total de Datos para el Usuario\n   (en GB, 1-838868 GB)"
      msg -bar
      read -p "(Predeterminado: Ilimitado):" ssr_transfer
      [[ -z "$ssr_transfer" ]] && ssr_transfer="838868" && echo && break
      expr ${ssr_transfer} + 0 &>/dev/null
      if [[ $? == 0 ]]; then
        if [[ ${ssr_transfer} -ge 1 ]] && [[ ${ssr_transfer} -le 838868 ]]; then
          echo && echo -e "	Trafico Total Para El Usuario: ${Green_font_prefix}${ssr_transfer} GB${Font_color_suffix}" && echo
          break
        else
          echo -e "${Error} Por favor ingrese el numero correcto (1-838868)"
        fi
      else
        echo -e "${Error} Por favor ingrese el numero correcto (1-838868)"
      fi
    done
  }
  Set_config_forbid() {
    msg -bar
    echo "PROIBIR PUERTOS"
    msg -bar
    echo -e "${Tip} Puertos prohibidos:\n Por ejemplo, si no permite el acceso al puerto 25, los\n usuarios no podran acceder al puerto de correo 25 a\n traves del proxy de SSR. Si 80,443 esta desactivado,\n los usuarios no podran acceda a los sitios\n http/https normalmente."
    msg -bar
    read -p "(Predeterminado: permitir todo):" ssr_forbid
    [[ -z "${ssr_forbid}" ]] && ssr_forbid=""
    echo && echo -e "	Puerto prohibido: ${Green_font_prefix}${ssr_forbid}${Font_color_suffix}" && echo
  }
  Set_config_enable() {
    user_total=$(expr ${user_total} - 1)
    for ((integer = 0; integer <= ${user_total}; integer++)); do
      echo -e "integer=${integer}"
      port_jq=$(${jq_file} ".[${integer}].port" "${config_user_mudb_file}")
      echo -e "port_jq=${port_jq}"
      if [[ "${ssr_port}" == "${port_jq}" ]]; then
        enable=$(${jq_file} ".[${integer}].enable" "${config_user_mudb_file}")
        echo -e "enable=${enable}"
        [[ "${enable}" == "null" ]] && echo -e "${Error} Obtenga el puerto actual [${ssr_port}] Estado deshabilitado fallido!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
        ssr_port_num=$(cat "${config_user_mudb_file}" | grep -n '"puerto": '${ssr_port}',' | awk -F ":" '{print $1}')
        echo -e "ssr_port_num=${ssr_port_num}"
        [[ "${ssr_port_num}" == "null" ]] && echo -e "${Error}Obtener actual Puerto [${ssr_port}] Numero de filas fallidas!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
        ssr_enable_num=$(expr ${ssr_port_num} - 5)
        echo -e "ssr_enable_num=${ssr_enable_num}"
        break
      fi
    done
    if [[ "${enable}" == "1" ]]; then
      echo -e "Puerto [${ssr_port}] El estado de la cuenta es: ${Green_font_prefix}Enabled ${Font_color_suffix} , Cambiar a ${Red_font_prefix}Disabled${Font_color_suffix} ?[Y/n]"
      read -p "(Predeterminado: Y):" ssr_enable_yn
      [[ -z "${ssr_enable_yn}" ]] && ssr_enable_yn="y"
      if [[ "${ssr_enable_yn}" == [Yy] ]]; then
        ssr_enable="0"
      else
        echo -e "Cancelado...\n$(msg -bar)" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
      fi
    elif [[ "${enable}" == "0" ]]; then
      echo -e "Port [${ssr_port}] El estado de la cuenta:${Green_font_prefix}Habilitado ${Font_color_suffix} , Cambie a ${Red_font_prefix}Deshabilitado${Font_color_suffix} ?[Y/n]"
      read -p "(Predeterminado: Y):" ssr_enable_yn
      [[ -z "${ssr_enable_yn}" ]] && ssr_enable_yn = "y"
      if [[ "${ssr_enable_yn}" == [Yy] ]]; then
        ssr_enable="1"
      else
        echo "Cancelar ..." && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
      fi
    else
      echo -e "${Error} El actual estado de discapacidad de Puerto es anormal.[${enable}] !" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    fi
  }
  Set_user_api_server_pub_addr() {
    addr=$1
    if [[ "${addr}" == "Modify" ]]; then
      server_pub_addr=$(cat ${config_user_api_file} | grep "SERVER_PUB_ADDR = " | awk -F "[']" '{print $2}')
      if [[ -z ${server_pub_addr} ]]; then
        echo -e "${Error} La IP del servidor o el nombre de dominio obtenidos fallaron!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
      else
        echo -e "${Info} La IP del servidor o el nombre de dominio actualmente configurados es ${Green_font_prefix}${server_pub_addr}${Font_color_suffix}"
      fi
    fi

    msg -bar
    read -p "(Deteccion automatica de IP):" ssr_server_pub_addr
    if [[ -z "${ssr_server_pub_addr}" ]]; then
      Get_IP
      if [[ ${ip} == "VPS_IP" ]]; then
        while true; do
          read -p "${Error} La deteccion automatica de la IP de la red externa fallo, ingrese manualmente la IP del servidor o el nombre de dominio" ssr_server_pub_addr
          if [[ -z "$ssr_server_pub_addr" ]]; then
            echo -e "${Error}No puede estar vacio!"
          else
            break
          fi
        done
      else
        ssr_server_pub_addr="${ip}"
      fi
    fi
    echo && msg -bar && echo -e "	IP o nombre de dominio: ${Green_font_prefix}${ssr_server_pub_addr}${Font_color_suffix}" && msg -bar && echo
  }
  Set_config_all() {
    lal=$1
    if [[ "${lal}" == "Modify" ]]; then
      Set_config_password
      Set_config_method
      Set_config_protocol
      Set_config_obfs
      Set_config_protocol_param
      Set_config_speed_limit_per_con
      Set_config_speed_limit_per_user
      Set_config_transfer
      Set_config_forbid
    else
      Set_config_user
      Set_config_port
      Set_config_password
      Set_config_method
      Set_config_protocol
      Set_config_obfs
      Set_config_protocol_param
      Set_config_speed_limit_per_con
      Set_config_speed_limit_per_user
      Set_config_transfer
      Set_config_forbid
    fi
  }
  #Modificar la informaci�n de configuraci�n
  Modify_config_password() {
    match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -k "${ssr_password}" | grep -w "edit user ")
    if [[ -z "${match_edit}" ]]; then
      echo -e "${Error} Fallo la modificacion de la contrasena del usuario ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} " && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    else
      echo -e "${Info} La contrasena del usuario se modifico correctamente ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} (Puede tardar unos 10 segundos aplicar la ultima configuracion)"
    fi
  }
  Modify_config_method() {
    match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -m "${ssr_method}" | grep -w "edit user ")
    if [[ -z "${match_edit}" ]]; then
      echo -e "${Error} La modificacion del metodo de cifrado del usuario fallo ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} " && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    else
      echo -e "${Info} Modo de cifrado de usuario ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} (Note: Nota: la configuracion mas reciente puede demorar unos 10 segundos)"
    fi
  }
  Modify_config_protocol() {
    match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -O "${ssr_protocol}" | grep -w "edit user ")
    if [[ -z "${match_edit}" ]]; then
      echo -e "${Error} Fallo la modificacion del protocolo de usuario ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} " && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    else
      echo -e "${Info} Acuerdo de usuario modificacion exito ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} (Nota: la configuracion m�s reciente puede demorar unos 10 segundos)"
    fi
  }
  Modify_config_obfs() {
    match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -o "${ssr_obfs}" | grep -w "edit user ")
    if [[ -z "${match_edit}" ]]; then
      echo -e "${Error} La modificacion de la confusion del usuario fallo ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} " && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    else
      echo -e "${Info} Confusion del usuario exito de modificacion ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} (Nota: La aplicacion de la ultima configuracion puede demorar unos 10 segundos)"
    fi
  }
  Modify_config_protocol_param() {
    match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -G "${ssr_protocol_param}" | grep -w "edit user ")
    if [[ -z "${match_edit}" ]]; then
      echo -e "${Error} Fallo la modificacion del parametro del protocolo del usuario (numero de dispositivos limite) ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} " && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    else
      echo -e "${Info} Parametros de negociaci�n del usuario (numero de dispositivos limite) modificados correctamente ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} (Nota: puede tomar aproximadamente 10 segundos aplicar la ultima configuracion)"
    fi
  }
  Modify_config_speed_limit_per_con() {
    match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -s "${ssr_speed_limit_per_con}" | grep -w "edit user ")
    if [[ -z "${match_edit}" ]]; then
      echo -e "${Error} Fallo la modificacion de la velocidad de un solo hilo ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} " && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    else
      echo -e "${Info} Modificacion de la velocidad de un solo hilo exitosa ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} (Nota: puede tomar aproximadamente 10 segundos aplicar la ultima configuracion)"
    fi
  }
  Modify_config_speed_limit_per_user() {
    match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -S "${ssr_speed_limit_per_user}" | grep -w "edit user ")
    if [[ -z "${match_edit}" ]]; then
      echo -e "${Error} Usuario Puerto la modificaci�n del limite de velocidad total fallo ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} " && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    else
      echo -e "${Info} Usuario Puerto limite de velocidad total modificado con exito ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} (Nota: la configuracion mas reciente puede demorar unos 10 segundos)"
    fi
  }
  Modify_config_connect_verbose_info() {
    sed -i 's/"connect_verbose_info": '"$(echo ${connect_verbose_info})"',/"connect_verbose_info": '"$(echo ${ssr_connect_verbose_info})"',/g' ${config_user_file}
  }
  Modify_config_transfer() {
    match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -t "${ssr_transfer}" | grep -w "edit user ")
    if [[ -z "${match_edit}" ]]; then
      echo -e "${Error} La modificacion de trafico total del usuario fallo ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} " && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    else
      echo -e "${Info} Trafico total del usuario ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} (Nota: la configuracion mas reciente puede demorar unos 10 segundos)"
    fi
  }
  Modify_config_forbid() {
    match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -f "${ssr_forbid}" | grep -w "edit user ")
    if [[ -z "${match_edit}" ]]; then
      echo -e "${Error} La modificacion del puerto prohibido por el usuario ha fallado ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} " && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    else
      echo -e "${Info} Los puertos prohibidos por el usuario se modificaron correctamente ${Green_font_prefix}[Port: ${ssr_port}]${Font_color_suffix} (Nota: puede tomar aproximadamente 10 segundos aplicar la ultima configuracion)"
    fi
  }
  Modify_config_enable() {
    sed -i "${ssr_enable_num}"'s/"enable": '"$(echo ${enable})"',/"enable": '"$(echo ${ssr_enable})"',/' ${config_user_mudb_file}
  }
  Modify_user_api_server_pub_addr() {
    sed -i "s/SERVER_PUB_ADDR = '${server_pub_addr}'/SERVER_PUB_ADDR = '${ssr_server_pub_addr}'/" ${config_user_api_file}
  }
  Modify_config_all() {
    Modify_config_password
    Modify_config_method
    Modify_config_protocol
    Modify_config_obfs
    Modify_config_protocol_param
    Modify_config_speed_limit_per_con
    Modify_config_speed_limit_per_user
    Modify_config_transfer
    Modify_config_forbid
  }
  Check_python() {
    python_ver=$(python -h)
    if [[ -z ${python_ver} ]]; then
      echo -e "${Info} No instalo Python, comience a instalar ..."
      if [[ ${release} == "centos" ]]; then
        yum install -y python
      else
        apt-get install -y python
      fi
    fi
  }
  Centos_yum() {
    yum update
    cat /etc/redhat-release | grep 7\..* | grep -i centos >/dev/null
    if [[ $? = 0 ]]; then
      yum install -y vim unzip crond net-tools git
    else
      yum install -y vim unzip crond git
    fi
  }
  Debian_apt() {
    apt-get update
    apt-get install -y vim unzip cron git net-tools
  }
  #Descargar ShadowsocksR
  Download_SSR() {
    cd "/usr/local"
    # wget -N --no-check-certificate "https://github.com/ToyoDAdoubi/shadowsocksr/archive/manyuser.zip"
    #git config --global http.sslVerify false
    git clone -b akkariiin/master https://github.com/shadowsocksrr/shadowsocksr.git
    [[ ! -e ${ssr_folder} ]] && echo -e "${Error} Fallo la descarga del servidor ShadowsocksR!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    # [[ ! -e "manyuser.zip" ]] && echo -e "${Error} Fallo la descarga del paquete de compresion lateral ShadowsocksR !" && rm -rf manyuser.zip && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    # unzip "manyuser.zip"
    # [[ ! -e "/usr/local/shadowsocksr-manyuser/" ]] && echo -e "${Error} Fallo la descompresi�n del servidor ShadowsocksR !" && rm -rf manyuser.zip && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    # mv "/usr/local/shadowsocksr-manyuser/" "/usr/local/shadowsocksr/"
    # [[ ! -e "/usr/local/shadowsocksr/" ]] && echo -e "${Error} Fallo el cambio de nombre del servidor ShadowsocksR!" && rm -rf manyuser.zip && rm -rf "/usr/local/shadowsocksr-manyuser/" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    # rm -rf manyuser.zip
    cd "shadowsocksr"
    cp "${ssr_folder}/config.json" "${config_user_file}"
    cp "${ssr_folder}/mysql.json" "${ssr_folder}/usermysql.json"
    cp "${ssr_folder}/apiconfig.py" "${config_user_api_file}"
    [[ ! -e ${config_user_api_file} ]] && echo -e "${Error} Fallo la replicacion apiconfig.py del servidor ShadowsocksR!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    sed -i "s/API_INTERFACE = 'sspanelv2'/API_INTERFACE = 'mudbjson'/" ${config_user_api_file}
    server_pub_addr="127.0.0.1"
    Modify_user_api_server_pub_addr
    #sed -i "s/SERVER_PUB_ADDR = '127.0.0.1'/SERVER_PUB_ADDR = '${ip}'/" ${config_user_api_file}
    sed -i 's/ \/\/ only works under multi-user mode//g' "${config_user_file}"
    echo -e "${Info} Descarga del servidor ShadowsocksR completa!"
  }
  Service_SSR() {
    if [[ ${release} = "centos" ]]; then
      if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/service/ssrmu_centos -O /etc/init.d/ssrmu; then
        echo -e "${Error} Fallo la descarga de la secuencia de comandos de administracion de servicios de ShadowsocksR!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
      fi
      chmod +x /etc/init.d/ssrmu
      chkconfig --add ssrmu
      chkconfig ssrmu on
    else
      if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/service/ssrmu_debian -O /etc/init.d/ssrmu; then
        echo -e "${Error} Fallo la descarga de la secuencia de comandos de administracion de servicio de ShadowsocksR!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
      fi
      chmod +x /etc/init.d/ssrmu
      update-rc.d -f ssrmu defaults
    fi
    echo -e "${Info} ShadowsocksR Service Management Script Descargar Descargar!"
  }
  #Instalar el analizador JQ
  JQ_install() {
    if [[ ! -e ${jq_file} ]]; then
      cd "${ssr_folder}"
      if [[ ${bit} = "x86_64" ]]; then
        # mv "jq-linux64" "jq"
        wget --no-check-certificate "https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux64" -O ${jq_file}
      else
        # mv "jq-linux32" "jq"
        wget --no-check-certificate "https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux32" -O ${jq_file}
      fi
      [[ ! -e ${jq_file} ]] && echo -e "${Error} JQ parser, por favor!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
      chmod +x ${jq_file}
      echo -e "${Info} La instalacion del analizador JQ se ha completado, continuar ..."
    else
      echo -e "${Info} JQ parser esta instalado, continuar ..."
    fi
  }
  #Instalacion
  Installation_dependency() {
    if [[ ${release} == "centos" ]]; then
      Centos_yum
    else
      Debian_apt
    fi
    [[ ! -e "/usr/bin/unzip" ]] && echo -e "${Error} Dependiente de la instalacion de descomprimir (paquete comprimido) fallo, en su mayoria problema, por favor verifique!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    Check_python
    #echo "nameserver 8.8.8.8" > /etc/resolv.conf
    #echo "nameserver 8.8.4.4" >> /etc/resolv.conf
    cp -f /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
    if [[ ${release} == "centos" ]]; then
      /etc/init.d/crond restart
    else
      /etc/init.d/cron restart
    fi
  }
  Install_SSR() {
    clear
    check_root
    msg -bar
    [[ -e ${ssr_folder} ]] && echo -e "${Error}\nLa carpeta ShadowsocksR ha sido creada, por favor verifique\n(si la instalacion falla, desinstalela primero) !\n$(msg -bar)" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    echo -e "${Info}\nProceso de instaacion de ShadowsocksR..."
    Set_user_api_server_pub_addr
    Set_config_all
    echo -e "${Info} Comience a instalar / configurar las dependencias de ShadowsocksR ..."
    Installation_dependency
    echo -e "${Info} Iniciar descarga / Instalar ShadowsocksR File ..."
    Download_SSR
    echo -e "${Info} Iniciar descarga / Instalar ShadowsocksR Service Script(init)..."
    Service_SSR
    echo -e "${Info} Iniciar descarga / instalar JSNO Parser JQ ..."
    JQ_install
    echo -e "${Info} Comience a agregar usuario inicial ..."
    Add_port_user "install"
    echo -e "${Info} Empezar a configurar el firewall de iptables ..."
    Set_iptables
    echo -e "${Info} Comience a agregar reglas de firewall de iptables ..."
    Add_iptables
    echo -e "${Info} Comience a guardar las reglas del servidor de seguridad de iptables ..."
    Save_iptables
    echo -e "${Info} Todos los pasos para iniciar el servicio ShadowsocksR ..."
    Start_SSR
    Get_User_info "${ssr_port}"
    View_User_info

  }
  Update_SSR() {
    SSR_installation_status
    # echo -e "Debido a que el beb� roto actualiza el servidor ShadowsocksR, entonces."
    cd ${ssr_folder}
    git pull
    Restart_SSR

  }
  Uninstall_SSR() {
    clear && clear
    msg -bar
    [[ ! -e ${ssr_folder} ]] && echo -e "${Error} ShadowsocksR no esta instalado\n$(msg -bar)" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    echo -e "\e[1;97m Desinstalar ShadowsocksR [y/n]"
    msg -bar
    read -p "(Predeterminado: n):" unyn
    msg -bar
    [[ -z ${unyn} ]] && unyn="n"
    if [[ ${unyn} == [Yy] ]]; then
      check_pid
      [[ ! -z "${PID}" ]] && kill -9 ${PID}
      user_info=$(python mujson_mgr.py -l)
      user_total=$(echo "${user_info}" | wc -l)
      if [[ ! -z ${user_info} ]]; then
        for ((integer = 1; integer <= ${user_total}; integer++)); do
          port=$(echo "${user_info}" | sed -n "${integer}p" | awk '{print $4}')
          Del_iptables
        done
      fi
      if [[ ${release} = "centos" ]]; then
        chkconfig --del ssrmu
      else
        update-rc.d -f ssrmu remove
      fi
      rm -rf ${ssr_folder} && rm -rf /etc/init.d/ssrmu
      echo -e "\e[1;32     DESINSTALACION DE SSR COMPLETA "
      msg -bar
      read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      controlador_ssr
    else
      echo && echo "\e[1;31m       Desinstalar cancelado ..." && echo
    fi

  }
  Check_Libsodium_ver() {
    echo -e "${Info} Descargando la ultima version de libsodium"
    #Libsodiumr_ver=$(wget -qO- "https://github.com/jedisct1/libsodium/tags"|grep "/jedisct1/libsodium/releases/tag/"|head -1|sed -r 's/.*tag\/(.+)\">.*/\1/')
    Libsodiumr_ver=1.0.17
    [[ -z ${Libsodiumr_ver} ]] && Libsodiumr_ver=${Libsodiumr_ver_backup}
    echo -e "${Info} La ultima version de libsodium es ${Green_font_prefix}${Libsodiumr_ver}${Font_color_suffix} !"
  }
  Install_Libsodium() {
    if [[ -e ${Libsodiumr_file} ]]; then
      echo -e "${Error} libsodium ya instalado, quieres actualizar?[y/N]"
      read -p "(Default: n):" yn
      [[ -z ${yn} ]] && yn="n"
      if [[ ${yn} == [Nn] ]]; then
        echo -e "Cancelado...\n$(msg -bar)" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
      fi
    else
      echo -e "${Info} libsodium no instalado, instalacion iniciada ..."
    fi
    Check_Libsodium_ver
    if [[ ${release} == "centos" ]]; then
      yum -y actualizacion
      echo -e "${Info} La instalacion depende de ..."
      yum -y groupinstall "Herramientas de desarrollo"
      echo -e "${Info} Descargar ..."
      wget --no-check-certificate -N "https://github.com/jedisct1/libsodium/releases/download/${Libsodiumr_ver}/libsodium-${Libsodiumr_ver}.tar.gz"
      echo -e "${Info} Descomprimir ..."
      tar -xzf libsodium-${Libsodiumr_ver}.tar.gz && cd libsodium-${Libsodiumr_ver}
      echo -e "${Info} Compilar e instalar ..."
      ./configure --disable-maintainer-mode && make -j2 && make install
      echo /usr/local/lib >/etc/ld.so.conf.d/usr_local_lib.conf
    else
      apt-get update
      echo -e "${Info} La instalacion depende de ..."
      apt-get install -y build-essential
      echo -e "${Info} Descargar ..."
      wget --no-check-certificate -N "https://github.com/jedisct1/libsodium/releases/download/${Libsodiumr_ver}/libsodium-${Libsodiumr_ver}.tar.gz"
      echo -e "${Info} Descomprimir ..."
      tar -xzf libsodium-${Libsodiumr_ver}.tar.gz && cd libsodium-${Libsodiumr_ver}
      echo -e "${Info} Compilar e instalar ..."
      ./configure --disable-maintainer-mode && make -j2 && make install
    fi
    ldconfig
    cd .. && rm -rf libsodium-${Libsodiumr_ver}.tar.gz && rm -rf libsodium-${Libsodiumr_ver}
    [[ ! -e ${Libsodiumr_file} ]] && echo -e "${Error} libsodium Instalacion fallida!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    echo && echo -e "${Info} libsodium exito de instalacion!" && echo
    msg -bar
  }
  #Mostrar informaci�n de conexi�n
  debian_View_user_connection_info() {
    format_1=$1
    user_info=$(python mujson_mgr.py -l)
    user_total=$(echo "${user_info}" | wc -l)
    [[ -z ${user_info} ]] && echo -e "${Error} No encontro, por favor compruebe!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    IP_total=$(netstat -anp | grep 'ESTABLISHED' | grep 'python' | grep 'tcp6' | awk '{print $5}' | awk -F ":" '{print $1}' | sort -u | wc -l)
    user_list_all=""
    for ((integer = 1; integer <= ${user_total}; integer++)); do
      user_port=$(echo "${user_info}" | sed -n "${integer}p" | awk '{print $4}')
      user_IP_1=$(netstat -anp | grep 'ESTABLISHED' | grep 'python' | grep 'tcp6' | grep ":${user_port} " | awk '{print $5}' | awk -F ":" '{print $1}' | sort -u)
      if [[ -z ${user_IP_1} ]]; then
        user_IP_total="0"
      else
        user_IP_total=$(echo -e "${user_IP_1}" | wc -l)
        if [[ ${format_1} == "IP_address" ]]; then
          get_IP_address
        else
          user_IP=$(echo -e "\n${user_IP_1}")
        fi
      fi
      user_list_all=${user_list_all}"Puerto: ${Green_font_prefix}"${user_port}"${Font_color_suffix}, No IPs: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}, Linked IP: ${Green_font_prefix}${user_IP}${Font_color_suffix}\n"
      user_IP=""
    done
    echo -e "Total de usuarios: ${Green_background_prefix} "${user_total}" ${Font_color_suffix} Total de IPs vinculadas: ${Green_background_prefix} "${IP_total}" ${Font_color_suffix}\n"
    echo -e "${user_list_all}"
    msg -bar
  }
  centos_View_user_connection_info() {
    format_1=$1
    user_info=$(python mujson_mgr.py -l)
    user_total=$(echo "${user_info}" | wc -l)
    [[ -z ${user_info} ]] && echo -e "${Error} No encontrado, por favor revise!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    IP_total=$(netstat -anp | grep 'ESTABLISHED' | grep 'python' | grep 'tcp' | grep '::ffff:' | awk '{print $5}' | awk -F ":" '{print $4}' | sort -u | wc -l)
    user_list_all=""
    for ((integer = 1; integer <= ${user_total}; integer++)); do
      user_port=$(echo "${user_info}" | sed -n "${integer}p" | awk '{print $4}')
      user_IP_1=$(netstat -anp | grep 'ESTABLISHED' | grep 'python' | grep 'tcp' | grep ":${user_port} " | grep '::ffff:' | awk '{print $5}' | awk -F ":" '{print $4}' | sort -u)
      if [[ -z ${user_IP_1} ]]; then
        user_IP_total="0"
      else
        user_IP_total=$(echo -e "${user_IP_1}" | wc -l)
        if [[ ${format_1} == "IP_address" ]]; then
          get_IP_address
        else
          user_IP=$(echo -e "\n${user_IP_1}")
        fi
      fi
      user_list_all=${user_list_all}"Puerto: ${Green_font_prefix}"${user_port}"${Font_color_suffix}, El numero total de IPs vinculadas: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix},Linked IP: ${Green_font_prefix}${user_IP}${Font_color_suffix}\n"
      user_IP=""
    done
    echo -e "El numero total de usuarios: ${Green_background_prefix} "${user_total}" ${Font_color_suffix} El numero total de IPs vinculadas: ${Green_background_prefix} "${IP_total}" ${Font_color_suffix} "
    echo -e "${user_list_all}"
  }
  View_user_connection_info() {
    clear
    SSR_installation_status
    msg -bar
    echo -e "      Seleccione el formato para mostrar
$(msg -bar)
 ${Green_font_prefix}1.${Font_color_suffix} Mostrar IP 

 ${Green_font_prefix}2.${Font_color_suffix} Mostrar IP + Resolver el nombre DNS"
    msg -bar
    read -p "(Predeterminado: 1):" ssr_connection_info
    msg -bar
    [[ -z "${ssr_connection_info}" ]] && ssr_connection_info="1"
    if [[ ${ssr_connection_info} == "1" ]]; then
      View_user_connection_info_1 ""
    elif [[ ${ssr_connection_info} == "2" ]]; then
      echo -e "${Tip} Detectar IP (ipip.net)puede llevar mas tiempo si hay muchas IPs"
      msg -bar
      View_user_connection_info_1 "IP_address"
    else
      echo -e "${Error} Ingrese el numero correcto(1-2)" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    fi
  }
  View_user_connection_info_1() {
    format=$1
    if [[ ${release} = "centos" ]]; then
      cat /etc/redhat-release | grep 7\..* | grep -i centos >/dev/null
      if [[ $? = 0 ]]; then
        debian_View_user_connection_info "$format"
      else
        centos_View_user_connection_info "$format"
      fi
    else
      debian_View_user_connection_info "$format"
    fi
  }
  get_IP_address() {
    #echo "user_IP_1=${user_IP_1}"
    if [[ ! -z ${user_IP_1} ]]; then
      #echo "user_IP_total=${user_IP_total}"
      for ((integer_1 = ${user_IP_total}; integer_1 >= 1; integer_1--)); do
        IP=$(echo "${user_IP_1}" | sed -n "$integer_1"p)
        #echo "IP=${IP}"
        IP_address=$(wget -qO- -t1 -T2 http://freeapi.ipip.net/${IP} | sed 's/\"//g;s/,//g;s/\[//g;s/\]//g')
        #echo "IP_address=${IP_address}"
        user_IP="${user_IP}\n${IP}(${IP_address})"
        #echo "user_IP=${user_IP}"
        sleep 1s
      done
    fi
  }
  #Modificar la configuraci�n del usuario
  Modify_port() {
    msg -bar
    List_port_user
    while true; do
      echo -e "Por favor ingrese el usuario (Puerto) que tiene que ser modificado"
      msg -bar
      echo -ne "\033[97m (Predeterminado: cancelar): \033[1;32m" && read ssr_port
      [[ -z "${ssr_port}" ]] && echo -e "Cancelado ...\n$(msg -bar)" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
      Modify_user=$(cat "${config_user_mudb_file}" | grep '"port": '"${ssr_port}"',')
      if [[ ! -z ${Modify_user} ]]; then
        break
      else
        echo -e "${Error} Puerto Introduzca el Puerto correcto!"
      fi
    done
  }
  Modify_Config() {
    clear
    SSR_installation_status
    msg -bar
    echo -e "       \e[1;93m ADMINISTRADOR DE CUENTAS SSR-SS \e[97m
$(msg -bar)
 ${Green_font_prefix}1.${Font_color_suffix}  Agregar y Configurar Usuario
 ${Green_font_prefix}2.${Font_color_suffix}  Eliminar la Configuracion del Usuario
\e[34m————————— Modificar la Configuracion del Usuario ————
 ${Green_font_prefix}3.${Font_color_suffix}  Modificar contrasena de Usuario
 ${Green_font_prefix}4.${Font_color_suffix}  Modificar el metodo de Cifrado
 ${Green_font_prefix}5.${Font_color_suffix}  Modificar el Protocolo
 ${Green_font_prefix}6.${Font_color_suffix}  Modificar Ofuscacion
 ${Green_font_prefix}7.${Font_color_suffix}  Modificar el Limite de Dispositivos
 ${Green_font_prefix}8.${Font_color_suffix}  Modificar el Limite de Velocidad de un solo Hilo
 ${Green_font_prefix}9.${Font_color_suffix}  Modificar limite de Velocidad Total del Usuario
 ${Green_font_prefix}10.${Font_color_suffix} Modificar el Trafico Total del Usuario
 ${Green_font_prefix}11.${Font_color_suffix} Modificar los Puertos Prohibidos Del usuario
 ${Green_font_prefix}12.${Font_color_suffix} Modificar la Configuracion Completa
\e[34m————————— Otras Configuraciones —————————
 ${Green_font_prefix}13.${Font_color_suffix} Modificar la IP o el nombre de dominio que\n se muestra en el perfil del usuario
$(msg -bar)
 ${Tip} El nombre de usuario y el puerto del usuario\n no se pueden modificar. Si necesita modificarlos, use\n el script para modificar manualmente la funcion !"
    msg -bar
    echo -ne "\033[97m (Predeterminado: cancelar): \033[1;32m" && read ssr_modify
    [[ -z "${ssr_modify}" ]] && echo -e "Cancelado ...\n$(msg -bar)" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    if [[ ${ssr_modify} == "1" ]]; then
      Add_port_user
    elif [[ ${ssr_modify} == "2" ]]; then
      Del_port_user
    elif [[ ${ssr_modify} == "3" ]]; then
      Modify_port
      Set_config_password
      Modify_config_password
    elif [[ ${ssr_modify} == "4" ]]; then
      Modify_port
      Set_config_method
      Modify_config_method
    elif [[ ${ssr_modify} == "5" ]]; then
      Modify_port
      Set_config_protocol
      Modify_config_protocol
    elif [[ ${ssr_modify} == "6" ]]; then
      Modify_port
      Set_config_obfs
      Modify_config_obfs
    elif [[ ${ssr_modify} == "7" ]]; then
      Modify_port
      Set_config_protocol_param
      Modify_config_protocol_param
    elif [[ ${ssr_modify} == "8" ]]; then
      Modify_port
      Set_config_speed_limit_per_con
      Modify_config_speed_limit_per_con
    elif [[ ${ssr_modify} == "9" ]]; then
      Modify_port
      Set_config_speed_limit_per_user
      Modify_config_speed_limit_per_user
    elif [[ ${ssr_modify} == "10" ]]; then
      Modify_port
      Set_config_transfer
      Modify_config_transfer
    elif [[ ${ssr_modify} == "11" ]]; then
      Modify_port
      Set_config_forbid
      Modify_config_forbid
    elif [[ ${ssr_modify} == "12" ]]; then
      Modify_port
      Set_config_all "Modify"
      Modify_config_all
    elif [[ ${ssr_modify} == "13" ]]; then
      Set_user_api_server_pub_addr "Modify"
      Modify_user_api_server_pub_addr
    else
      echo -e "${Error} Ingrese el numero correcto(1-13)" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    fi

  }
  List_port_user() {
    user_info=$(python mujson_mgr.py -l)
    user_total=$(echo "${user_info}" | wc -l)
    [[ -z ${user_info} ]] && echo -e "${Error} No encontre al usuario, por favor verifica otra vez!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    user_list_all=""
    for ((integer = 1; integer <= ${user_total}; integer++)); do
      user_port=$(echo "${user_info}" | sed -n "${integer}p" | awk '{print $4}')
      user_username=$(echo "${user_info}" | sed -n "${integer}p" | awk '{print $2}' | sed 's/\[//g;s/\]//g')
      Get_User_transfer "${user_port}"

      user_list_all=${user_list_all}"Nombre de usuario: ${Green_font_prefix} "${user_username}"${Font_color_suffix}\nPort: ${Green_font_prefix}"${user_port}"${Font_color_suffix}\nUso del trafico (Usado + Restante = Total):\n ${Green_font_prefix}${transfer_enable_Used_2}${Font_color_suffix} + ${Green_font_prefix}${transfer_enable_Used}${Font_color_suffix} = ${Green_font_prefix}${transfer_enable}${Font_color_suffix}\n--------------------------------------------\n "
    done
    msg -bar && echo -e "\e[93m     ===== DETALLES DE LOS USUARIOS ===== ${Green_background_prefix} "${user_total}" ${Font_color_suffix}" && msg -bar
    echo -e ${user_list_all}
  }
  Add_port_user() {
    clear
    lalal=$1
    if [[ "$lalal" == "install" ]]; then
      match_add=$(python mujson_mgr.py -a -u "${ssr_user}" -p "${ssr_port}" -k "${ssr_password}" -m "${ssr_method}" -O "${ssr_protocol}" -G "${ssr_protocol_param}" -o "${ssr_obfs}" -s "${ssr_speed_limit_per_con}" -S "${ssr_speed_limit_per_user}" -t "${ssr_transfer}" -f "${ssr_forbid}" | grep -w "add user info")
    else
      while true; do
        Set_config_all
        match_port=$(python mujson_mgr.py -l | grep -w "port ${ssr_port}$")
        [[ ! -z "${match_port}" ]] && echo -e "${Error} El puerto [${ssr_port}] Ya existe, no lo agregue de nuevo !" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
        match_username=$(python mujson_mgr.py -l | grep -w "Usuario \[${ssr_user}]")
        [[ ! -z "${match_username}" ]] && echo -e "${Error} Nombre de usuario [${ssr_user}] Ya existe, no lo agregues de nuevo !" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
        match_add=$(python mujson_mgr.py -a -u "${ssr_user}" -p "${ssr_port}" -k "${ssr_password}" -m "${ssr_method}" -O "${ssr_protocol}" -G "${ssr_protocol_param}" -o "${ssr_obfs}" -s "${ssr_speed_limit_per_con}" -S "${ssr_speed_limit_per_user}" -t "${ssr_transfer}" -f "${ssr_forbid}" | grep -w "add user info")
        if [[ -z "${match_add}" ]]; then
          echo -e "${Error} Usuario no se pudo agregar ${Green_font_prefix}[Nombre de usuario: ${ssr_user} , port: ${ssr_port}]${Font_color_suffix} "
          break
        else
          Add_iptables
          Save_iptables
          msg -bar
          echo -e "${Info} Usuario agregado exitosamente\n ${Green_font_prefix}[Nombre de usuario: ${ssr_user} , Puerto: ${ssr_port}]${Font_color_suffix} "
          echo
          read -p "Continuar para agregar otro Usuario?[y/n]:" addyn
          [[ -z ${addyn} ]] && addyn="y"
          if [[ ${addyn} == [Nn] ]]; then
            Get_User_info "${ssr_port}"
            View_User_info
            break
          else
            echo -e "${Info} Continuar agregando configuracion de usuario ..."
          fi
        fi
      done
    fi
  }
  Del_port_user() {

    List_port_user
    while true; do
      msg -bar
      echo -e "Por favor ingrese el puerto de usuario para ser eliminado"
      echo -ne "\033[97m (Predeterminado: cancelar): \033[1;32m" && read del_user_port
      msg -bar
      [[ -z "${del_user_port}" ]] && echo -e "Cancelado...\n$(msg -bar)" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
      del_user=$(cat "${config_user_mudb_file}" | grep '"port": '"${del_user_port}"',')
      if [[ ! -z ${del_user} ]]; then
        port=${del_user_port}
        match_del=$(python mujson_mgr.py -d -p "${del_user_port}" | grep -w "delete user ")
        if [[ -z "${match_del}" ]]; then
          echo -e "${Error} La eliminación del usuario falló ${Green_font_prefix}[Puerto: ${del_user_port}]${Font_color_suffix} "
        else
          Del_iptables
          Save_iptables
          echo -e "${Info} Usuario eliminado exitosamente ${Green_font_prefix}[Puerto: ${del_user_port}]${Font_color_suffix} "
        fi
        break
      else
        echo -e "${Error} Por favor ingrese el puerto correcto !"
      fi
    done
    msg -bar
  }
  Manually_Modify_Config() {
    clear
    msg -bar
    SSR_installation_status
    nano ${config_user_mudb_file}
    echo "Si reiniciar ShadowsocksR ahora?[Y/n]" && echo
    msg -bar
    read -p "(Predeterminado: y):" yn
    [[ -z ${yn} ]] && yn="y"
    if [[ ${yn} == [Yy] ]]; then
      Restart_SSR
    fi

  }
  Clear_transfer() {
    clear
    msg -bar
    SSR_installation_status
    echo -e "Que quieres realizar?
$(msg -bar)
 ${Green_font_prefix}1.${Font_color_suffix}  Borrar el trafico de un solo usuario
 ${Green_font_prefix}2.${Font_color_suffix}  Borrar todo el trafico de usuarios (irreparable)
 ${Green_font_prefix}3.${Font_color_suffix}  Todo el trafico de usuarios se borra en el inicio
 ${Green_font_prefix}4.${Font_color_suffix}  Deja de cronometrar todo el trafico de usuarios
 ${Green_font_prefix}5.${Font_color_suffix}  Modificar la sincronizacion de todo el trafico de usuarios"
    msg -bar
    read -p "(Predeterminado:Cancelar):" ssr_modify
    [[ -z "${ssr_modify}" ]] && echo "Cancelado ..." && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    if [[ ${ssr_modify} == "1" ]]; then
      Clear_transfer_one
    elif [[ ${ssr_modify} == "2" ]]; then
      msg -bar
      echo "Esta seguro de que desea borrar todo el trafico de usuario[y/n]" && echo
      msg -bar
      read -p "(Predeterminado: n):" yn
      [[ -z ${yn} ]] && yn="n"
      if [[ ${yn} == [Yy] ]]; then
        Clear_transfer_all
      else
        echo "Cancelar ..."
      fi
    elif [[ ${ssr_modify} == "3" ]]; then
      check_crontab
      Set_crontab
      Clear_transfer_all_cron_start
    elif [[ ${ssr_modify} == "4" ]]; then
      check_crontab
      Clear_transfer_all_cron_stop
    elif [[ ${ssr_modify} == "5" ]]; then
      check_crontab
      Clear_transfer_all_cron_modify
    else
      echo -e "${Error} Por favor numero de (1-5)" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    fi

  }
  Clear_transfer_one() {
    List_port_user
    while true; do
      msg -bar
      echo -e "Por favor ingrese el puerto de usuario para borrar el tráfico usado"
      echo -ne "\033[97m (Predeterminado: cancelar): \033[1;32m" && read Clear_transfer_user_port
      [[ -z "${Clear_transfer_user_port}" ]] && echo -e "Cancelado...\n$(msg -bar)" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
      Clear_transfer_user=$(cat "${config_user_mudb_file}" | grep '"port": '"${Clear_transfer_user_port}"',')
      if [[ ! -z ${Clear_transfer_user} ]]; then
        match_clear=$(python mujson_mgr.py -c -p "${Clear_transfer_user_port}" | grep -w "clear user ")
        if [[ -z "${match_clear}" ]]; then
          echo -e "${Error} El usuario no ha podido utilizar la compensación de tráfico ${Green_font_prefix}[Puerto: ${Clear_transfer_user_port}]${Font_color_suffix} "
        else
          echo -e "${Info} El usuario ha eliminado con éxito el tráfico utilizando cero. ${Green_font_prefix}[Puerto: ${Clear_transfer_user_port}]${Font_color_suffix} "
        fi
        break
      else
        echo -e "${Error} Por favor ingrese el puerto correcto !"
      fi
    done
  }
  Clear_transfer_all() {
    clear
    cd "${ssr_folder}"
    user_info=$(python mujson_mgr.py -l)
    user_total=$(echo "${user_info}" | wc -l)
    [[ -z ${user_info} ]] && echo -e "${Error} No encontro, por favor compruebe!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    for ((integer = 1; integer <= ${user_total}; integer++)); do
      user_port=$(echo "${user_info}" | sed -n "${integer}p" | awk '{print $4}')
      match_clear=$(python mujson_mgr.py -c -p "${user_port}" | grep -w "clear user ")
      if [[ -z "${match_clear}" ]]; then
        echo -e "${Error} El usuario ha utilizado el trafico borrado fallido ${Green_font_prefix}[Port: ${user_port}]${Font_color_suffix} "
      else
        echo -e "${Info} El usuario ha utilizado el trafico para borrar con exito ${Green_font_prefix}[Port: ${user_port}]${Font_color_suffix} "
      fi
    done
    echo -e "${Info} Se borra todo el trafico de usuarios!"
  }
  Clear_transfer_all_cron_start() {
    crontab -l >"$file/crontab.bak"
    sed -i "/ssrmu.sh/d" "$file/crontab.bak"
    echo -e "\n${Crontab_time} /bin/bash $file/ssrmu.sh clearall" >>"$file/crontab.bak"
    crontab "$file/crontab.bak"
    rm -r "$file/crontab.bak"
    cron_config=$(crontab -l | grep "ssrmu.sh")
    if [[ -z ${cron_config} ]]; then
      echo -e "${Error} Temporizacion de todo el trafico de usuarios borrado. !" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    else
      echo -e "${Info} Programacion de todos los tiempos de inicio claro exitosos!"
    fi
  }
  Clear_transfer_all_cron_stop() {
    crontab -l >"$file/crontab.bak"
    sed -i "/ssrmu.sh/d" "$file/crontab.bak"
    crontab "$file/crontab.bak"
    rm -r "$file/crontab.bak"
    cron_config=$(crontab -l | grep "ssrmu.sh")
    if [[ ! -z ${cron_config} ]]; then
      echo -e "${Error} Temporizado Todo el trafico de usuarios se ha borrado Parado fallido!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    else
      echo -e "${Info} Timing All Clear Stop Stop Successful!!"
    fi
  }
  Clear_transfer_all_cron_modify() {
    Set_crontab
    Clear_transfer_all_cron_stop
    Clear_transfer_all_cron_start
  }
  Set_crontab() {
    clear

    echo -e "Por favor ingrese el intervalo de tiempo de flujo
 === Formato ===
 * * * * * Mes * * * * *
 ${Green_font_prefix} 0 2 1 * * ${Font_color_suffix} Representante 1er, 2:00, claro, trafico usado.
$(msg -bar)
 ${Green_font_prefix} 0 2 15 * * ${Font_color_suffix} Representativo El 1  2} representa el 15  2:00 minutos Punto de flujo usado despejado 0 minutos Borrar flujo usado�
$(msg -bar)
 ${Green_font_prefix} 0 2 */7 * * ${Font_color_suffix} Representante 7 dias 2: 0 minutos despeja el trafico usado.
$(msg -bar)
 ${Green_font_prefix} 0 2 * * 0 ${Font_color_suffix} Representa todos los domingos (7) para despejar el trafico utilizado.
$(msg -bar)
 ${Green_font_prefix} 0 2 * * 3 ${Font_color_suffix} Representante (3) Flujo de trafico usado despejado"
    msg -bar
    read -p "(Default: 0 2 1 * * 1 de cada mes 2:00):" Crontab_time
    [[ -z "${Crontab_time}" ]] && Crontab_time="0 2 1 * *"
  }
  Start_SSR() {
    clear
    SSR_installation_status
    check_pid
    [[ ! -z ${PID} ]] && echo -e "${Error} ShadowsocksR se esta ejecutando!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    /etc/init.d/ssrmu start

  }
  Stop_SSR() {
    clear
    SSR_installation_status
    check_pid
    [[ -z ${PID} ]] && echo -e "${Error} ShadowsocksR no esta funcionando!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    /etc/init.d/ssrmu stop

  }
  Restart_SSR() {
    clear
    SSR_installation_status
    check_pid
    [[ ! -z ${PID} ]] && /etc/init.d/ssrmu stop
    /etc/init.d/ssrmu start

  }
  View_Log() {
    SSR_installation_status
    [[ ! -e ${ssr_log_file} ]] && echo -e "${Error} El registro de ShadowsocksR no existe!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    echo && echo -e "${Tip} Presione ${Red_font_prefix}Ctrl+C ${Font_color_suffix} Registro de registro de terminacion" && echo
    tail -f ${ssr_log_file}

  }
  #Afilado
  Configure_Server_Speeder() {
    clear
    msg -bar
    echo && echo -e "Que vas a hacer
${BARRA1}
 ${Green_font_prefix}1.${Font_color_suffix} Velocidad aguda
$(msg -bar)
 ${Green_font_prefix}2.${Font_color_suffix} Velocidad aguda
————————
 ${Green_font_prefix}3.${Font_color_suffix} Velocidad aguda
$(msg -bar)
 ${Green_font_prefix}4.${Font_color_suffix} Velocidad aguda
$(msg -bar)
 ${Green_font_prefix}5.${Font_color_suffix} Reinicie la velocidad aguda
$(msg -bar)
 ${Green_font_prefix}6.${Font_color_suffix} Estado agudo
 $(msg -bar)
 Nota: Sharp y LotServer no se pueden instalar / iniciar al mismo tiempo"
    msg -bar
    echo -ne "\033[97m (Predeterminado: cancelar): \033[1;32m" && read server_speeder_num
    [[ -z "${server_speeder_num}" ]] && echo "Cancelado ..." && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    if [[ ${server_speeder_num} == "1" ]]; then
      Install_ServerSpeeder
    elif [[ ${server_speeder_num} == "2" ]]; then
      Server_Speeder_installation_status
      Uninstall_ServerSpeeder
    elif [[ ${server_speeder_num} == "3" ]]; then
      Server_Speeder_installation_status
      ${Server_Speeder_file} start
      ${Server_Speeder_file} status
    elif [[ ${server_speeder_num} == "4" ]]; then
      Server_Speeder_installation_status
      ${Server_Speeder_file} stop
    elif [[ ${server_speeder_num} == "5" ]]; then
      Server_Speeder_installation_status
      ${Server_Speeder_file} restart
      ${Server_Speeder_file} status
    elif [[ ${server_speeder_num} == "6" ]]; then
      Server_Speeder_installation_status
      ${Server_Speeder_file} status
    else
      echo -e "${Error} Por favor numero(1-6)" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    fi
  }
  Install_ServerSpeeder() {
    [[ -e ${Server_Speeder_file} ]] && echo -e "${Error} Server Speeder esta instalado!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    #Prestamo de la version feliz de 91yun.rog
    wget --no-check-certificate -qO /tmp/serverspeeder.sh https://raw.githubusercontent.com/91yun/serverspeeder/master/serverspeeder.sh
    [[ ! -e "/tmp/serverspeeder.sh" ]] && echo -e "${Error} Prestamo de la version feliz de 91yun.rog!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    bash /tmp/serverspeeder.sh
    sleep 2s
    PID=$(ps -ef | grep -v grep | grep "serverspeeder" | awk '{print $2}')
    if [[ ! -z ${PID} ]]; then
      rm -rf /tmp/serverspeeder.sh
      rm -rf /tmp/91yunserverspeeder
      rm -rf /tmp/91yunserverspeeder.tar.gz
      echo -e "${Info} La instalacion del servidor Speeder esta completa!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    else
      echo -e "${Error} Fallo la instalacion de Server Speeder!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    fi
  }
  Uninstall_ServerSpeeder() {
    clear
    msg -bar
    echo "yes para desinstalar Speed ??Speed ??(Server Speeder)[y/N]" && echo
    msg -bar
    read -p "(Predeterminado: n):" unyn
    [[ -z ${unyn} ]] && echo && echo "Cancelado ..." && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    if [[ ${unyn} == [Yy] ]]; then
      chattr -i /serverspeeder/etc/apx*
      /serverspeeder/bin/serverSpeeder.sh uninstall -f
      echo && echo "Server Speeder Desinstalacion completa!" && echo
    fi
  }
  # LotServer
  Configure_LotServer() {
    clear
    msg -bar
    echo && echo -e "Que vas a hacer?
$(msg -bar)
 ${Green_font_prefix}1.${Font_color_suffix} Instalar LotServer
$(msg -bar)
 ${Green_font_prefix}2.${Font_color_suffix} Desinstalar LotServer
————————
 ${Green_font_prefix}3.${Font_color_suffix} Iniciar LotServer
$(msg -bar)
 ${Green_font_prefix}4.${Font_color_suffix} Detener LotServer
$(msg -bar)
 ${Green_font_prefix}5.${Font_color_suffix} Reiniciar LotServer
$(msg -bar)
 ${Green_font_prefix}6.${Font_color_suffix} Ver el estado de LotServer
${BARRA1}
 
 Nota: Sharp y LotServer no se pueden instalar / iniciar al mismo tiempo"
    msg -bar

    echo -ne "\033[97m (Predeterminado: cancelar): \033[1;32m" && read lotserver_num
    [[ -z "${lotserver_num}" ]] && echo "Cancelado ..." && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    if [[ ${lotserver_num} == "1" ]]; then
      Install_LotServer
    elif [[ ${lotserver_num} == "2" ]]; then
      LotServer_installation_status
      Uninstall_LotServer
    elif [[ ${lotserver_num} == "3" ]]; then
      LotServer_installation_status
      ${LotServer_file} start
      ${LotServer_file} status
    elif [[ ${lotserver_num} == "4" ]]; then
      LotServer_installation_status
      ${LotServer_file} stop
    elif [[ ${lotserver_num} == "5" ]]; then
      LotServer_installation_status
      ${LotServer_file} restart
      ${LotServer_file} status
    elif [[ ${lotserver_num} == "6" ]]; then
      LotServer_installation_status
      ${LotServer_file} status
    else
      echo -e "${Error} Por favor numero(1-6)" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    fi
  }
  Install_LotServer() {
    [[ -e ${LotServer_file} ]] && echo -e "${Error} LotServer esta instalado!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    #Github: https://github.com/0oVicero0/serverSpeeder_Install
    wget --no-check-certificate -qO /tmp/appex.sh "https://raw.githubusercontent.com/0oVicero0/serverSpeeder_Install/master/appex.sh"
    [[ ! -e "/tmp/appex.sh" ]] && echo -e "${Error} Fallo la descarga del script de instalacion de LotServer!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    bash /tmp/appex.sh 'install'
    sleep 2s
    PID=$(ps -ef | grep -v grep | grep "appex" | awk '{print $2}')
    if [[ ! -z ${PID} ]]; then
      echo -e "${Info} La instalacion de LotServer esta completa!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    else
      echo -e "${Error} Fallo la instalacion de LotServer!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    fi
  }
  Uninstall_LotServer() {
    clear && clear
    msg -bar
    echo "Desinstalar Para desinstalar LotServer[y/N]" && echo
    msg -bar
    read -p "(Predeterminado: n):" unyn
    msg -bar
    [[ -z ${unyn} ]] && echo && echo "Cancelado ..." && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    if [[ ${unyn} == [Yy] ]]; then
      wget --no-check-certificate -qO /tmp/appex.sh "https://raw.githubusercontent.com/0oVicero0/serverSpeeder_Install/master/appex.sh" && bash /tmp/appex.sh 'uninstall'
      echo && echo "La desinstalacion de LotServer esta completa!" && echo
    fi
  }
  # BBR
  Configure_BBR() {
    clear && clear
    msg -bar
    echo -e "  Que vas a hacer?
$(msg -bar)	
 ${Green_font_prefix}1.${Font_color_suffix} Instalar BBR
————————
${Green_font_prefix}2.${Font_color_suffix} Iniciar BBR
${Green_font_prefix}3.${Font_color_suffix} Dejar de BBR
${Green_font_prefix}4.${Font_color_suffix} Ver el estado de BBR"
    msg -bar
    echo -e "${Green_font_prefix} [Por favor, preste atencion antes de la instalacion] ${Font_color_suffix}
$(msg -bar)
1. Abra BBR, reemplace, hay un error de reemplazo (despues de reiniciar)
2. Este script solo es compatible con los nucleos de reemplazo de Debian / Ubuntu. OpenVZ y Docker no admiten el reemplazo de los nucleos.
3. Debian reemplaza el proceso del kernel [Desea finalizar el kernel de desinstalacion], seleccione ${Green_font_prefix} NO ${Font_color_suffix}"
    echo -ne "\033[97m (Predeterminado: cancelar): \033[1;32m" && read bbr_num
    msg -bar
    [[ -z "${bbr_num}" ]] && echo -e "Cancelado...\n$(msg -bar)" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    if [[ ${bbr_num} == "1" ]]; then
      Install_BBR
    elif [[ ${bbr_num} == "2" ]]; then
      Start_BBR
    elif [[ ${bbr_num} == "3" ]]; then
      Stop_BBR
    elif [[ ${bbr_num} == "4" ]]; then
      Status_BBR
    else
      echo -e "${Error} Por favor numero(1-4)" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    fi
  }
  Install_BBR() {
    [[ ${release} = "centos" ]] && echo -e "${Error} Este script de instalacion del sistema CentOS. BBR !" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    BBR_installation_status
    bash "${BBR_file}"
  }
  Start_BBR() {
    BBR_installation_status
    bash "${BBR_file}" start
  }
  Stop_BBR() {
    BBR_installation_status
    bash "${BBR_file}" stop
  }
  Status_BBR() {
    BBR_installation_status
    bash "${BBR_file}" status
  }
  BackUP_ssrr() {
    clear && clear
    msg -bar
    msg -ama "HERRAMIENTA DE BACKUP SS-SSRR -BETA"
    msg -bar
    msg -azu "CREANDO BACKUP" "RESTAURAR BACKUP"
    msg -bar
    rm -rf /root/mudb.json >/dev/null 2>&1
    cp /usr/local/shadowsocksr/mudb.json /root/mudb.json >/dev/null 2>&1
    msg -azu "Procedimiento Hecho con Exito, Guardado en:"
    echo -e "\033[1;31mBACKUP > [\033[1;32m/root/mudb.json\033[1;31m]"
    msg -bar
  }
  RestaurarBackUp_ssrr() {
    clear && clear
    msg -bar
    msg -ama "HERRAMIENTA DE RESTAURACION SS-SSRR -BETA"
    msg -bar
    msg -azu "Recuerde tener minimo una cuenta ya creada"
    msg -azu "Copie el archivo mudb.json en la carpeta /root"
    read -p "     ►► Presione enter para continuar ◄◄"
    msg -bar
    msg -azu "Procedimiento Hecho con Exito"
    read -p "  ►► Presione enter para Reiniciar Panel SSRR ◄◄"
    msg -bar
    mv /root/mudb.json /usr/local/shadowsocksr/mudb.json
    Restart_SSR
    msg -bar
  }

  # Otros
  Other_functions() {
    clear && clear
    msg -bar
    echo -e "\e[1;93m  Que vas a realizar?
$(msg -bar)
  ${Green_font_prefix}1.${Font_color_suffix} Configurar BBR
  ${Green_font_prefix}2.${Font_color_suffix} Velocidad de configuracion (ServerSpeeder)
  ${Green_font_prefix}3.${Font_color_suffix} Configurar LotServer (Rising Parent)
  ${Tip} Sharp / LotServer / BBR no es compatible con OpenVZ!
  ${Tip} Speed y LotServer no pueden coexistir!
————————————
  ${Green_font_prefix}4.${Font_color_suffix} Llave de bloqueo BT/PT/SPAM (iptables)
  ${Green_font_prefix}5.${Font_color_suffix} Llave de desbloqueo BT/PT/SPAM (iptables)
————————————
  ${Green_font_prefix}6.${Font_color_suffix} Cambiar modo de salida de registro ShadowsocksR
  —— Modo bajo o verboso..
  ${Green_font_prefix}7.${Font_color_suffix} Supervisar el estado de ejecucion del servidor ShadowsocksR
  —— NOTA: Supervisa que SSR este Activo
———————————— 
 ${Green_font_prefix}8.${Font_color_suffix} Backup SSRR
 ${Green_font_prefix}9.${Font_color_suffix} Restaurar Backup"
    msg -bar
    echo -ne "\033[97m (Predeterminado: cancelar): \033[1;32m" && read other_num
    [[ -z "${other_num}" ]] && echo -e "Cancelado...\n$(msg -bar)" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    if [[ ${other_num} == "1" ]]; then
      Configure_BBR
    elif [[ ${other_num} == "2" ]]; then
      Configure_Server_Speeder
    elif [[ ${other_num} == "3" ]]; then
      Configure_LotServer
    elif [[ ${other_num} == "4" ]]; then
      BanBTPTSPAM
    elif [[ ${other_num} == "5" ]]; then
      UnBanBTPTSPAM
    elif [[ ${other_num} == "6" ]]; then
      Set_config_connect_verbose_info
    elif [[ ${other_num} == "7" ]]; then
      Set_crontab_monitor_ssr
    elif [[ ${other_num} == "8" ]]; then
      BackUP_ssrr
    elif [[ ${other_num} == "9" ]]; then
      RestaurarBackUp_ssrr
    else
      echo -e "${Error} Por favor numero [1-9]" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    fi

  }
  #Prohibido�BT PT SPAM
  BanBTPTSPAM() {
    wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/ban_iptables.sh && chmod +x ban_iptables.sh && bash ban_iptables.sh banall
    rm -rf ban_iptables.sh
  }
  #Desbloquear BT PT SPAM
  UnBanBTPTSPAM() {
    wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/ban_iptables.sh && chmod +x ban_iptables.sh && bash ban_iptables.sh unbanall
    rm -rf ban_iptables.sh
  }
  Set_config_connect_verbose_info() {
    clear && clear
    msg -bar
    SSR_installation_status
    [[ ! -e ${jq_file} ]] && echo -e "${Error} JQ parser No, por favor, compruebe!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    connect_verbose_info=$(${jq_file} '.connect_verbose_info' ${config_user_file})
    if [[ ${connect_verbose_info} = "0" ]]; then
      echo && echo -e "Modo de registro actual: ${Green_font_prefix}Registro de errores en modo simple${Font_color_suffix}"
      msg -bar
      echo -e "yes para cambiar a ${Green_font_prefix}Modo detallado (registro de conexi�n + registro de errores)${Font_color_suffix}？[y/N]"
      msg -bar
      read -p "(Predeterminado: n):" connect_verbose_info_ny
      [[ -z "${connect_verbose_info_ny}" ]] && connect_verbose_info_ny="n"
      if [[ ${connect_verbose_info_ny} == [Yy] ]]; then
        ssr_connect_verbose_info="1"
        Modify_config_connect_verbose_info
        Restart_SSR
      else
        echo && echo "	Cancelado ..." && echo
      fi
    else
      echo && echo -e "Modo de registro actual: ${Green_font_prefix}Modo detallado (conexion de conexion + registro de errores)${Font_color_suffix}"
      msg -bar
      echo -e "yes para cambiar a ${Green_font_prefix}Modo simple ${Font_color_suffix}?[y/N]"
      read -p "(Predeterminado: n):" connect_verbose_info_ny
      [[ -z "${connect_verbose_info_ny}" ]] && connect_verbose_info_ny="n"
      if [[ ${connect_verbose_info_ny} == [Yy] ]]; then
        ssr_connect_verbose_info="0"
        Modify_config_connect_verbose_info
        Restart_SSR
      else
        echo && echo "	Cancelado ..." && echo
      fi
    fi
  }
  Set_crontab_monitor_ssr() {
    clear && clear
    msg -bar
    SSR_installation_status
    crontab_monitor_ssr_status=$(crontab -l | grep "ssrmu.sh monitor")
    if [[ -z "${crontab_monitor_ssr_status}" ]]; then
      echo && echo -e "Modo de monitoreo actual: ${Green_font_prefix}No monitoreado${Font_color_suffix}"
      msg -bar
      echo -e "Ok para abrir ${Green_font_prefix}Servidor ShadowsocksR ejecutando monitoreo de estado${Font_color_suffix} Funcion? (Cuando el proceso R lado SSR R)[Y/n]"
      msg -bar
      read -p "(Predeterminado: y):" crontab_monitor_ssr_status_ny
      [[ -z "${crontab_monitor_ssr_status_ny}" ]] && crontab_monitor_ssr_status_ny="y"
      if [[ ${crontab_monitor_ssr_status_ny} == [Yy] ]]; then
        crontab_monitor_ssr_cron_start
      else
        echo && echo "	Cancelado ..." && echo
      fi
    else
      echo && echo -e "Modo de monitoreo actual: ${Green_font_prefix}Abierto${Font_color_suffix}"
      msg -bar
      echo -e "Ok para apagar ${Green_font_prefix}Servidor ShadowsocksR ejecutando monitoreo de estado${Font_color_suffix} Funcion? (procesar servidor SSR)[y/N]"
      msg -bar
      read -p "(Predeterminado: n):" crontab_monitor_ssr_status_ny
      [[ -z "${crontab_monitor_ssr_status_ny}" ]] && crontab_monitor_ssr_status_ny="n"
      if [[ ${crontab_monitor_ssr_status_ny} == [Yy] ]]; then
        crontab_monitor_ssr_cron_stop
      else
        echo && echo "	Cancelado ..." && echo
      fi
    fi
  }
  crontab_monitor_ssr() {
    SSR_installation_status
    check_pid
    if [[ -z ${PID} ]]; then
      echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Detectado que el servidor ShadowsocksR no esta iniciado, inicie..." | tee -a ${ssr_log_file}
      /etc/init.d/ssrmu start
      sleep 1s
      check_pid
      if [[ -z ${PID} ]]; then
        echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Fallo el inicio del servidor ShadowsocksR..." | tee -a ${ssr_log_file} && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
      else
        echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Inicio de inicio del servidor ShadowsocksR..." | tee -a ${ssr_log_file} && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
      fi
    else
      echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] El proceso del servidor ShadowsocksR se ejecuta normalmente..." exit 0
    fi
  }
  crontab_monitor_ssr_cron_start() {
    crontab -l >"$file/crontab.bak"
    sed -i "/ssrmu.sh monitor/d" "$file/crontab.bak"
    echo -e "\n* * * * * /bin/bash $file/ssrmu.sh monitor" >>"$file/crontab.bak"
    crontab "$file/crontab.bak"
    rm -r "$file/crontab.bak"
    cron_config=$(crontab -l | grep "ssrmu.sh monitor")
    if [[ -z ${cron_config} ]]; then
      echo -e "${Error} Fallo el arranque del servidor ShadowsocksR!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    else
      echo -e "${Info} El servidor ShadowsocksR esta ejecutando la monitorizacion del estado con exito!"
    fi
  }
  crontab_monitor_ssr_cron_stop() {
    crontab -l >"$file/crontab.bak"
    sed -i "/ssrmu.sh monitor/d" "$file/crontab.bak"
    crontab "$file/crontab.bak"
    rm -r "$file/crontab.bak"
    cron_config=$(crontab -l | grep "ssrmu.sh monitor")
    if [[ ! -z ${cron_config} ]]; then
      echo -e "${Error} Fallo la detencion del servidor ShadowsocksR!" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
    else
      echo -e "${Info} La supervision del estado de ejecucion del servidor de ShadowsocksR se detiene correctamente!"
    fi
  }
  Update_Shell() {
    clear && clear
    msg -bar
    echo -e "La version actual es [ ${sh_ver} ], Comienza a detectar la ultima version ..."
    sh_new_ver=$(wget --no-check-certificate -qO- "https://raw.githubusercontent.com/hybtoy/ssrrmu/master/ssrrmu.sh" | grep 'sh_ver="' | awk -F "=" '{print $NF}' | sed 's/\"//g' | head -1) && sh_new_type="github"
    [[ -z ${sh_new_ver} ]] && sh_new_ver=$(wget --no-check-certificate -qO- "https://raw.githubusercontent.com/hybtoy/ssrrmu/master/ssrrmu.sh" | grep 'sh_ver="' | awk -F "=" '{print $NF}' | sed 's/\"//g' | head -1) && sh_new_type="github"
    [[ -z ${sh_new_ver} ]] && echo -e "${Error} Ultima version de deteccion !" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
    if [[ ${sh_new_ver} != ${sh_ver} ]]; then
      echo -e "Descubrir nueva version[ ${sh_new_ver} ], Esta actualizado?[Y/n]"
      msg -bar
      read -p "(Predeterminado: y):" yn
      [[ -z "${yn}" ]] && yn="y"
      if [[ ${yn} == [Yy] ]]; then
        cd "${file}"
        if [[ $sh_new_type == "github" ]]; then
          wget -N --no-check-certificate https://raw.githubusercontent.com/hybtoy/ssrrmu/master/ssrrmu.sh && chmod +x ssrrmu.sh
        fi
        echo -e "El script ha sido actualizado a la ultima version.[ ${sh_new_ver} ] !"
      else
        echo && echo "	Cancelado ..." && echo
      fi
    else
      echo -e "Actualmente es la ultima version.[ ${sh_new_ver} ] !"
    fi
    exit 0

  }
  # Mostrar el estado del menu
  menu_status() {

    if [[ -e ${ssr_folder} ]]; then
      check_pid
      if [[ ! -z "${PID}" ]]; then
        echo -e "       Estado actual: ${Green_font_prefix}Instalado${Font_color_suffix} y ${Green_font_prefix}Iniciado${Font_color_suffix}"
        msg -bar
      else
        echo -e "       Estado actual: ${Green_font_prefix}Instalado${Font_color_suffix} pero ${Red_font_prefix}no comenzo${Font_color_suffix}"
        msg -bar
      fi
      cd "${ssr_folder}"
    else
      echo -e "        Estado actual: ${Red_font_prefix}No Instalado${Font_color_suffix}"
      msg -bar
    fi
  }
  check_sys
  [[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && [[ ${release} != "centos" ]] && echo -e "${Error} el script no es compatible con el sistema actual ${release} !" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && controlador_ssr
  action=$1
  if [[ "${action}" == "clearall" ]]; then
    Clear_transfer_all
  elif [[ "${action}" == "monitor" ]]; then
    crontab_monitor_ssr
  else

    msg -tit
    msg -bar
    echo -e "\e[1;93m      CONTROLADOR DE SHADOWSOCKR  ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}"
    msg -bar

    echo -ne "\e[1;93m  [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;97mINSTALAR" && echo -ne "       \e[1;93m[\e[1;32m2\e[1;93m]\033[1;31m > \e[1;97mACTUALIZAR \n"
    echo -ne "\e[1;93m  [\e[1;32m3\e[1;93m]\033[1;31m > \e[1;97mDESINSTALAR  " && echo -ne "  \e[1;93m[\e[1;32m4\e[1;93m]\033[1;31m > \e[1;97mINSTALAR LIBSODIUM\n"
    echo -ne "\e[1;93m  [\e[1;32m5\e[1;93m]\033[1;31m > \e[1;97mINICIAR " && echo -ne "       \e[1;93m[\e[1;32m6\e[1;93m]\033[1;31m > \e[1;97mDETENER\n"
    echo -ne "\e[1;93m  [\e[1;32m7\e[1;93m]\033[1;31m > \e[1;97mREINICIAR " && echo -ne "     \e[1;93m[\e[1;32m8\e[1;93m]\033[1;31m > \e[1;97mVER NANO JSOn\n"
    echo -e "\033[38;5;239m══════════════\e[100m\e[97m  ADMINISTRAR CUENTAS  \e[0m\e[38;5;239m══════════════"
    echo -e "\e[1;93m  [\e[1;32m9\e[1;93m]\033[1;31m > \e[1;97mAGREGAR | MODIFICAR | ELIMINAR [\e[1;93m CUENTAS \e[1;97m]  "
    echo -e "\e[1;93m [\e[1;32m10\e[1;93m]\033[1;31m > \e[1;97mMOSTRAR CONEXIONES"
    echo -e "\e[1;93m [\e[1;32m11\e[1;93m]\033[1;31m > \e[1;97mMODIFICAR CUENTAS"
    echo -e "\e[1;93m [\e[1;32m12\e[1;93m]\033[1;31m > \e[1;97mBORRAR EL TRAFICO USADO  "
    echo -e "\e[1;93m [\e[1;32m13\e[1;93m]\033[1;31m > \e[1;97mREGISTRO DE CONEXIONES"

    echo -e "\e[1;93m [\e[1;32m14\e[1;93m]\033[1;31m > \e[1;97mOTRAS FUNCIONES / BACKUP'S"
    msg -bar
    echo -ne " \e[1;93m [\e[1;32m0\e[1;93m]\033[1;31m > " && echo -e "\e[97m\033[1;41m VOLVER \033[0;37m"
    msg -bar
    echo -ne "\033[1;97m   └⊳ Seleccione una opcion [0-14]: \033[1;32m" && read num
    msg -bar
    case "$num" in
    1)
      Install_SSR
      read -t 240 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      controlador_ssr
      ;;
    2)
      Update_SSR
      read -t 240 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      controlador_ssr
      ;;
    3)
      Uninstall_SSR
      read -t 240 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      controlador_ssr
      ;;
    4)
      Install_Libsodium
      read -t 240 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      controlador_ssr
      ;;
    5)
      Start_SSR
      read -t 240 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      controlador_ssr
      ;;
    6)
      Stop_SSR

      read -t 240 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      controlador_ssr
      ;;
    7)
      Restart_SSR

      read -t 240 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      controlador_ssr
      ;;
    8)
      Manually_Modify_Config

      read -t 240 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      controlador_ssr
      ;;
    9)
      Modify_Config

      read -t 240 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      controlador_ssr
      ;;
    10)

      View_user_connection_info
      read -t 240 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      controlador_ssr
      ;;
    11)
      View_User
      read -t 240 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      controlador_ssr
      ;;
    12)
      Clear_transfer
      read -t 240 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      controlador_ssr
      ;;
    13)
      View_Log

      read -t 240 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      controlador_ssr
      ;;
    14)
      Other_functions
      read -t 240 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      controlador_ssr
      ;;
    15)

      read -t 240 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      controlador_ssr
      ;;
    *)
      menu
      ;;
    esac
  fi
  exit 0
}

#--- CONTROLADOR SSH/SSL/DROPBEAR/OPENVPN
controlador_ssh() {
  myip=$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0' | head -n1)
  myint=$(ifconfig | grep -B1 "inet addr:$myip" | head -n1 | awk '{print $1}')
  declare -A TIMEUS
  SCPdir="/etc/SCRIPT-LATAM"
  SCPdir2="${SCPdir}/herramientas"
  SCPusr="${SCPdir}/controlador"
  USRdatabase="${SCPdir}/cuentassh"
  VERY="$(ps aux | grep "/etc/SCRIPT-LATAM/menu.sh verificar" | grep -v grep)"
  VERY2="$(ps aux | grep "/etc/SCRIPT-LATAM/menu.sh desbloqueo" | grep -v grep)"
  # Open VPN
  newclient() {
    #Nome #Senha
    usermod -p $(openssl passwd -1 $2) $1
    while [[ ${newfile} != @(s|S|y|Y|n|N) ]]; do
      msg -bar
      read -p "Crear Archivo OpenVPN? [S/N]: " -e -i S newfile
      tput cuu1 && tput dl1
    done
    if [[ ${newfile} = @(s|S) ]]; then
      # Generates the custom client.ovpn
      rm -rf /etc/openvpn/easy-rsa/pki/reqs/$1.req
      rm -rf /etc/openvpn/easy-rsa/pki/issued/$1.crt
      rm -rf /etc/openvpn/easy-rsa/pki/private/$1.key
      cd /etc/openvpn/easy-rsa/
      ./easyrsa build-client-full $1 nopass >/dev/null 2>&1
      cd

      cp /etc/openvpn/client-common.txt ~/$1.ovpn
      echo "<ca>" >>~/$1.ovpn
      cat /etc/openvpn/easy-rsa/pki/ca.crt >>~/$1.ovpn
      echo "</ca>" >>~/$1.ovpn
      echo "<cert>" >>~/$1.ovpn
      cat /etc/openvpn/easy-rsa/pki/issued/$1.crt >>~/$1.ovpn
      echo "</cert>" >>~/$1.ovpn
      echo "<key>" >>~/$1.ovpn
      cat /etc/openvpn/easy-rsa/pki/private/$1.key >>~/$1.ovpn
      echo "</key>" >>~/$1.ovpn
      echo "<tls-auth>" >>~/$1.ovpn
      cat /etc/openvpn/ta.key >>~/$1.ovpn
      echo "</tls-auth>" >>~/$1.ovpn

      while [[ ${ovpnauth} != @(s|S|y|Y|n|N) ]]; do
        read -p "Colocar autenticacion de usuario en el archivo? [S/N]: " -e -i S ovpnauth
        tput cuu1 && tput dl1
      done
      [[ ${ovpnauth} = @(s|S) ]] && sed -i "s;auth-user-pass;<auth-user-pass>\n$1\n$2\n</auth-user-pass>;g" ~/$1.ovpn
      cd $HOME
      zip ./$1.zip ./$1.ovpn >/dev/null 2>&1
      rm ./$1.ovpn >/dev/null 2>&1

      echo -e "\033[1;31mArchivo creado: ($HOME/$1.zip)"

    fi
  }

  unlockall2() {
    for user in $(cat /etc/passwd | awk -F : '$3 > 900 {print $1}' | grep -v "rick" | grep -vi "nobody"); do
      userpid=$(ps -u $user | awk {'print $1'})

      usermod -U $user &>/dev/null
    done
  }

  eliminar_all() {
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    echo -e "\033[1;31m       BORRAR TODOS LOS USUARIOS REGISTRADOS"
    msg -bar
    read -p "   ►► Enter para Continuar  o CTRL + C Cancelar ◄◄"
    echo ""
    for user in $(cat /etc/passwd | awk -F : '$3 > 900 {print $1}' | grep -v "rick" | grep -vi "nobody"); do
      userdel --force $user
      echo -e "\033[1;32mUSUARIO:\033[1;33m $user \033[1;31mEliminado"
    done
    rm -rf /etc/SCRIPT-LATAM/cuentassh &>/dev/null
    rm -rf /etc/SCRIPT-LATAM/cuentahwid &>/dev/null
    rm -rf /etc/SCRIPT-LATAM/cuentatoken &>/dev/null
    service sshd restart &>/dev/null
    service ssh restart &>/dev/null
    service dropbear start &>/dev/null
    service stunnel4 start &>/dev/null
    service squid restart &>/dev/null
    rm -rf /etc/SCRIPT-LATAM/temp/userlock &>/dev/null
    rm -rf /etc/SCRIPT-LATAM/temp/Limiter.log &>/dev/null
    unlockall2
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    controlador_ssh
  }

  reset_contador() {
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    echo -e "\033[1;33m          REINICIAR CONTADOR DE BLOQUEOS"
    msg -bar
    echo -e "\033[1;97m !! Usar unicamente cuando en el apartado del contador\n   marque alguna cantidad erronea. ¡¡"
    echo ""
    echo -e "\033[1;31m          ## Cancelar Precione CTRL+C  ## "
    msg -bar
    read -p "        ►► Presione enter para continuar ◄◄"
    rm -rf /etc/SCRIPT-LATAM/temp/userlock
    rm -rf /etc/SCRIPT-LATAM/temp/Limiter.log
    unlockall2
    msg -bar
    echo -e "\033[1;92m           ¡¡CONTADORES REINICIADOS!!"
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    controlador_ssh
  }
  droppids() {
    local pids

    local portasVAR=$(lsof -V -i tcp -P -n | grep -v "ESTABLISHED" | grep -v "COMMAND" | grep "LISTEN")
    local NOREPEAT
    local reQ
    local Port
    while read port; do
      reQ=$(echo ${port} | awk '{print $1}')
      Port=$(echo {$port} | awk '{print $9}' | awk -F ":" '{print $2}')
      [[ $(echo -e $NOREPEAT | grep -w "$Port") ]] && continue
      NOREPEAT+="$Port\n"
      case ${reQ} in

      dropbear)
        [[ -z $DPB ]] && local DPB="\033[1;31m DROPBEAR: \033[1;32m"
        DPB+="$Port "
        ;;

      esac
    done <<<"${portasVAR}"

    [[ ! -z $DPB ]] && echo -e $DPB

    local port_dropbear="$DPB"
    #cat /var/log/auth.log|grep "$(date|cut -d' ' -f2,3)" > /var/log/authday.log
    cat /var/log/auth.log | tail -1000 >/var/log/authday.log
    local log=/var/log/authday.log
    local loginsukses='Password auth succeeded'
    [[ -z $port_dropbear ]] && return 1
    for port in $(echo $port_dropbear); do
      for pidx in $(ps ax | grep dropbear | grep "$port" | awk -F" " '{print $1}'); do
        pids="${pids}$pidx\n"
      done
    done
    for pid in $(echo -e "$pids"); do
      pidlogs=$(grep $pid $log | grep "$loginsukses" | awk -F" " '{print $3}')
      i=0
      for pidend in $pidlogs; do
        let i++
      done
      if [[ $pidend ]]; then
        login=$(grep $pid $log | grep "$pidend" | grep "$loginsukses")
        PID=$pid
        user=$(echo $login | awk -F" " '{print $10}' | sed -r "s/'//g")
        waktu=$(echo $login | awk -F" " '{print $2"-"$1,$3}')
        [[ -z $user ]] && continue
        echo "$user|$PID|$waktu"
      fi
    done
  }

  block_userfun() {
    local USRloked="/etc/SCRIPT-LATAM/temp/userlock"
    local LIMITERLOG="/etc/SCRIPT-LATAM/temp/Limiter.log"
    local LIMITERLOG2="/etc/SCRIPT-LATAM/temp/Limiter2.log"
    if [[ $2 = "-loked" ]]; then
      [[ $(cat ${USRloked} | grep -w "$1") ]] && return 1
      pkill -u $1 &>/dev/null
    fi
    if [[ $(cat ${USRloked} | grep -w "$1") ]]; then
      usermod -U "$1" &>/dev/null
      [[ -e ${USRloked} ]] && {
        newbase=$(cat ${USRloked} | grep -w -v "$1")
        [[ -e ${USRloked} ]] && rm ${USRloked}
        for value in $(echo ${newbase}); do
          echo $value >>${USRloked}
        done
      }
      [[ -e ${LIMITERLOG} ]] && [[ $(cat ${LIMITERLOG} | grep -w "$1") ]] && {
        newbase=$(cat ${LIMITERLOG} | grep -w -v "$1")
        [[ -e ${LIMITERLOG} ]] && rm ${LIMITERLOG}
        for value in $(echo ${newbase}); do
          echo $value >>${LIMITERLOG}
          echo $value >>${LIMITERLOG}
        done
      }
      return 1
    else
      usermod -L "$1" &>/dev/null
      pkill -u $1 &>/dev/null
      # droplim=`droppids|grep -w "$1"|cut -d'|' -f2`
      # kill -9 $droplim &>/dev/null
      droplim=$(dropbear_pids | grep -w "$1" | cut -d'|' -f2)
      kill -9 $droplim &>/dev/null
      echo $1 >>${USRloked}
      return 0
    fi
  }

  block_user() {
    clear && clear
    msg -bar
    local USRloked="/etc/SCRIPT-LATAM/temp/userlock"
    [[ ! -e ${USRloked} ]] && touch ${USRloked}

    ##-->>LECTOR DE CUENTAS
    if [[ -e "/etc/SCRIPT-LATAM/cuentassh" ]]; then
      readarray -t usuarios_ativos1 < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentassh)
      readarray -t usuarios_ativosf2 < <(cut -d '|' -f2 /etc/SCRIPT-LATAM/cuentassh)
    fi
    if [[ -e "/etc/SCRIPT-LATAM/cuentahwid" ]]; then
      readarray -t usuarios_ativos2 < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentahwid)
    fi
    if [[ -e "/etc/SCRIPT-LATAM/cuentatoken" ]]; then
      readarray -t usuarios_ativos3 < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentatoken)
    fi
    ##-->>GENERAR USUARIOS TOTALES
    cat /etc/SCRIPT-LATAM/cuentassh /etc/SCRIPT-LATAM/cuentahwid /etc/SCRIPT-LATAM/cuentatoken 2>/dev/null | cut -d '|' -f1 >/etc/SCRIPT-LATAM/cuentasactivast
    if [[ -e "/etc/SCRIPT-LATAM/cuentasactivast" ]]; then
      readarray -t mostrar_totales < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentasactivast)
    fi

    if [[ -z ${mostrar_totales[@]} ]]; then
      msg -tit
      msg -bar
      msg -verm "     BLOCK/UNBLOCK | Ningun Usuario Registrado"
      msg -bar
      read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      controlador_ssh
    else
      msg -tit
      msg -bar
      msg -ama "    BLOCK/UNBLOCK | Usuarios Activos del Servidor"
      #SSH
      if [[ -z ${usuarios_ativos1[@]} ]]; then
        echo "" >/dev/null 2>&1
      else
        echo -e "\033[38;5;239m════════════════\e[100m\e[97m  CUENTAS NORMALES  \e[0m\e[38;5;239m════════════════"
      fi

      Numb=0
      for us in $(echo ${usuarios_ativos1[@]}); do
        if [[ $(cat ${USRloked} | grep -w "${us}") ]]; then
          echo -ne "\e[1;93m [\e[1;32m$Numb\e[1;93m]\033[1;31m >" && echo -e "\033[1;97m ${us} \033[1;31m[ Lock ]"
        else
          echo -ne "\e[1;93m [\e[1;32m$Numb\e[1;93m]\033[1;31m >" && echo -e "\033[1;97m ${us} \033[1;32m[ Unlock ]"
        fi
        let Numb++
      done
      #HWID
      if [[ -z ${usuarios_ativos2[@]} ]]; then
        echo "" >/dev/null 2>&1
      else
        echo -e "\033[38;5;239m════════════════\e[100m\e[97m  CUENTAS CON HWID  \e[0m\e[38;5;239m════════════════"
      fi
      for us in $(echo ${usuarios_ativos2[@]}); do
        if [[ $(cat ${USRloked} | grep -w "${us}") ]]; then
          nomhwid="$(cat /etc/SCRIPT-LATAM/cuentahwid | grep -w "${us}" | cut -d'|' -f5)"
          echo -ne "\e[1;93m [\e[1;32m$Numb\e[1;93m]\033[1;31m >" && echo -e "\033[1;96m $nomhwid\n\033[1;97m ${us} \033[1;31m[ Lock ]"
        else
          nomhwid="$(cat /etc/SCRIPT-LATAM/cuentahwid | grep -w "${us}" | cut -d'|' -f5)"
          echo -ne "\e[1;93m [\e[1;32m$Numb\e[1;93m]\033[1;31m >" && echo -e "\033[1;96m $nomhwid\n\033[1;97m ${us} \033[1;32m[ Unlock ]"
        fi
        let Numb++
      done
      #TOKEN
      if [[ -z ${usuarios_ativos3[@]} ]]; then
        echo "" >/dev/null 2>&1
      else
        echo -e "\033[38;5;239m════════════════\e[100m\e[97m  CUENTAS CON TOKEN  \e[0m\e[38;5;239m═══════════════"
      fi
      for us in $(echo ${usuarios_ativos3[@]}); do
        if [[ $(cat ${USRloked} | grep -w "${us}") ]]; then
          nomtoken="$(cat /etc/SCRIPT-LATAM/cuentatoken | grep -w "${us}" | cut -d'|' -f5)"
          echo -ne "\e[1;93m [\e[1;32m$Numb\e[1;93m]\033[1;31m >" && echo -e "\033[1;96m $nomtoken\n\033[1;97m ${us} \033[1;31m[ Lock ]"
        else
          nomtoken="$(cat /etc/SCRIPT-LATAM/cuentatoken | grep -w "${us}" | cut -d'|' -f5)"
          echo -ne "\e[1;93m [\e[1;32m$Numb\e[1;93m]\033[1;31m >" && echo -e "\033[1;96m $nomtoken\n\033[1;97m ${us} \033[1;32m[ Unlock ]"
        fi
        let Numb++
      done

    fi
    msg -bar
    echo -e "\e[1;97m    Digite No de usuario a Bloquear/Desbloquear"
    msg -bar
    unset selection
    while [[ ${selection} = "" ]]; do
      echo -ne "\033[1;97m No. \e[1;32m" && read selection
      tput cuu1 && tput dl1
    done
    if [[ ! $(echo "${selection}" | egrep '[^0-9]') ]]; then
      usuario_del="${mostrar_totales[$selection]}"
    else
      usuario_del="$selection"
    fi
    [[ -z $usuario_del ]] && {
      msg -verm "Error, Usuario Invalido"
      msg -bar
      return 1
    }
    [[ ! $(echo ${mostrar_totales[@]} | grep -w "$usuario_del") ]] && {
      msg -verm "Error, Usuario Invalido"
      msg -bar
      return 1
    }
    msg -ne " " && echo -ne "\e[1;36m$usuario_del "
    block_userfun "$usuario_del" && msg -verm "[ Bloqueado ]" || msg -verd "[ Desbloqueado ]"
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    controlador_ssh
  }

  add_user() {
    Fecha=$(date +%d-%m-%y-%R)
    #nome senha Dias limite
    [[ $(cat /etc/passwd | grep $1: | grep -vi [a-z]$1 | grep -v [0-9]$1 >/dev/null) ]] && return 1
    valid=$(date '+%C%y-%m-%d' -d " +$3 days") && datexp=$(date "+%F" -d " + $3 days")
    useradd -m -s /bin/false $1 -e ${valid} >/dev/null 2>&1 || return 1
    (
      echo $2
      echo $2
    ) | passwd $1 2>/dev/null || {
      userdel --force $1
      return 1
    }
    echo "$1|$2|${datexp}|$4" >>/etc/SCRIPT-LATAM/cuentassh
    echo "$1|$2|${datexp}|$4" >>/etc/SCRIPT-LATAM/regtotal
    echo "" >/dev/null 2>&1
  }

  renew_user_fun() {
    #USUARIO-DIAS
    datexp=$(date "+%F" -d " + $2 days") && valid=$(date '+%C%y-%m-%d' -d " + $2 days")
    chage -E $valid $1 2>/dev/null || return 1
    sed -i '/'$1'/d' /etc/SCRIPT-LATAM/temp/userexp 2>/dev/null
    ##-->>LECTOR DE CUENTAS
    if [[ -e "/etc/SCRIPT-LATAM/cuentassh" ]]; then
      readarray -t usuarios_ativos1 < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentassh)
      readarray -t usuarios_ativosf2 < <(cut -d '|' -f2 /etc/SCRIPT-LATAM/cuentassh)
    fi
    if [[ -e "/etc/SCRIPT-LATAM/cuentahwid" ]]; then
      readarray -t usuarios_ativos2 < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentahwid)
    fi
    if [[ -e "/etc/SCRIPT-LATAM/cuentatoken" ]]; then
      readarray -t usuarios_ativos3 < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentatoken)
    fi
    ##-->>GENERAR USUARIOS TOTALES
    cat /etc/SCRIPT-LATAM/cuentassh /etc/SCRIPT-LATAM/cuentahwid /etc/SCRIPT-LATAM/cuentatoken 2>/dev/null | cut -d '|' -f1 >/etc/SCRIPT-LATAM/cuentasactivast
    if [[ -e "/etc/SCRIPT-LATAM/cuentasactivast" ]]; then
      readarray -t mostrar_totales < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentasactivast)
    fi

    #SSH
    if [[ -z ${usuarios_ativos1[@]} ]]; then
      echo "" >/dev/null 2>&1
    else
      [[ $(grep -o -i $1 /etc/SCRIPT-LATAM/cuentassh) ]] && {
        pass=$(cat /etc/SCRIPT-LATAM/cuentassh | grep -w "$1" | cut -d'|' -f2)
        limit=$(cat /etc/SCRIPT-LATAM/cuentassh | grep -w "$1" | cut -d'|' -f4)
        userb=$(cat /etc/SCRIPT-LATAM/cuentassh | grep -n -w $1 | cut -d'|' -f1 | cut -d':' -f1)
        sed -i "${userb}d" /etc/SCRIPT-LATAM/cuentassh
        echo "$1|$pass|${datexp}|$limit|$userb" >>/etc/SCRIPT-LATAM/cuentassh
      }
    fi
    #HWID
    if [[ -z ${usuarios_ativos2[@]} ]]; then
      echo "" >/dev/null 2>&1
    else
      [[ $(grep -o -i $1 /etc/SCRIPT-LATAM/cuentahwid) ]] && {
        nomhwid="$(cat /etc/SCRIPT-LATAM/cuentahwid | grep -w "$1" | cut -d'|' -f5)"
        sed -i '/'$1'/d' /etc/SCRIPT-LATAM/cuentahwid
        echo "$1||${datexp}||$nomhwid" >>/etc/SCRIPT-LATAM/cuentahwid
      }
    fi
    #TOKEN
    if [[ -z ${usuarios_ativos3[@]} ]]; then
      echo "" >/dev/null 2>&1
    else
      [[ $(grep -o -i $1 /etc/SCRIPT-LATAM/cuentatoken) ]] && {
        nomtoken="$(cat /etc/SCRIPT-LATAM/cuentatoken | grep -w "$1" | cut -d'|' -f5)"
        sed -i '/'$1'/d' /etc/SCRIPT-LATAM/cuentatoken
        echo "$1||${datexp}||$nomtoken" >>/etc/SCRIPT-LATAM/cuentatoken
      }
    fi
    echo "" >/dev/null 2>&1
  }

  edit_user_fun() {
    #nome senha dias limite
    (
      echo "$2"
      echo "$2"
    ) | passwd $1 >/dev/null 2>&1 || return 1
    datexp=$(date "+%F" -d " + $3 days") && valid=$(date '+%C%y-%m-%d' -d " + $3 days")
    chage -E $valid $1 2>/dev/null || return 1
    userb=$(cat /etc/SCRIPT-LATAM/cuentassh | grep -n -w $1 | cut -d'|' -f1 | cut -d':' -f1)
    sed -i "${userb}d" /etc/SCRIPT-LATAM/cuentassh
    echo "$1|$2|${datexp}|$4" >>/etc/SCRIPT-LATAM/cuentassh
  }
  rm_user() {
    #nome
    userdel --force "$1" &>/dev/null || return 1
    echo "" >/dev/null 2>&1
  }
  mostrar_usuarios() {
    for u in $(awk -F : '$3 > 900 { print $1 }' /etc/passwd | grep -v "nobody" | grep -vi polkitd | grep -vi system-); do
      echo "$u"
    done
  }
  dropbear_pids() {
    local pids
    local portasVAR=$(lsof -V -i tcp -P -n | grep -v "ESTABLISHED" | grep -v "COMMAND" | grep "LISTEN")
    local NOREPEAT
    local reQ
    local Port
    while read port; do
      reQ=$(echo ${port} | awk '{print $1}')
      Port=$(echo {$port} | awk '{print $9}' | awk -F ":" '{print $2}')
      [[ $(echo -e $NOREPEAT | grep -w "$Port") ]] && continue
      NOREPEAT+="$Port\n"
      case ${reQ} in
      dropbear)
        [[ -z $DPB ]] && local DPB=""
        DPB+="$Port "
        ;;
      esac
    done <<<"${portasVAR}"
    [[ ! -z $DPB ]] && echo -e $DPB
    #local port_dropbear="$DPB"
    local port_dropbear=$(ps aux | grep dropbear | awk NR==1 | awk '{print $17;}')
    cat /var/log/auth.log | grep -a -i dropbear | grep -a -i "Password auth succeeded" >/var/log/authday.log
    #cat /var/log/auth.log|grep "$(date|cut -d' ' -f2,3)" > /var/log/authday.log
    #cat /var/log/auth.log | tail -1000 >/var/log/authday.log
    local log=/var/log/authday.log
    local loginsukses='Password auth succeeded'
    [[ -z $port_dropbear ]] && return 1
    for port in $(echo $port_dropbear); do
      for pidx in $(ps ax | grep dropbear | grep "$port" | awk -F" " '{print $1}'); do
        pids="${pids}$pidx\n"
      done
    done
    for pid in $(echo -e "$pids"); do
      pidlogs=$(grep $pid $log | grep "$loginsukses" | awk -F" " '{print $3}')
      i=0
      for pidend in $pidlogs; do
        let i++
      done
      if [[ $pidend ]]; then
        login=$(grep $pid $log | grep "$pidend" | grep "$loginsukses")
        PID=$pid
        user=$(echo $login | awk -F" " '{print $10}' | sed -r "s/'//g")
        waktu=$(echo $login | awk -F" " '{print $2"-"$1,$3}')
        [[ -z $user ]] && continue
        echo "$user|$PID|$waktu"
      fi
    done
  }
  openvpn_pids() {
    #nome|#loguin|#rcv|#snd|#time
    byte() {
      while read B dummy; do
        [[ "$B" -lt 1024 ]] && echo "${B} bytes" && break
        KB=$(((B + 512) / 1024))
        [[ "$KB" -lt 1024 ]] && echo "${KB} Kb" && break
        MB=$(((KB + 512) / 1024))
        [[ "$MB" -lt 1024 ]] && echo "${MB} Mb" && break
        GB=$(((MB + 512) / 1024))
        [[ "$GB" -lt 1024 ]] && echo "${GB} Gb" && break
        echo $(((GB + 512) / 1024)) terabytes
      done
    }
    for user in $(mostrar_usuarios); do
      user="$(echo $user | sed -e 's/[^a-z0-9 -]//ig')"
      [[ ! $(sed -n "/^${user},/p" /etc/openvpn/openvpn-status.log) ]] && continue
      i=0
      unset RECIVED
      unset SEND
      unset HOUR
      while read line; do
        IDLOCAL=$(echo ${line} | cut -d',' -f2)
        RECIVED+="$(echo ${line} | cut -d',' -f3)+"
        SEND+="$(echo ${line} | cut -d',' -f4)+"
        DATESEC=$(date +%s --date="$(echo ${line} | cut -d',' -f5 | cut -d' ' -f1,2,3,4)")
        TIMEON="$(($(date +%s) - ${DATESEC}))"
        MIN=$(($TIMEON / 60)) && SEC=$(($TIMEON - $MIN * 60)) && HOR=$(($MIN / 60)) && MIN=$(($MIN - $HOR * 60))
        HOUR+="${HOR}h:${MIN}m:${SEC}s\n"
        let i++
      done <<<"$(sed -n "/^${user},/p" /etc/openvpn/openvpn-status.log)"
      RECIVED=$(echo $(echo ${RECIVED}0 | bc) | byte)
      SEND=$(echo $(echo ${SEND}0 | bc) | byte)
      HOUR=$(echo -e $HOUR | sort -n | tail -1)
      echo -e "$user|$i|$RECIVED|$SEND|$HOUR"
    done
  }
  err_fun() {
    case $1 in
    1)
      msg -verm "Usuario Nulo - Regresando al Menu SSH"
      sleep 3s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    2)
      msg -verm "Usuario con nombre muy corto (5-15 Caracteres)"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    3)
      msg -verm "Usuario con nombre muy grande (5-15 Caracteres)"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    4)
      msg -verm "Contraseña Nula"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    5)
      msg -verm "Contraseña muy corta (5-15 Caracteres)"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    6)
      msg -verm "Contraseña muy grande (5-15 Caracteres)"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    7)
      msg -verm "Duracion Nula"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    8)
      msg -verm "Duracion invalida utilize numeros"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    9)
      msg -verm "Duracion maxima y de un año"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    11)
      msg -verm "Limite Nulo"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    12)
      msg -verm "Limite invalido utilize numeros"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    13)
      msg -verm "Limite maximo de 999"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    14)
      msg -verm "Usuario Ya Existe"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    15)
      msg -verm "HWID/Nombre Nulo (8-10 Caracteres)"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    16)
      msg -verm "HWID Ya Existe"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    17)
      msg -verm "TOKEN/Nombre Nulo (8-10 Caracteres)"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    18)
      msg -verm "TOKEN Ya Existe"
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    19)
      msg -verm "User o Pass ya Ocupado reintente con Otro"
      sleep 3s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    20)
      msg -verm "No usar mismo user como pass y misma cantidad de caracteres "
      sleep 2s
      tput cuu1
      tput dl1
      tput cuu1
      tput dl1
      ;;
    esac
  }
  new_user() {
    clear && clear
    msg -bar
    if [[ -e "/etc/SCRIPT-LATAM/cuentasactivast" ]]; then
      readarray -t mostrar_totales < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentasactivast)
    fi
    if [[ -z ${mostrar_totales[@]} ]]; then
      msg -tit
      msg -ama "   AGREGAR USUARIO | Ningun Usuario Registrado"
      msg -bar
    else
      msg -tit
      msg -bar
      msg -ama "  AGREGAR USUARIO | Usuarios  Activos en Servidor"
      ##-->>LECTOR DE CUENTAS
      if [[ -e "/etc/SCRIPT-LATAM/cuentassh" ]]; then
        readarray -t usuarios_ativos1 < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentassh)
        readarray -t usuarios_ativosf2 < <(cut -d '|' -f2 /etc/SCRIPT-LATAM/cuentassh)
      fi
      if [[ -e "/etc/SCRIPT-LATAM/cuentahwid" ]]; then
        readarray -t usuarios_ativos2 < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentahwid)
      fi
      if [[ -e "/etc/SCRIPT-LATAM/cuentatoken" ]]; then
        readarray -t usuarios_ativos3 < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentatoken)
      fi
      ##-->>GENERAR USUARIOS TOTALES
      cat /etc/SCRIPT-LATAM/cuentassh /etc/SCRIPT-LATAM/cuentahwid /etc/SCRIPT-LATAM/cuentatoken 2>/dev/null | cut -d '|' -f1 >/etc/SCRIPT-LATAM/cuentasactivast
      if [[ -e "/etc/SCRIPT-LATAM/cuentasactivast" ]]; then
        readarray -t mostrar_totales < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentasactivast)
      fi
      #SSH
      if [[ -z ${usuarios_ativos1[@]} ]]; then
        echo "" >/dev/null 2>&1
      else
        echo -e "\033[38;5;239m════════════════\e[100m\e[97m  CUENTAS NORMALES  \e[0m\e[38;5;239m════════════════"
      fi
      i=1
      for us in $(echo ${usuarios_ativos1[@]}); do
        echo -e " \e[1;32m$i\033[1;31m -\e[1;97m ${us}"
        let i++
      done
      #HWID
      if [[ -z ${usuarios_ativos2[@]} ]]; then
        echo "" >/dev/null 2>&1
      else
        echo -e "\033[38;5;239m════════════════\e[100m\e[97m  CUENTAS CON HWID  \e[0m\e[38;5;239m════════════════"
      fi
      i=1
      for us in $(echo ${usuarios_ativos2[@]}); do
        echo -e " \e[1;32m$i\033[1;31m -\e[1;97m ${us}"
        let i++
      done
      #TOKEN
      if [[ -z ${usuarios_ativos3[@]} ]]; then
        echo "" >/dev/null 2>&1
      else
        echo -e "\033[38;5;239m════════════════\e[100m\e[97m  CUENTAS CON TOKEN  \e[0m\e[38;5;239m═══════════════"
      fi
      i=1
      for us in $(echo ${usuarios_ativos3[@]}); do
        echo -e " \e[1;32m$i\033[1;31m -\e[1;97m ${us}"
        let i++
      done
    fi

    cuenta_normal() {
      msg -bar
      echo -e "\e[1;97m             ----- CUENTA NORMAL  ------"
      msg -bar
      while true; do
        echo -ne "\e[1;93mDigite Nuevo Usuario: \e[1;32m" && read nomeuser
        nomeuser="$(echo $nomeuser | sed -e 's/[^a-z0-9 -]//ig')"
        if [[ -z $nomeuser ]]; then
          err_fun 1 && controlador_ssh
        elif [[ "${#nomeuser}" -lt "5" ]]; then
          err_fun 2 && continue
        elif [[ "${#nomeuser}" -gt "20" ]]; then
          err_fun 3 && continue
        elif [[ "$(echo ${usuarios_ativos1[@]} | grep -w "$nomeuser")" ]]; then
          err_fun 14 && continue
        elif [[ "$(echo ${usuarios_ativosf2[@]} | grep -w "$nomeuser")" ]]; then
          err_fun 19 && continue
        fi
        break
      done

      while true; do
        echo -ne "\e[1;93mDigite Nueva Contraseña: \e[1;32m" && read senhauser
        if [[ -z $senhauser ]]; then
          err_fun 4 && continue
        elif [[ "${#senhauser}" -lt "5" ]]; then
          err_fun 5 && continue
        elif [[ "${#senhauser}" -gt "20" ]]; then
          err_fun 6 && continue
        elif [[ "${#senhauser}" -eq "${#nomeuser}" ]]; then
          err_fun 20 && continue
        elif [[ "$(echo ${usuarios_ativosf2[@]} | grep -w "$senhauser")" ]]; then
          err_fun 19 && continue
        fi
        break
      done
      while true; do
        echo -ne "\e[1;93mDigite Tiempo de Validez: \e[1;32m" && read diasuser
        if [[ -z "$diasuser" ]]; then
          err_fun 7 && continue
        elif [[ "$diasuser" != +([0-9]) ]]; then
          err_fun 8 && continue
        elif [[ "$diasuser" -gt "360" ]]; then
          err_fun 9 && continue
        fi
        break
      done
      while true; do
        echo -ne "\e[1;93mDigite conexiones maximas: \e[1;32m" && read limiteuser
        if [[ -z "$limiteuser" ]]; then
          err_fun 11 && continue
        elif [[ "$limiteuser" != +([0-9]) ]]; then
          err_fun 12 && continue
        elif [[ "$limiteuser" -gt "999" ]]; then
          err_fun 13 && continue
        fi
        break
      done
      tput cuu1 && tput dl1
      tput cuu1 && tput dl1
      tput cuu1 && tput dl1
      tput cuu1 && tput dl1
      echo -ne "\e[38;5;202mIP del Servidor \e[1;97m" && echo -e "$(meu_ip)"
      echo -ne "\e[38;5;202mUsuario: \e[1;97m" && echo -e "$nomeuser"
      echo -ne "\e[38;5;202mContraseña: \e[1;97m" && echo -e "$senhauser"
      echo -ne "\e[38;5;202mDias de Duracion: \e[1;97m" && echo -e "$diasuser"
      echo -ne "\e[38;5;202mFecha de Expiracion: \e[1;97m" && echo -e "$(date "+%F" -d " + $diasuser days")"
      echo -ne "\e[38;5;202mLimite de Conexiones: \e[1;97m" && echo -e "$limiteuser"
      msg -bar
      add_user "${nomeuser}" "${senhauser}" "${diasuser}" "${limiteuser}" && echo -e "\e[1;32m            Usuario Creado con Exito" || msg -verm "         Error, Usuario no creado" && msg -bar
      [[ $(dpkg --get-selections | grep -w "openvpn" | head -1) ]] && [[ -e /etc/openvpn/openvpn-status.log ]] && newclient "$nomeuser" "$senhauser"
      rebootnb "backbaseu" 2>/dev/null

      read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      controlador_ssh
    }
    #####-----CUENTA HWID
    cuenta_hwid() {
      msg -bar
      echo -e "\e[1;97m               ----- CUENTA HWID  ------"
      msg -bar
      while true; do
        echo -ne "\e[1;93mDigite HWID: \e[1;32m" && read nomeuser
        nomeuser="$(echo $nomeuser | sed -e 's/[^a-z0-9 -]//ig')"
        if [[ -z $nomeuser ]]; then
          err_fun 15 && controlador_ssh
        elif [[ "${#nomeuser}" -lt "5" ]]; then
          err_fun 15 && continue
        elif [[ "${#nomeuser}" -gt "32" ]]; then
          err_fun 15 && continue
        elif [[ "$(echo ${usuarios_ativos2[@]} | grep -w "$nomeuser")" ]]; then
          err_fun 16 && continue
        fi
        break
      done

      while true; do
        echo -ne "\e[1;93mDigite Nombre: \e[1;32m" && read nickhwid
        nickhwid="$(echo $nickhwid | sed -e 's/[^a-z0-9 -]//ig')"
        if [[ -z $nickhwid ]]; then
          err_fun 15 && continue
        elif [[ "${#nickhwid}" -lt "5" ]]; then
          err_fun 15 && continue
        elif [[ "${#nickhwid}" -gt "15" ]]; then
          err_fun 15 && continue
        elif [[ "$(echo ${usuarios_ativos2[@]} | grep -w "$nickhwid")" ]]; then
          err_fun 16 && continue
        fi
        break
      done
      while true; do
        echo -ne "\e[1;93mDigite Tiempo de Validez: \e[1;32m" && read diasuser
        if [[ -z "$diasuser" ]]; then
          err_fun 7 && continue
        elif [[ "$diasuser" != +([0-9]) ]]; then
          err_fun 8 && continue
        elif [[ "$diasuser" -gt "360" ]]; then
          err_fun 9 && continue
        fi
        break
      done
      tput cuu1 && tput dl1
      tput cuu1 && tput dl1
      echo -ne "\e[38;5;202mIP del Servidor \e[1;97m" && echo -e "$(meu_ip)"
      echo -ne "\e[38;5;202mHWID: \e[1;97m" && echo -e "$nomeuser"
      echo -ne "\e[38;5;202mUsuario: \e[1;97m" && echo -e "$nickhwid"
      echo -ne "\e[38;5;202mDias de Duracion: \e[1;97m" && echo -e "$diasuser"
      echo -ne "\e[38;5;202mFecha de Expiracion: \e[1;97m" && echo -e "$(date "+%F" -d " + $diasuser days")"
      msg -bar
      [[ $(cat /etc/passwd | grep $nomeuser: | grep -vi [a-z]$nomeuser | grep -v [0-9]$nomeuser >/dev/null) ]] && {
        msg -verm "         Error, Usuario no creado"
        return 0
      }
      valid=$(date '+%C%y-%m-%d' -d " +$diasuser days") && datexp=$(date "+%F" -d " + $diasuser days")
      userdel $nomeuser >/dev/null 2>&1
      useradd -m -s /bin/false $nomeuser -e ${valid} >/dev/null 2>&1 || {
        msg -verm "         Error, Usuario no creado"
        return 0
      }
      (
        echo $nomeuser
        echo $nomeuser
      ) | passwd $nomeuser 2>/dev/null || {
        userdel --force $nomeuser

        return 1
      }
      echo "$nomeuser||${datexp}||${nickhwid}" >>/etc/SCRIPT-LATAM/cuentahwid
      echo "$nomeuser||${datexp}||${nickhwid}" >>/etc/SCRIPT-LATAM/regtotal
      msg -ama "\e[1;32m            Usuario Creado con Exito"
      msg -bar
      rebootnb "backbaseu" 2>/dev/null

      read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      controlador_ssh
    }
    #####-----CUENTA TOKEN
    cuenta_token() {
      msg -bar
      echo -e "\e[1;97m               ----- CUENTA TOKEN  ------"
      msg -bar
      passgeneral() {
        echo -ne "\e[1;93mDIGITE SU TOKEN GENERAL:\e[1;32m " && read passgeneral
        echo "$passgeneral" >/etc/SCRIPT-LATAM/temp/.passw
        msg -bar
      }
      [[ -e "/etc/SCRIPT-LATAM/temp/.passw" ]] || passgeneral
      while true; do
        echo -ne "\e[1;93mDigite TOKEN: \e[1;32m" && read nomeuser
        nomeuser="$(echo $nomeuser | sed -e 's/[^a-z0-9 -]//ig')"
        if [[ -z $nomeuser ]]; then
          err_fun 17 && controlador_ssh
        elif [[ "${#nomeuser}" -lt "4" ]]; then
          err_fun 17 && continue
        elif [[ "${#nomeuser}" -gt "32" ]]; then
          err_fun 17 && continue
        elif [[ "$(echo ${usuarios_ativos3[@]} | grep -w "$nomeuser")" ]]; then
          err_fun 18 && continue
        fi
        break
      done

      while true; do
        echo -ne "\e[1;93mDigite Nombre: \e[1;32m" && read nickhwid
        nickhwid="$(echo $nickhwid | sed -e 's/[^a-z0-9 -]//ig')"
        if [[ -z $nickhwid ]]; then
          err_fun 15 && continue
        elif [[ "${#nickhwid}" -lt "5" ]]; then
          err_fun 15 && continue
        elif [[ "${#nickhwid}" -gt "15" ]]; then
          err_fun 15 && continue
        elif [[ "$(echo ${usuarios_ativos2[@]} | grep -w "$nickhwid")" ]]; then
          err_fun 16 && continue
        fi
        break
      done

      while true; do
        echo -ne "\e[1;93mDigite Tiempo de Validez: \e[1;32m" && read diasuser
        if [[ -z "$diasuser" ]]; then
          err_fun 7 && continue
        elif [[ "$diasuser" != +([0-9]) ]]; then
          err_fun 8 && continue
        elif [[ "$diasuser" -gt "360" ]]; then
          err_fun 9 && continue
        fi
        break
      done
      tput cuu1 && tput dl1
      tput cuu1 && tput dl1
      echo -ne "\e[38;5;202mIP del Servidor \e[1;97m" && echo -e "$(meu_ip)"
      echo -ne "\e[38;5;202mToken: \e[1;97m" && echo -e "$nomeuser"
      echo -ne "\e[38;5;202mUsuario: \e[1;97m" && echo -e "$nickhwid"
      echo -ne "\e[38;5;202mDias de Duracion: \e[1;97m" && echo -e "$diasuser"
      echo -ne "\e[38;5;202mFecha de Expiracion: \e[1;97m" && echo -e "$(date "+%F" -d " + $diasuser days")"
      msg -bar
      passtoken=$(cat /etc/SCRIPT-LATAM/temp/.passw | tr -d " \t\n\r")

      [[ $(cat /etc/passwd | grep $nomeuser: | grep -vi [a-z]$nomeuser | grep -v [0-9]$nomeuser >/dev/null) ]] && {
        msg -verm "         Error, Usuario no creado"
        return 0
      }
      valid=$(date '+%C%y-%m-%d' -d " +$diasuser days") && datexp=$(date "+%F" -d " + $diasuser days")
      useradd -m -s /bin/false $nomeuser -e ${valid} >/dev/null 2>&1 || {
        msg -verm "         Error, Usuario no creado"
        return 0
      }
      (
        echo $passtoken
        echo $passtoken
      ) | passwd $nomeuser 2>/dev/null || {
        userdel --force $nomeuser
        return 1
      }
      echo "$nomeuser||${datexp}||${nickhwid}" >>/etc/SCRIPT-LATAM/cuentatoken
      echo "$nomeuser||${datexp}||${nickhwid}" >>/etc/SCRIPT-LATAM/regtotal
      msg -ama "\e[1;32m            Usuario Creado con Exito"
      rebootnb "backbaseu" 2>/dev/null

      msg -bar
      read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      controlador_ssh
    }
    msg -bar
    echo -e "\033[1;36m   --   Seleccione primero Tipo de Cuenta   --"
    echo -ne "  \e[1;93m [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;93m NORMAL \e[97m "
    echo -ne " \e[1;93m [\e[1;32m2\e[1;93m]\033[1;31m > \033[1;93m HWID\e[97m "
    echo -ne " \e[1;93m [\e[1;32m3\e[1;93m]\033[1;31m > \033[1;93m TOKEN\e[97m \n"
    msg -bar
    echo -e "    \e[97m\033[1;41m ENTER SIN RESPUESTA REGRESA A MENU ANTERIOR \033[0;97m"
    msg -bar
    echo -ne "\033[1;97m    └⊳ Seleccione una Opcion [1-3]: \e[1;32m"
    read opcao
    case $opcao in
    1)
      cuenta_normal
      ;;
    2)
      cuenta_hwid
      ;;
    3)
      cuenta_token
      ;;
    0)
      controlador_ssh
      ;;
    *)
      msg -bar
      controlador_ssh
      ;;

    esac

  }

  remove_user() {
    clear && clear
    msg -bar
    ##-->>LECTOR DE CUENTAS
    if [[ -e "/etc/SCRIPT-LATAM/cuentassh" ]]; then
      readarray -t usuarios_ativos1 < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentassh)
      readarray -t usuarios_ativosf2 < <(cut -d '|' -f2 /etc/SCRIPT-LATAM/cuentassh)
    fi
    if [[ -e "/etc/SCRIPT-LATAM/cuentahwid" ]]; then
      readarray -t usuarios_ativos2 < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentahwid)
    fi
    if [[ -e "/etc/SCRIPT-LATAM/cuentatoken" ]]; then
      readarray -t usuarios_ativos3 < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentatoken)
    fi
    ##-->>GENERAR USUARIOS TOTALES
    cat /etc/SCRIPT-LATAM/cuentassh /etc/SCRIPT-LATAM/cuentahwid /etc/SCRIPT-LATAM/cuentatoken 2>/dev/null | cut -d '|' -f1 >/etc/SCRIPT-LATAM/cuentasactivast
    if [[ -e "/etc/SCRIPT-LATAM/cuentasactivast" ]]; then
      readarray -t mostrar_totales < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentasactivast)
    fi
    if [[ -z ${mostrar_totales[@]} ]]; then
      msg -tit
      msg -bar
      msg -verm " BORAR USUARIO  | Ningun usuario registrado "
      msg -bar

      read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      controlador_ssh
    else
      msg -tit
      msg -bar
      msg -ama "   BORAR USUARIO |  Usuarios Activos del Servidor"
      #SSH
      if [[ -z ${usuarios_ativos1[@]} ]]; then
        echo "" >/dev/null 2>&1
      else
        echo -e "\033[38;5;239m════════════════\e[100m\e[97m  CUENTAS NORMALES  \e[0m\e[38;5;239m════════════════"
      fi
      i=0
      for us in $(echo ${usuarios_ativos1[@]}); do
        msg -ne "\e[1;93m [\e[1;32m$i\e[1;93m]\033[1;31m >" && echo -e "\e[1;97m ${us}"
        let i++
      done
      #HWID
      if [[ -z ${usuarios_ativos2[@]} ]]; then
        echo "" >/dev/null 2>&1
      else
        echo -e "\033[38;5;239m════════════════\e[100m\e[97m  CUENTAS CON HWID  \e[0m\e[38;5;239m════════════════"
      fi
      for us in $(echo ${usuarios_ativos2[@]}); do
        nomhwid="$(cat /etc/SCRIPT-LATAM/cuentahwid | grep -w "${us}" | cut -d'|' -f5)"
        msg -ne "\e[1;93m [\e[1;32m$i\e[1;93m]\033[1;31m >" && echo -e "\e[1;97m ${us} \e[1;93m| \e[1;96m$nomhwid"
        let i++
      done
      #TOKEN
      if [[ -z ${usuarios_ativos3[@]} ]]; then
        echo "" >/dev/null 2>&1
      else
        echo -e "\033[38;5;239m════════════════\e[100m\e[97m  CUENTAS CON TOKEN \e[0m\e[38;5;239m═══════════════"
      fi
      for us in $(echo ${usuarios_ativos3[@]}); do
        nomtoken="$(cat /etc/SCRIPT-LATAM/cuentatoken | grep -w "${us}" | cut -d'|' -f5)"
        msg -ne "\e[1;93m [\e[1;32m$i\e[1;93m]\033[1;31m >" && echo -e "\e[1;97m ${us} \e[1;93m| \e[1;96m$nomtoken"
        let i++
      done
    fi
    msg -bar
    echo -e "\e[1;97m         Escriba o Seleccione un Usuario"
    msg -bar
    unset selection
    while [[ -z ${selection} ]]; do
      echo -ne "\033[1;37mSeleccione Una Opcion: \e[1;32m" && read selection
      tput cuu1 && tput dl1
    done

    if [[ ! $(echo "${selection}" | egrep '[^0-9]') ]]; then
      usuario_del="${mostrar_totales[$selection]}"
    else
      usuario_del="$selection"
    fi

    [[ -z $usuario_del ]] && {
      msg -verm "Error, Usuario Invalido"
      msg -bar
      return 1
    }
    [[ ! $(echo ${mostrar_totales[@]} | grep -w "$usuario_del") ]] && {
      msg -verm "error, Usuario Invalido"
      msg -bar
      return 1
    }
    msg -ne "Usuario Seleccionado: " && echo -ne "$usuario_del"
    pkill -u $usuario_del
    droplim=$(dropbear_pids | grep -w "$usuario_del" | cut -d'|' -f2)
    kill -9 $droplim &>/dev/null
    rm_user "$usuario_del" && msg -verd " [ Removido ]" || msg -verm " [ No Removido ]"

    #SSH
    if [[ -z ${usuarios_ativos1[@]} ]]; then
      echo "" >/dev/null 2>&1
    else
      [[ $(grep -o -i $usuario_del /etc/SCRIPT-LATAM/cuentassh) ]] && {
        userb=$(cat /etc/SCRIPT-LATAM/cuentassh | grep -n -w $usuario_del | cut -d'|' -f1 | cut -d':' -f1)
        sed -i "${userb}d" /etc/SCRIPT-LATAM/cuentassh >/dev/null 2>&1
      }
    fi
    #HWID
    if [[ -z ${usuarios_ativos2[@]} ]]; then
      echo "" >/dev/null 2>&1
    else
      [[ $(grep -o -i $usuario_del /etc/SCRIPT-LATAM/cuentahwid) ]] && {
        sed -i '/'$usuario_del'/d' /etc/SCRIPT-LATAM/cuentahwid >/dev/null 2>&1
      }
    fi
    #TOKEN
    if [[ -z ${usuarios_ativos3[@]} ]]; then
      echo "" >/dev/null 2>&1
    else
      [[ $(grep -o -i $usuario_del /etc/SCRIPT-LATAM/cuentatoken) ]] && {
        sed -i '/'$usuario_del'/d' /etc/SCRIPT-LATAM/cuentatoken >/dev/null 2>&1
      }
    fi

    rm -rf /etc/SCRIPT-LATAM/temp/userlock
    rm -rf /etc/SCRIPT-LATAM/temp/Limiter.log
    unlockall2
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    controlador_ssh
  }

  renew_user() {
    clear && clear
    msg -bar
    ##-->>LECTOR DE CUENTAS
    if [[ -e "/etc/SCRIPT-LATAM/cuentassh" ]]; then
      readarray -t usuarios_ativos1 < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentassh)
      readarray -t usuarios_ativosf2 < <(cut -d '|' -f2 /etc/SCRIPT-LATAM/cuentassh)
    fi
    if [[ -e "/etc/SCRIPT-LATAM/cuentahwid" ]]; then
      readarray -t usuarios_ativos2 < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentahwid)
    fi
    if [[ -e "/etc/SCRIPT-LATAM/cuentatoken" ]]; then
      readarray -t usuarios_ativos3 < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentatoken)
    fi
    ##-->>GENERAR USUARIOS TOTALES
    cat /etc/SCRIPT-LATAM/cuentassh /etc/SCRIPT-LATAM/cuentahwid /etc/SCRIPT-LATAM/cuentatoken 2>/dev/null | cut -d '|' -f1 >/etc/SCRIPT-LATAM/cuentasactivast
    if [[ -e "/etc/SCRIPT-LATAM/cuentasactivast" ]]; then
      readarray -t mostrar_totales < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentasactivast)
    fi
    if [[ -z ${mostrar_totales[@]} ]]; then
      msg -tit
      msg -bar
      msg -verm " RENOVAR USUARIO | Ningun usuario registrado "
      msg -bar

      read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      controlador_ssh
    else
      msg -tit
      msg -bar
      msg -ama "  RENOVAR USUARIO | Usuarios Activos en el Servidor"

      #SSH
      if [[ -z ${usuarios_ativos1[@]} ]]; then
        echo "" >/dev/null 2>&1
      else
        echo -e "\033[38;5;239m════════════════\e[100m\e[97m  CUENTAS NORMALES  \e[0m\e[38;5;239m════════════════"
      fi
      i=0
      for us in $(echo ${usuarios_ativos1[@]}); do
        VPSsec=$(date +%s)
        DateExp="$(cat /etc/SCRIPT-LATAM/cuentassh | grep -w "${us}" | cut -d'|' -f3)"
        DataSec=$(date +%s --date="$DateExp")
        if [[ "$VPSsec" -gt "$DataSec" ]]; then
          EXPTIME="${red}[Exp]"
        else
          EXPTIME="${gren}[$(($(($DataSec - $VPSsec)) / 86400))]"
        fi
        msg -ne "\e[1;93m [\e[1;32m$i\e[1;93m]\033[1;31m >" && echo -e "\033[1;97m ${us} \e[1;93m| ${EXPTIME}"
        let i++
      done
      #HWID
      if [[ -z ${usuarios_ativos2[@]} ]]; then
        echo "" >/dev/null 2>&1
      else
        echo -e "\033[38;5;239m════════════════\e[100m\e[97m  CUENTAS CON HWID  \e[0m\e[38;5;239m════════════════"
      fi
      for us in $(echo ${usuarios_ativos2[@]}); do
        VPSsec=$(date +%s)
        DateExp="$(cat /etc/SCRIPT-LATAM/cuentahwid | grep -w "${us}" | cut -d'|' -f3)"
        DataSec=$(date +%s --date="$DateExp")
        if [[ "$VPSsec" -gt "$DataSec" ]]; then
          EXPTIME="${red}[Exp]"
        else
          EXPTIME="${gren}[$(($(($DataSec - $VPSsec)) / 86400))]"
        fi
        nomhwid="$(cat /etc/SCRIPT-LATAM/cuentahwid | grep -w "${us}" | cut -d'|' -f5)"
        msg -ne "\e[1;93m [\e[1;32m$i\e[1;93m]\033[1;31m >" && echo -e "\033[1;97m ${us} \e[1;93m| \033[1;96m${nomhwid} \e[1;93m| ${EXPTIME}"
        let i++
      done
      #TOKEN
      if [[ -z ${usuarios_ativos3[@]} ]]; then
        echo "" >/dev/null 2>&1
      else
        echo -e "\033[38;5;239m════════════════\e[100m\e[97m  CUENTAS CON TOKEN \e[0m\e[38;5;239m═══════════════"
      fi
      for us in $(echo ${usuarios_ativos3[@]}); do
        VPSsec=$(date +%s)
        DateExp="$(cat /etc/SCRIPT-LATAM/cuentatoken | grep -w "${us}" | cut -d'|' -f3)"
        DataSec=$(date +%s --date="$DateExp")
        if [[ "$VPSsec" -gt "$DataSec" ]]; then
          EXPTIME="${red}[Exp]"
        else
          EXPTIME="${gren}[$(($(($DataSec - $VPSsec)) / 86400))]"
        fi
        nomtoken="$(cat /etc/SCRIPT-LATAM/cuentatoken | grep -w "${us}" | cut -d'|' -f5)"
        msg -ne "\e[1;93m [\e[1;32m$i\e[1;93m]\033[1;31m >" && echo -e "\033[1;97m ${us} \e[1;93m| \033[1;96m${nomtoken} \e[1;93m| ${EXPTIME}"
        let i++
      done

    fi
    msg -bar
    echo -e "\e[1;97m         Escriba o seleccione un Usuario"
    msg -bar
    unset selection
    while [[ -z ${selection} ]]; do
      echo -ne "\033[1;37mSeleccione una Opcion: \e[1;32m" && read selection
      tput cuu1
      tput dl1
    done
    if [[ ! $(echo "${selection}" | egrep '[^0-9]') ]]; then
      useredit="${mostrar_totales[$selection]}"
    else
      useredit="$selection"
    fi
    [[ -z $useredit ]] && {
      msg -verm "Error, Usuario Invalido"
      msg -bar
      return 1
    }
    [[ ! $(echo ${mostrar_totales[@]} | grep -w "$useredit") ]] && {
      msg -verm "Error, Usuario Invalido"
      msg -bar
      return 1
    }
    while true; do
      echo -ne "\e[1;97m Nueva Duracion\033[1;33m [\033[1;32m $useredit \033[1;33m]\033[1;97m: " && read diasuser
      if [[ -z "$diasuser" ]]; then
        echo -e '\n\n\n'
        err_fun 7 && continue
      elif [[ "$diasuser" != +([0-9]) ]]; then
        echo -e '\n\n\n'
        err_fun 8 && continue
      elif [[ "$diasuser" -gt "360" ]]; then
        echo -e '\n\n\n'
        err_fun 9 && continue
      fi
      break
    done
    msg -bar

    renew_user_fun "${useredit}" "${diasuser}" && echo -e "\e[1;32m           Usuario Renovado Con Exito" || msg -verm "Error, Usuario no Modificado"

    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    controlador_ssh
  }

  edit_user() {
    clear && clear
    msg -bar
    ##-->>LECTOR DE CUENTAS
    if [[ -e "/etc/SCRIPT-LATAM/cuentassh" ]]; then
      readarray -t usuarios_ativos1 < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentassh)
      readarray -t usuarios_ativosf2 < <(cut -d '|' -f2 /etc/SCRIPT-LATAM/cuentassh)
    fi
    if [[ -e "/etc/SCRIPT-LATAM/cuentahwid" ]]; then
      readarray -t usuarios_ativos2 < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentahwid)
    fi
    if [[ -e "/etc/SCRIPT-LATAM/cuentatoken" ]]; then
      readarray -t usuarios_ativos3 < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentatoken)
    fi
    ##-->>GENERAR USUARIOS TOTALES
    cat /etc/SCRIPT-LATAM/cuentassh /etc/SCRIPT-LATAM/cuentahwid /etc/SCRIPT-LATAM/cuentatoken 2>/dev/null | cut -d '|' -f1 >/etc/SCRIPT-LATAM/cuentasactivast
    if [[ -e "/etc/SCRIPT-LATAM/cuentasactivast" ]]; then
      readarray -t mostrar_totales < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentasactivast)
    fi
    if [[ -z ${mostrar_totales[@]} ]]; then
      msg -tit
      msg -bar
      msg -verm " EDITAR USUARIO | Ningun usuario registrado "
      msg -bar

      read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      controlador_ssh
    else

      msg -tit
      msg -bar
      msg -ama "   EDITAR USER | Usuarios Activos del Servidor"
      msg -bar
      i=0
      if [[ -z ${usuarios_ativos1[@]} ]]; then
        echo "" >/dev/null 2>&1
      else
        echo -e "\033[38;5;239m════════════════\e[100m\e[97m  CUENTAS NORMALES  \e[0m\e[38;5;239m════════════════"
      fi
      for us in $(echo ${usuarios_ativos1[@]}); do
        msg -ne "\e[1;93m [\e[1;32m$i\e[1;93m]\033[1;31m >" && echo -e "\033[1;33m ${us}"
        let i++
      done
      msg -bar
    fi
    echo -e "\e[1;97m     Seleccione No. del Usuario a Editar"
    msg -bar
    unset selection
    while [[ -z ${selection} ]]; do
      echo -ne "\033[1;37m No. " && read selection
      tput cuu1
      tput dl1
    done
    if [[ ! $(echo "${selection}" | egrep '[^0-9]') ]]; then
      useredit="${mostrar_totales[$selection]}"
    else
      useredit="$selection"
    fi
    [[ -z $useredit ]] && {
      msg -verm "Error, Usuario Invalido"
      msg -bar
      return 1
    }
    [[ ! $(echo ${mostrar_totales[@]} | grep -w "$useredit") ]] && {
      msg -verm "Error, Usuario Invalido"
      msg -bar
      return 1
    }
    while true; do
      echo -ne "\e[1;97m Usuario Seleccionado: " && echo -e "\e[1;32m [ $useredit ]"
      echo -ne "\e[1;97m Nueva Contraseña de: \e[1;36m" && read senhauser
      if [[ -z "$senhauser" ]]; then
        err_fun 4 && continue
      elif [[ "${#senhauser}" -lt "6" ]]; then
        err_fun 5 && continue
      elif [[ "${#senhauser}" -gt "20" ]]; then
        err_fun 6 && continue
      fi
      break
    done
    while true; do
      echo -ne "\e[1;97m Dias de Duracion de: \e[1;36m" && read diasuser
      if [[ -z "$diasuser" ]]; then
        err_fun 7 && continue
      elif [[ "$diasuser" != +([0-9]) ]]; then
        err_fun 8 && continue
      elif [[ "$diasuser" -gt "360" ]]; then
        err_fun 9 && continue
      fi
      break
    done
    while true; do
      echo -ne "\e[1;97m Nuevo Limite de Conexion de: \e[1;36m" && read limiteuser
      if [[ -z "$limiteuser" ]]; then
        err_fun 11 && continue
      elif [[ "$limiteuser" != +([0-9]) ]]; then
        err_fun 12 && continue
      elif [[ "$limiteuser" -gt "999" ]]; then
        err_fun 13 && continue
      fi
      break
    done
    tput cuu1 && tput dl1
    tput cuu1 && tput dl1
    tput cuu1 && tput dl1
    tput cuu1 && tput dl1
    msg -ne "\e[38;5;202m Usuario: " && echo -e "$useredit"
    msg -ne "\e[38;5;202m Contraseña: " && echo -e "$senhauser"
    msg -ne "\e[38;5;202m Dias de Duracion: " && echo -e "$diasuser"
    msg -ne "\e[38;5;202m Fecha de Expiracion: " && echo -e "$(date "+%F" -d " + $diasuser days")"
    msg -ne "\e[38;5;202m Limite de Conexiones: " && echo -e "$limiteuser"
    msg -bar

    edit_user_fun "${useredit}" "${senhauser}" "${diasuser}" "${limiteuser}" && echo -e "\e[1;32m      Usuario Modificado Con Exito" && rm -rf /etc/SCRIPT-LATAM/temp/Limiter.log || msg -verm "Error, Usuario nao Modificado"
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    controlador_ssh
  }

  detail_user() {
    clear && clear
    ##-->>LECTOR DE CUENTAS
    if [[ -e "/etc/SCRIPT-LATAM/cuentassh" ]]; then
      readarray -t usuarios_ativos1 < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentassh)
      readarray -t usuarios_ativosf2 < <(cut -d '|' -f2 /etc/SCRIPT-LATAM/cuentassh)
    fi
    if [[ -e "/etc/SCRIPT-LATAM/cuentahwid" ]]; then
      readarray -t usuarios_ativos2 < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentahwid)
    fi
    if [[ -e "/etc/SCRIPT-LATAM/cuentatoken" ]]; then
      readarray -t usuarios_ativos3 < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentatoken)
    fi
    ##-->>GENERAR USUARIOS TOTALES
    cat /etc/SCRIPT-LATAM/cuentassh /etc/SCRIPT-LATAM/cuentahwid /etc/SCRIPT-LATAM/cuentatoken 2>/dev/null | cut -d '|' -f1 >/etc/SCRIPT-LATAM/cuentasactivast
    if [[ -e "/etc/SCRIPT-LATAM/cuentasactivast" ]]; then
      readarray -t mostrar_totales < <(cut -d '|' -f1 /etc/SCRIPT-LATAM/cuentasactivast)
    fi
    if [[ -z ${mostrar_totales[@]} ]]; then
      msg -bar
      msg -tit
      msg -bar
      msg -verm " DETALLES USUARIO | Ningun usuario registrado "
      msg -bar

      read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      controlador_ssh
    else
      msg -bar
      msg -tit
      msg -bar
      msg -ama "        INFORMACION DE USUARIOS REGISTRADOS "
      msg -bar
      red=$(tput setaf 1)
      gren=$(tput setaf 2)
      yellow=$(tput setaf 3)

      txtvar=$(printf '%-23s' "\e[1;97mUSUARIO")
      txtvar+=$(printf '%-31s' "\e[1;33mCONTRASEÑA")
      txtvar+=$(printf '%-17s' "\e[1;31mFECHA")
      txtvar+=$(printf '%-15s' "\e[1;36mLIMITE")
      echo -e "\033[1;33m${txtvar}"

      VPSsec=$(date +%s)

      #CUENTAS SSH
      mostrar_usuariosssh() {
        for u in $(cat /etc/SCRIPT-LATAM/cuentassh | cut -d'|' -f1); do
          echo "$u"
        done
      }
      [[ -e "/etc/SCRIPT-LATAM/cuentassh" ]] && usuarios_ativos1=($(mostrar_usuariosssh))
      if [[ -z ${usuarios_ativos1[@]} ]]; then
        echo "" >/dev/null 2>&1
      else
        echo -e "\033[38;5;239m════════════════\e[100m\e[97m  CUENTAS NORMALES  \e[0m\e[38;5;239m════════════════"
        while read user; do
          data_user=$(chage -l "$user" | grep -i co | awk -F ":" '{print $2}')
          txtvar=$(printf '%-25s' "\e[1;97m$user")
          if [[ -e "/etc/SCRIPT-LATAM/cuentassh" ]]; then
            if [[ $(cat /etc/SCRIPT-LATAM/cuentassh | grep -w "${user}") ]]; then
              txtvar+="$(printf '%-22s' "${yellow}$(cat /etc/SCRIPT-LATAM/cuentassh | grep -w "${user}" | cut -d'|' -f2)")"
              DateExp="$(cat /etc/SCRIPT-LATAM/cuentassh | grep -w "${user}" | cut -d'|' -f3)"
              DataSec=$(date +%s --date="$DateExp")
              if [[ "$VPSsec" -gt "$DataSec" ]]; then
                EXPTIME="${red}[Exp]"
              else
                EXPTIME="${gren}[$(($(($DataSec - $VPSsec)) / 86400))]"
              fi
              txtvar+="$(printf '%-25s' "${red}${DateExp}${EXPTIME}")"
              txtvar+="$(printf '%-1s' "\e[1;36m$(cat /etc/SCRIPT-LATAM/cuentassh | grep -w "${user}" | cut -d'|' -f4)")"
            else
              txtvar+="$(printf '%-21s' "${red}")"
              txtvar+="$(printf '%-29s' "${red}")"
              txtvar+="$(printf '%-5s' "${red}")"
            fi
          fi
          echo -e "$txtvar"
        done <<<"$(mostrar_usuariosssh)"

      fi

      #--- CUENTAS HWDI
      mostrar_usuarioshwid() {
        for u in $(cat /etc/SCRIPT-LATAM/cuentahwid | cut -d'|' -f1); do
          echo "$u"
        done
      }
      [[ -e "/etc/SCRIPT-LATAM/cuentahwid" ]] && usuarios_ativos2=($(mostrar_usuarioshwid))
      if [[ -z ${usuarios_ativos2[@]} ]]; then
        echo "" >/dev/null 2>&1
      else
        echo -e "\033[38;5;239m════════════════\e[100m\e[97m  CUENTAS CON HWID  \e[0m\e[38;5;239m════════════════"
        while read user; do
          data_user=$(chage -l "$user" | grep -i co | awk -F ":" '{print $2}')
          txtvar=$(printf '%-42s' "\e[1;97m$user")
          nomhwid="$(printf '%-18s' "\e[1;36m$(cat /etc/SCRIPT-LATAM/cuentahwid | grep -w "${user}" | cut -d'|' -f5)")"
          if [[ -e "/etc/SCRIPT-LATAM/cuentahwid" ]]; then
            if [[ $(cat /etc/SCRIPT-LATAM/cuentahwid | grep -w "${user}") ]]; then
              #txtvar+="$(printf '%-18s' "${yellow}$(cat ${USRdatabase} | grep -w "${user}" | cut -d'|' -f2)")"
              DateExp="$(cat /etc/SCRIPT-LATAM/cuentahwid | grep -w "${user}" | cut -d'|' -f3)"
              DataSec=$(date +%s --date="$DateExp")
              if [[ "$VPSsec" -gt "$DataSec" ]]; then
                EXPTIME="${red}[Exp]"
              else
                EXPTIME="${gren}[$(($(($DataSec - $VPSsec)) / 86400))]"
              fi
              txtvar+="$(printf '%-25s' "${red}${DateExp}${EXPTIME}")"
              txtvar+="$(printf '%-1s' "\e[1;36m$(cat /etc/SCRIPT-LATAM/cuentahwid | grep -w "${user}" | cut -d'|' -f4)")"
            else
              txtvar+="$(printf '%-21s' "${red}")"
              txtvar+="$(printf '%-29s' "${red}")"
              txtvar+="$(printf '%-5s' "${red}")"
            fi
          fi

          echo -e "$nomhwid\n$txtvar"
        done <<<"$(mostrar_usuarioshwid)"
      fi
      #--- CUENTAS TOKEN
      mostrar_usuariotoken() {
        for u in $(cat /etc/SCRIPT-LATAM/cuentatoken | cut -d'|' -f1); do
          echo "$u"
        done
      }
      [[ -e "/etc/SCRIPT-LATAM/cuentatoken" ]] && usuarios_ativos3=($(mostrar_usuariotoken))
      if [[ -z ${usuarios_ativos3[@]} ]]; then
        echo "" >/dev/null 2>&1
      else
        echo -e "\033[38;5;239m════════════════\e[100m\e[97m  CUENTAS CON TOKEN \e[0m\e[38;5;239m═══════════════"
        while read user; do
          data_user=$(chage -l "$user" | grep -i co | awk -F ":" '{print $2}')
          txtvar=$(printf '%-32s' "\e[1;97m$user")
          if [[ -e "/etc/SCRIPT-LATAM/cuentatoken" ]]; then
            if [[ $(cat /etc/SCRIPT-LATAM/cuentatoken | grep -w "${user}") ]]; then
              #txtvar+="$(printf '%-18s' "${yellow}$(cat ${USRdatabase} | grep -w "${user}" | cut -d'|' -f2)")"
              txtvar+="$(printf '%-18s' "\e[1;36m$(cat /etc/SCRIPT-LATAM/cuentatoken | grep -w "${user}" | cut -d'|' -f5)")"
              DateExp="$(cat /etc/SCRIPT-LATAM/cuentatoken | grep -w "${user}" | cut -d'|' -f3)"
              DataSec=$(date +%s --date="$DateExp")
              if [[ "$VPSsec" -gt "$DataSec" ]]; then
                EXPTIME="${red}[Exp]"
              else
                EXPTIME="${gren}[$(($(($DataSec - $VPSsec)) / 86400))]"
              fi
              txtvar+="$(printf '%-25s' "${red}${DateExp}${EXPTIME}")"
              txtvar+="$(printf '%-1s' "\e[1;36m$(cat /etc/SCRIPT-LATAM/cuentatoken | grep -w "${user}" | cut -d'|' -f4)")"
            else
              txtvar+="$(printf '%-21s' "${red}")"
              txtvar+="$(printf '%-29s' "${red}")"
              txtvar+="$(printf '%-5s' "${red}")"
            fi
          fi
          echo -e "$txtvar"
        done <<<"$(mostrar_usuariotoken)"
      fi
    fi
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    controlador_ssh
  }

  mostrar_usuariossh() {
    for u in $(cat /etc/SCRIPT-LATAM/cuentassh | cut -d'|' -f1); do
      echo "$u"
    done
  }
  mostrar_usuariohwid() {
    for u in $(cat /etc/SCRIPT-LATAM/cuentahwid | cut -d'|' -f1); do
      echo "$u"
    done
  }
  mostrar_usuariotoken() {
    for u in $(cat /etc/SCRIPT-LATAM/cuentatoken | cut -d'|' -f1); do
      echo "$u"
    done
  }

  #MONITOR DE USER
  monit_user() {
    clear && clear
    mostrar_usuariossh() {
      for u in $(cat /etc/SCRIPT-LATAM/cuentassh | cut -d'|' -f1); do
        echo "$u"
      done
    }
    mostrar_usuariohwid() {
      for u in $(cat /etc/SCRIPT-LATAM/cuentahwid | cut -d'|' -f1); do
        echo "$u"
      done
    }

    mostrar_usuariotoken() {
      for u in $(cat /etc/SCRIPT-LATAM/cuentatoken | cut -d'|' -f1); do
        echo "$u"
      done
    }
    [[ -e "/etc/SCRIPT-LATAM/cuentassh" ]] && usuarios_ativos1=($(mostrar_usuariossh))
    [[ -e "/etc/SCRIPT-LATAM/cuentahwid" ]] && usuarios_ativos2=($(mostrar_usuariohwid))
    [[ -e "/etc/SCRIPT-LATAM/cuentatoken" ]] && usuarios_ativos3=($(mostrar_usuariotoken))

    for us in $(echo ${usuarios_ativos1[@]}); do
      echo "${us}"
    done >/etc/SCRIPT-LATAM/cuentasactivast
    for us in $(echo ${usuarios_ativos2[@]}); do
      echo "${us}"
    done >>/etc/SCRIPT-LATAM/cuentasactivast
    for us in $(echo ${usuarios_ativos3[@]}); do
      echo "${us}"
    done >>/etc/SCRIPT-LATAM/cuentasactivast
    mostrar_totales() {
      for u in $(cat /etc/SCRIPT-LATAM/cuentasactivast | cut -d'|' -f1); do
        echo "$u"
      done
    }

    usuarios_totales=($(mostrar_totales))
    if [[ -z ${usuarios_totales[@]} ]]; then
      msg -bar
      msg -tit
      msg -bar
      msg -verm " MONITOR | Ningun usuario registrado "
      msg -bar
      read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
      controlador_ssh
    else
      msg -bar
      msg -tit
      msg -bar

      yellow=$(tput setaf 3)
      gren=$(tput setaf 2)
      echo -e "\e[93m   MONITOR DE CONEXIONES SSH/DROPBEAR/SSL/OPENVPN"
      msg -bar
      txtvar=$(printf '%-46s' "\e[1;97m USUARIO")
      txtvar+=$(printf '%-10s' "\e[1;93m CONEXIONES")
      #txtvar+=$(printf '%-16s' "TIME/ON")
      echo -e "\033[1;92m${txtvar}"
      #SSH
      if [[ -z ${usuarios_ativos1[@]} ]]; then
        echo "" >/dev/null 2>&1
      else
        echo -e "\033[38;5;239m════════════════\e[100m\e[97m  CUENTAS NORMALES  \e[0m\e[38;5;239m════════════════"
        while read user; do
          _=$(
            PID="0+"
            [[ $(dpkg --get-selections | grep -w "openssh" | head -1) ]] && PID+="$(ps aux | grep -v grep | grep sshd | grep -w "$user" | grep -v root | wc -l)+"
            [[ $(dpkg --get-selections | grep -w "dropbear" | head -1) ]] && PID+="$(dropbear_pids | grep -w "${user}" | wc -l)+"
            [[ $(dpkg --get-selections | grep -w "openvpn" | head -1) ]] && [[ -e /etc/openvpn/openvpn-status.log ]] && [[ $(openvpn_pids | grep -w "$user" | cut -d'|' -f2) ]] && PID+="$(openvpn_pids | grep -w "$user" | cut -d'|' -f2)+"
            PID+="0"

            [[ -z $(cat /etc/SCRIPT-LATAM/cuentassh | grep -w "${user}") ]] && MAXUSER="?" || MAXUSER="$(cat /etc/SCRIPT-LATAM/cuentassh | grep -w "${user}" | cut -d'|' -f4)"
            [[ $(echo $PID | bc) -gt 0 ]] && user="$user \e[1;93m[\033[1;32m ON \e[1;93m]" || user="$user \e[1;93m[\033[1;31m OFF \e[1;93m]"
            TOTALPID="$(echo $PID | bc)/$MAXUSER"
            while [[ ${#user} -lt 67 ]]; do
              user=$user" "
            done

            echo -e "\e[1;97m $user $TOTALPID " >&2
          ) &
          pid=$!
          sleep 0.5
        done <<<"$(mostrar_usuariossh)"
        while [[ -d /proc/$pid ]]; do
          sleep 1s
        done
      fi
      #HWID
      if [[ -z ${usuarios_ativos2[@]} ]]; then
        echo "" >/dev/null 2>&1
      else
        echo -e "\033[38;5;239m════════════════\e[100m\e[97m  CUENTAS CON HWID  \e[0m\e[38;5;239m════════════════"
        while read user; do
          _=$(
            PID="0+"
            [[ $(dpkg --get-selections | grep -w "openssh" | head -1) ]] && PID+="$(ps aux | grep -v grep | grep sshd | grep -w "$user" | grep -v root | wc -l)+"
            [[ $(dpkg --get-selections | grep -w "dropbear" | head -1) ]] && PID+="$(dropbear_pids | grep -w "${user}" | wc -l)+"
            [[ $(dpkg --get-selections | grep -w "openvpn" | head -1) ]] && [[ -e /etc/openvpn/openvpn-status.log ]] && [[ $(openvpn_pids | grep -w "$user" | cut -d'|' -f2) ]] && PID+="$(openvpn_pids | grep -w "$user" | cut -d'|' -f2)+"
            PID+="0"
            nomhwid="\e[1;96m$(cat /etc/SCRIPT-LATAM/cuentahwid | grep -w "${user}" | cut -d'|' -f5)"
            [[ -z $(cat /etc/SCRIPT-LATAM/cuentahwid | grep -w "${user}") ]] && MAXUSER="?" || MAXUSER="$(cat /etc/SCRIPT-LATAM/cuentahwid | grep -w "${user}" | cut -d'|' -f4)"
            [[ $(echo $PID | bc) -gt 0 ]] && user="$user \e[1;93m[\033[1;32m ON \e[1;93m]" || user="$user \e[1;93m[\033[1;31m OFF \e[1;93m]"
            TOTALPID="$(echo $PID | bc)"
            while [[ ${#user} -lt 69 ]]; do
              user=$user" "
            done
            echo -e "$nomhwid\e[1;97m\n$user $TOTALPID " >&2
          ) &
          pid=$!
          sleep 0.5s
        done <<<"$(mostrar_usuariohwid)"
        while [[ -d /proc/$pid ]]; do
          sleep 1s
        done
      fi
      #TOKEN
      if [[ -z ${usuarios_ativos3[@]} ]]; then
        echo "" >/dev/null 2>&1
      else
        echo -e "\033[38;5;239m════════════════\e[100m\e[97m  CUENTAS CON TOKEN  \e[0m\e[38;5;239m═══════════════"
        while read user; do
          _=$(
            PID="0+"
            [[ $(dpkg --get-selections | grep -w "openssh" | head -1) ]] && PID+="$(ps aux | grep -v grep | grep sshd | grep -w "$user" | grep -v root | wc -l)+"
            [[ $(dpkg --get-selections | grep -w "dropbear" | head -1) ]] && PID+="$(dropbear_pids | grep -w "${user}" | wc -l)+"
            [[ $(dpkg --get-selections | grep -w "openvpn" | head -1) ]] && [[ -e /etc/openvpn/openvpn-status.log ]] && [[ $(openvpn_pids | grep -w "$user" | cut -d'|' -f2) ]] && PID+="$(openvpn_pids | grep -w "$user" | cut -d'|' -f2)+"
            PID+="0"
            nomtoken="$(cat /etc/SCRIPT-LATAM/cuentatoken | grep -w "${user}" | cut -d'|' -f5)"
            [[ -z $(cat /etc/SCRIPT-LATAM/cuentatoken | grep -w "${user}") ]] && MAXUSER="?" || MAXUSER="$(cat /etc/SCRIPT-LATAM/cuentatoken | grep -w "${user}" | cut -d'|' -f4)"
            [[ $(echo $PID | bc) -gt 0 ]] && user="$user \e[1;96m$nomtoken \e[1;93m[\033[1;32m ON \e[1;93m]" || user="$user \e[1;96m$nomtoken \e[1;93m[\033[1;31m OFF \e[1;93m]"
            TOTALPID="$(echo $PID | bc)"
            while [[ ${#user} -lt 76 ]]; do
              user=$user" "
            done
            echo -e "\e[1;97m $user $TOTALPID " >&2
          ) &
          pid=$!
          sleep 0.5s
        done <<<"$(mostrar_usuariotoken)"
        while [[ -d /proc/$pid ]]; do
          sleep 1s
        done
      fi
    fi

    # while read user; do
    # [[ $(dpkg --get-selections | grep -w "openssh" | head -1) ]] && SSH=ON || SSH=OFF
    # [[ $(dpkg --get-selections | grep -w "dropbear" | head -1) ]] && DROP=ON || DROP=OFF
    # [[ $(dpkg --get-selections | grep -w "openvpn" | head -1) ]] && [[ -e /etc/openvpn/openvpn-status.log ]] && OPEN=ON || OPEN=OFF
    #   #----CONTADOR DE ONLINES
    #   totalo=$(
    #     PID="0"
    #     [[ $SSH = ON ]] && PID+="$(ps aux | grep -v grep | grep sshd | grep -w "$user" | grep -v root | wc -l 2>/dev/null)+"
    #     [[ $DROP = ON ]] && PID+="$(dropbear_pids | grep -w "$user" | wc -l 2>/dev/null)+"
    #     [[ $OPEN = ON ]] && [[ $(openvpn_pids | grep -w "$user" | cut -d'|' -f2) ]] && PID+="$(openvpn_pids | grep -w "$user" | cut -d'|' -f2)+"
    #     ONLINES+="$(echo ${PID}0 | bc)+"
    #     echo "${ONLINES}0" | bc >/etc/SCRIPT-LATAM/temp/Tonli
    #   ) &
    #   readonlit=$totalo
    # done <<<"$(mostrar_totales)"
    rebootnb "contadortotal" 2>/dev/null

    onlinest=$(cat /etc/SCRIPT-LATAM/temp/Tonli)
    msg -bar
    echo -e "\033[1;32m            TOTAL DE CONECTADOS:\033[1;36m[\e[97m $onlinest \033[1;36m]"
    msg -bar

    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    controlador_ssh
  }
  rm_vencidos() {
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    msg -ama "          BORRANDO USUARIOS EXPIRADOS "
    msg -bar
    red=$(tput setaf 1)
    gren=$(tput setaf 2)
    yellow=$(tput setaf 3)
    txtvar=$(printf '%-42s' "\e[1;97m   USUARIOS")
    txtvar+=$(printf '%-1s' "\e[1;32m  VALIDIDEZ")
    echo -e "\033[1;92m${txtvar}"

    expired="${red}Usuario Expirado"
    valid="${gren}Usuario Vigente"
    never="${yellow}Usuario Ilimitado"
    removido="${red}Eliminado"
    DataVPS=$(date +%s)
    #CUENTAS SSH
    mostrar_usuariosssh() {
      for u in $(cat /etc/SCRIPT-LATAM/cuentassh | cut -d'|' -f1); do
        echo "$u"
      done
    }
    [[ -e "/etc/SCRIPT-LATAM/cuentassh" ]] && usuarios_ativos1=($(mostrar_usuariosssh))
    if [[ -z ${usuarios_ativos1[@]} ]]; then
      echo "" >/dev/null 2>&1
    else
      echo -e "\033[38;5;239m════════════════\e[100m\e[97m  CUENTAS NORMALES  \e[0m\e[38;5;239m════════════════"
      while read user; do
        DataUser=$(chage -l "${user}" | grep -i co | awk -F ":" '{print $2}')
        usr=$user
        while [[ ${#usr} -lt 34 ]]; do
          usr=$usr" "
        done
        [[ "$DataUser" = " never" ]] && {
          echo -e "\e[1;97m$usr $never"
          continue
        }
        DataSEC=$(date +%s --date="$DataUser")
        if [[ "$DataSEC" -lt "$DataVPS" ]]; then
          echo -ne "\e[1;97m$usr $expired"
          pkill -u $user &>/dev/null
          droplim=$(dropbear_pids | grep -w "$user" | cut -d'|' -f2)
          kill -9 $droplim &>/dev/null
          # droplim=`droppids|grep -w "$user"|cut -d'|' -f2`
          # kill -9 $droplim &>/dev/null
          rm_user "$user" && echo -e " y ($removido)"
          userb=$(cat /etc/SCRIPT-LATAM/cuentassh | grep -n -w $user | cut -d'|' -f1 | cut -d':' -f1)
          sed -i "${userb}d" /etc/SCRIPT-LATAM/cuentassh
        else
          echo -e "\e[1;97m$usr $valid"
        fi
      done <<<"$(mostrar_usuariosssh)"
    fi
    #---SSH HWID
    mostrar_usuarioshwid() {
      for u in $(cat /etc/SCRIPT-LATAM/cuentahwid | cut -d'|' -f1); do
        echo "$u"
      done
    }
    [[ -e "/etc/SCRIPT-LATAM/cuentahwid" ]] && usuarios_ativos2=($(mostrar_usuarioshwid))
    if [[ -z ${usuarios_ativos2[@]} ]]; then
      echo "" >/dev/null 2>&1
    else
      echo -e "\033[38;5;239m═════════════════\e[100m\e[97m  CUENTAS HWID  \e[0m\e[38;5;239m═════════════════"

      while read user; do
        DataUser=$(chage -l "${user}" | grep -i co | awk -F ":" '{print $2}')
        usr=$user
        while [[ ${#usr} -lt 34 ]]; do
          usr=$usr" "
        done
        [[ "$DataUser" = " never" ]] && {
          echo -e "\e[1;97m$usr $never"
          continue
        }
        DataSEC=$(date +%s --date="$DataUser")
        if [[ "$DataSEC" -lt "$DataVPS" ]]; then
          echo -ne "\e[1;97m$usr $expired"
          pkill -u $user &>/dev/null
          droplim=$(dropbear_pids | grep -w "$user" | cut -d'|' -f2)
          kill -9 $droplim &>/dev/null
          # droplim=`droppids|grep -w "$user"|cut -d'|' -f2`
          # kill -9 $droplim &>/dev/null
          rm_user "$user" && echo -e " y ($removido)"
          sed -i '/'$user'/d' /etc/SCRIPT-LATAM/cuentahwid
        else
          echo -e "\e[1;97m$usr $valid"
        fi
      done <<<"$(mostrar_usuarioshwid)"
    fi
    #--- CUENTAS TOKEN
    mostrar_usuariotoken() {
      for u in $(cat /etc/SCRIPT-LATAM/cuentatoken | cut -d'|' -f1); do
        echo "$u"
      done
    }
    [[ -e "/etc/SCRIPT-LATAM/cuentatoken" ]] && usuarios_ativos3=($(mostrar_usuariotoken))
    if [[ -z ${usuarios_ativos3[@]} ]]; then
      echo "" >/dev/null 2>&1
    else
      echo -e "\033[38;5;239m═════════════════\e[100m\e[97m  CUENTAS TOKEN  \e[0m\e[38;5;239m═════════════════"
      while read user; do
        DataUser=$(chage -l "${user}" | grep -i co | awk -F ":" '{print $2}')
        usr=$user
        while [[ ${#usr} -lt 34 ]]; do
          usr=$usr" "
        done
        [[ "$DataUser" = " never" ]] && {
          echo -e "\e[1;97m$usr $never"
          continue
        }
        DataSEC=$(date +%s --date="$DataUser")
        if [[ "$DataSEC" -lt "$DataVPS" ]]; then
          echo -ne "\e[1;97m$usr $expired"
          pkill -u $user &>/dev/null
          droplim=$(dropbear_pids | grep -w "$user" | cut -d'|' -f2)
          kill -9 $droplim &>/dev/null
          # droplim=`droppids|grep -w "$user"|cut -d'|' -f2`
          # kill -9 $droplim &>/dev/null
          rm_user "$user" && echo -e "y ($removido)"
          sed -i '/'$user'/d' /etc/SCRIPT-LATAM/cuentatoken
        else
          echo -e "\e[1;97m$usr $valid"
        fi
      done <<<"$(mostrar_usuariotoken)"
    fi
    rm -rf /etc/SCRIPT-LATAM/temp/userlock
    rm -rf /etc/SCRIPT-LATAM/temp/userexp
    unlockall2
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    controlador_ssh
  }

  #BACKUP USER SSH
  backup_fun() {
    clear && clear
    backupssh() {
      rm -rf /root/backup-latam/ >/dev/null 2>&1
      apt install sshpass >/dev/null 2>&1
      mkdir /root/backup-latam/
      export UGIDLIMIT=1000
      awk -v LIMIT=$UGIDLIMIT -F: '($3>=LIMIT) && ($3!=65534)' /etc/passwd >/root/backup-latam/passwd.mig
      awk -v LIMIT=$UGIDLIMIT -F: '($3>=LIMIT) && ($3!=65534)' /etc/group >/root/backup-latam/group.mig
      awk -v LIMIT=$UGIDLIMIT -F: '($3>=LIMIT) && ($3!=65534) {print $1}' /etc/passwd | tee - | egrep -f - /etc/shadow >/root/backup-latam/shadow.mig
      cp /etc/gshadow /root/backup-latam/gshadow.mig >/dev/null 2>&1
      cp /etc/SCRIPT-LATAM/cuentassh /root/backup-latam/cuentassh >/dev/null 2>&1
      cp /etc/SCRIPT-LATAM/cuentahwid /root/backup-latam/cuentahwid >/dev/null 2>&1
      cp /etc/SCRIPT-LATAM/cuentatoken /root/backup-latam/cuentatoken >/dev/null 2>&1
      cp /etc/SCRIPT-LATAM/temp/.passw /root/backup-latam/.passw >/dev/null 2>&1
      tar -zcvpf /root/backup-latam/home.tar.gz /home >/dev/null 2>&1
      echo -ne "\e[1;97mDigite usuario root del Nuevo VPS:\033[1;92m " && read useroot
      echo -ne "\e[1;97mDigite IP del Nuevo VPS:\033[1;92m " && read ipvps
      echo -ne "\e[1;97mDigite Contraseña del Nuevo VPS:\033[1;92m " && read passvps
      echo ""
      sshpass -p "$passvps" scp -o "StrictHostKeyChecking no" -r /root/backup-latam/ "$useroot"@"$ipvps":/root/
      msg -azu " Procedimiento Hecho con Exito, Guardado en:"
      echo ""
      echo -e "\033[1;31m   BACKUP > [\033[1;32m/root/backup-latam/\033[1;31m]"

    }

    restaurarback() {
      echo -ne "\033[1;37m ¡¡Recomiendo DESACTIVAR LIM/DES!!\n"
      msg -bar
      read -t 60 -n 1 -rsp $'\033[1;39m  Presiona enter para Continuar \n'

      [[ -e /root/Backup-Latam.tar.gz ]] && {
        rm -rf /root/backup-latam
        tar -xzvf Backup-Latam.tar.gz
      }
      msg -bar
      mkdir /root/users.bk
      cp /etc/passwd /etc/shadow /etc/group /etc/gshadow /root/users.bk
      cd /root/backup-latam/
      cat passwd.mig >>/etc/passwd
      cat group.mig >>/etc/group
      cat shadow.mig >>/etc/shadow
      /bin/cp gshadow.mig /etc/gshadow
      cat cuentassh >/etc/SCRIPT-LATAM/cuentassh
      cat cuentahwid >/etc/SCRIPT-LATAM/cuentahwid
      cat cuentatoken >/etc/SCRIPT-LATAM/cuentatoken
      cat .passw >/etc/SCRIPT-LATAM/temp/.passw
      cd /
      tar -zxvf /root/backup-latam/home.tar.gz
      echo ""
      msg -azu " Procedimiento Hecho con Exito, Reinicie su VPS"
    }

    msg -bar
    msg -tit
    msg -bar
    msg -ama "        HERRAMIENTA DE BACKUP DE USUARIOS"
    msg -bar
    echo -e "\e[1;31m >>\e[1;97m Se generara un backup y enviara a la VPS Nueva\033[1;92m "
    echo -e "\e[1;31m >>\e[1;97m Tenga su VPS Nueva ya configurada \033[1;92m "
    msg -bar
    echo -ne " \e[1;93m [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;97m CREAR BACKUP REMOTO   \e[97m \n"
    echo -ne " \e[1;93m [\e[1;32m2\e[1;93m]\033[1;31m > \033[1;97m RESTAURAR BACKUP\e[97m \n"
    msg -bar
    unset selection
    while [[ ${selection} != @([1-2]) ]]; do
      echo -ne "\033[1;37mSeleccione una Opcion: " && read selection
      tput cuu1 && tput dl1
    done
    case ${selection} in
    1)
      backupssh
      ;;
    2)
      restaurarback
      ;;
    esac
    echo ""
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    controlador_ssh
  }

  ##LIMITADOR
  verif_funx() {
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    echo -e "\033[1;32m             LIMITADOR DE CUENTAS"
    msg -bar
    echo -e "Esta Opcion Limita las Conexiones de SSH/SSL/DROPBEAR"
    PIDVRF="$(ps aux | grep "/etc/SCRIPT-LATAM/menu.sh verificar" | grep -v grep | awk '{print $2}')"
    if [[ -z $PIDVRF ]]; then
      msg -bar
      echo -ne "\033[1;96m   ¿Cada cuantos segundos ejecutar el limitador?\n\033[1;97m  +Segundos = -Uso de CPU | -Segundos = +Uso de CPU\033[0;92m \n                Predeterminado:\033[1;37m 120s\n     Cuantos Segundos (Numeros Unicamente): " && read tiemlim

      error() {
        msg -verm "Tiempo invalido,se ajustara a 120s (Tiempo por Defeto)"
        sleep 5s
        tput cuu1
        tput dl1
        tput cuu1
        tput dl1
        tiemlim="120"
        echo "${tiemlim}" >/etc/SCRIPT-LATAM/temp/T-Lim

      }
      #[[ -z "$tiemlim" ]] && tiemlim="120"
      if [[ "$tiemlim" != +([0-9]) ]]; then
        error
      fi
      [[ -z "$tiemlim" ]] && tiemlim="120"
      if [ "$tiemlim" -lt "120" ]; then
        error
      fi
      echo "${tiemlim}" >/etc/SCRIPT-LATAM/temp/T-Lim
      screen -dmS limitador watch -n $tiemlim /etc/SCRIPT-LATAM/menu.sh "verificar"
    else
      for pid in $(echo $PIDVRF); do
        screen -S limitador -p 0 -X quit
      done
      [[ -e /etc/SCRIPT-LATAM/temp/USRonlines ]] && rm /etc/SCRIPT-LATAM/temp/USRonlines
      [[ -e /etc/SCRIPT-LATAM/temp/USRexpired ]] && rm /etc/SCRIPT-LATAM/temp/USRexpired
      [[ -e /etc/SCRIPT-LATAM/temp/USRbloqueados ]] && rm /etc/SCRIPT-LATAM/temp/USRbloqueados
    fi
    msg -bar
    [[ -z ${VERY} ]] && verificar="\033[1;32m ACTIVADO " || verificar="\033[1;31m DESACTIVADO "
    echo -e "            $verificar  --  CON EXITO"
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    controlador_ssh
  }

  ##DESBLOEUEAR
  verif2_funx() {
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    echo -e "\033[1;32m      DESBLOQUEO AUT. Y LIMPIADOR DE EXPIARDOS"
    msg -bar
    echo -e "Esta opcion desbloquea  a usuarios bloqueados por \nel limitador y limpia los usuarios expirados"
    PIDVRF2="$(ps aux | grep "/etc/SCRIPT-LATAM/menu.sh desbloqueo" | grep -v grep | awk '{print $2}')"
    if [[ -z $PIDVRF2 ]]; then
      msg -bar
      echo -ne "\033[1;96m  ¿Cada cuantos segundos ejecutar el desbloqueador?\n\033[1;97m  +Segundos = -Uso de CPU | -Segundos = +Uso de CPU\033[0;92m \n                Predeterminado:\033[1;37m 120s\n     Cuantos Segundos (Numeros Unicamente): " && read tiemdes
      error() {
        msg -verm "Tiempo invalido,se ajustara a 120s (Tiempo por Defeto)"
        sleep 5s
        tput cuu1
        tput dl1
        tput cuu1
        tput dl1
        tiemdes="120"
        echo "${tiemdes}" >/etc/SCRIPT-LATAM/temp/T-Des
      }
      #[[ -z "$tiemdes" ]] && tiemdes="120"
      if [[ "$tiemdes" != +([0-9]) ]]; then
        error
      fi
      [[ -z "$tiemdes" ]] && tiemdes="120"
      if [ "$tiemdes" -lt "120" ]; then
        error
      fi
      echo "${tiemdes}" >/etc/SCRIPT-LATAM/temp/T-Des
      screen -dmS desbloqueador watch -n $tiemdes /etc/SCRIPT-LATAM/menu.sh "desbloqueo"
      #screen -dmS very2 /etc/SCRIPT-LATAM/menu.sh desbloqueo
    else
      for pid in $(echo $PIDVRF2); do
        screen -S desbloqueador -p 0 -X quit
      done

    fi
    msg -bar
    [[ -z ${VERY2} ]] && desbloqueo="\033[1;32m ACTIVADO " || desbloqueo="\033[1;31m DESACTIVADO "
    echo -e "            $desbloqueo  --  CON EXITO"
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    controlador_ssh
  }

  baner_fun() {
    banner_on() {
      clear && clear
      local="/etc/SCRIPT-LATAM/bannerssh"
      rm -rf $local >/dev/null 2>&1
      local2="/etc/dropbear/banner"
      chk=$(cat /etc/ssh/sshd_config | grep Banner)
      if [ "$(echo "$chk" | grep -v "#Banner" | grep Banner)" != "" ]; then
        local=$(echo "$chk" | grep -v "#Banner" | grep Banner | awk '{print $2}')
      else
        echo "" >>/etc/ssh/sshd_config
        echo "Banner /etc/SCRIPT-LATAM/bannerssh" >>/etc/ssh/sshd_config
        local="/etc/SCRIPT-LATAM/bannerssh"
      fi
      msg -bar
      msg -tit
      msg -bar
      msg -ama "         AGREGAR BANNER SSH/SSL/DROPBEAR"
      msg -bar
      msg -ne "Inserte el BANNER de preferencia en HTML sin saltos: \n\n" && read ban_ner
      echo ""
      msg -bar
      credi="$(less /etc/SCRIPT-LATAM/message.txt)"
      echo "$ban_ner" >>$local
      echo '<p style="text-align: center;"><strong><span style="color: #993300;">'$credi'</span></strong></p>' >>$local
      echo '<p style="text-align: center;"><strong>SCRIPT <span style="color: #ff0000;">|</span><span style="color: #ffcc00;"> LATAM</span></strong></p>' >>$local
      if [[ -e "$local2" ]]; then
        rm $local2 >/dev/null 2>&1
        cp $local $local2 >/dev/null 2>&1
      fi
      msg -verd "          BANNER AGREGADO CON !! EXITO ¡¡" && msg -bar
      service ssh restart 2>/dev/null
      service dropbear stop 2>/dev/null
      sed -i "s/=1/=0/g" /etc/default/dropbear
      service dropbear restart
      sed -i "s/=0/=1/g" /etc/default/dropbear
    }

    banner_off() {
      clear && clear
      msg -bar
      msg -ama "         ELIMINANDO  BANNER SSH/SSL/DROPBEAR"
      msg -bar
      sed -i '/'Banner'/d' /etc/ssh/sshd_config
      sed -i -e 's/^[ \t]*//; s/[ \t]*$//; /^$/d' /etc/ssh/sshd_config
      echo "" >>/etc/ssh/sshd_config
      rm -rf /etc/dropbear/banner >/dev/null 2>&1
      echo "" >/etc/dropbear/banner >/dev/null 2>&1
      service ssh restart 2>/dev/null
      service dropbear stop 2>/dev/null
      sed -i "s/=1/=0/g" /etc/default/dropbear
      service dropbear restart
      sed -i "s/=0/=1/g" /etc/default/dropbear
      echo -e "\033[1;92m            BANNER ELIMINADO !! EXITO ¡¡ "
      msg -bar
    }
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    msg -ama "         AGREGAR BANNER SSH/SSL/DROPBEAR"
    msg -bar
    echo -e "${cor[1]}            Escoja la opcion deseada."
    msg -bar
    echo -e "\e[1;93m [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;97m AGREGAR BANNER SSH/SSL/DROPBEAR "
    echo -e "\e[1;93m [\e[1;32m2\e[1;93m]\033[1;31m > \e[1;97m ELIMINAR Y DESACTIVAR BANNER   "
    msg -bar
    echo -e "    \e[97m\033[1;41m ENTER SIN RESPUESTA REGRESA A MENU ANTERIOR \033[0;37m"
    msg -bar
    echo -ne "\033[1;37mDigite solo el numero segun su respuesta: \033[1;32m"
    read opcao
    case $opcao in
    1)
      msg -bar
      banner_on
      ;;
    2)
      msg -bar
      banner_off
      ;;
    *)
      msg -bar
      ;;
    esac
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    controlador_ssh
  }

  rec_total() {
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    msg -ama "     REGISTRO TOTAL DE CUENTAS VIEJAS Y NUEVAS"
    msg -bar
    cat /etc/SCRIPT-LATAM/regtotal
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    controlador_ssh
  }

  demo_ssh() {

    rm -rf /etc/SCRIPT-LATAM/temp/demo-ssh 2>/dev/null
    mkdir /etc/SCRIPT-LATAM/temp/demo-ssh 2>/dev/null
    SCPdir="/etc/SCRIPT-LATAM"
    declare -A cor=([0]="\033[1;37m" [1]="\033[1;34m" [2]="\033[1;31m" [3]="\033[1;33m" [4]="\033[1;32m")
    tmpusr() {
      time="$1"
      timer=$(($time * 60))
      timer2="'$timer's"
      echo "#!/bin/bash
sleep $timer2
kill"' $(ps -u '"$2 |awk '{print"' $1'"}') 1> /dev/null 2> /dev/null
userdel --force $2
rm -rf /tmp/$2
exit" >/tmp/$2
    }

    tmpusr2() {
      time="$1"
      timer=$(($time * 60))
      timer2="'$timer's"
      echo "#!/bin/bash
sleep $timer2
kill=$(dropb | grep "$2" | awk '{print $2}')
kill $kill
userdel --force $2
rm -rf /tmp/$2
exit" >/tmp/$2
    }
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    msg -ama "        CREAR USUARIO POR TIEMPO (Minutos)"
    msg -bar
    echo -e "\033[1;97m Los Usuarios que cres en esta opcion se eliminaran\n automaticamete pasando el tiempo designado.\033[0m"
    msg -bar
    echo -ne "\033[1;91m [1]- \033[1;93mDigite Nuevo Usuario:\033[1;32m " && read name
    if [[ -z $name ]]; then
      echo "No a digitado el Nuevo Usuario"
      exit
    fi
    if cat /etc/passwd | grep $name: | grep -vi [a-z]$name | grep -v [0-9]$name >/dev/null; then
      echo -e "\033[1;31mUsuario $name ya existe\033[0m"
      exit
    fi
    echo -ne "\033[1;91m [2]- \033[1;93mDigite Nueva Contraseña:\033[1;32m " && read pass
    echo -ne "\033[1;91m [3]- \033[1;93mDigite Tiempo (Minutos):\033[1;32m " && read tmp
    if [ "$tmp" = "" ]; then
      tmp="30"
      echo -e "\033[1;32mFue Definido 30 minutos Por Defecto!\033[0m"
      msg -bar
      sleep 2s
    fi
    useradd -m -s /bin/false $name
    (
      echo $pass
      echo $pass
    ) | passwd $name 2>/dev/null
    touch /tmp/$name
    tmpusr $tmp $name
    chmod 777 /tmp/$name
    touch /tmp/cmd
    chmod 777 /tmp/cmd
    echo "nohup /tmp/$name & >/dev/null" >/tmp/cmd
    /tmp/cmd 2>/dev/null 1>/dev/null
    rm -rf /tmp/cmd
    touch /etc/SCRIPT-LATAM/temp/demo-ssh/$name
    echo "senha: $pass" >>/etc/SCRIPT-LATAM/temp/demo-ssh/$name
    echo "data: ($tmp)Minutos" >>/etc/SCRIPT-LATAM/temp/demo-ssh/$name
    msg -bar2
    echo -e "\033[1;93m        ¡¡  USUARIO TEMPORAL x MINUTOS  !!\033[1;0m"
    msg -bar2
    echo -e "\033[1;97m\e[38;5;202m IP del Servidor: \033[1;32m$(meu_ip) "
    echo -e "\e[38;5;202m Usuario: \033[1;32m$name"
    echo -e "\e[38;5;202m Contraseña: \033[1;32m$pass"
    echo -e "\e[38;5;202m Minutos de Duración: \033[1;32m$tmp"
    msg -bar2
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    controlador_ssh

  }

  [[ -z ${VERY} ]] && verificar="\e[1;93m[\033[1;31m DESACTIVADO \e[1;93m]" || verificar="\e[1;93m[\033[1;32m ACTIVO \e[1;93m]"
  [[ -z ${VERY2} ]] && desbloqueo="\e[1;93m[\033[1;31m DESACTIVADO \e[1;93m]" || desbloqueo="\e[1;93m[\033[1;32m ACTIVO \e[1;93m]"
  clear && clear
  msg -bar
  msg -tit
  msg -bar
  echo -e "\e[1;93m      CONTROLADOR DE CUENTAS SSL/SSH/DROPBEAR"
  msg -bar
  echo -ne "\e[1;93m  [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;97mCREAR CUENTA" && echo -e "   \e[1;93m  [\e[1;32m2\e[1;93m]\033[1;31m > \e[1;97mCREAR CUENTA TEMP"
  echo -ne "\e[1;93m  [\e[1;32m3\e[1;93m]\033[1;31m > \e[1;97mREMOVER USUARIO" && echo -e "\e[1;93m  [\e[1;32m4\e[1;93m]\033[1;31m > \e[1;97mBLOQUEAR | DESBLOQUEAR "
  echo -ne "\e[1;93m  [\e[1;32m5\e[1;93m]\033[1;31m > \e[1;97mEDITAR CUENTA" && echo -e "  \e[1;93m  [\e[1;32m6\e[1;93m]\033[1;31m > \e[1;97mRENOVAR CUENTA"
  echo -e "\e[1;93m  [\e[1;32m7\e[1;93m]\033[1;31m > \e[1;97mDETALLES DE TODOS USUARIOS"
  echo -e "\e[1;93m  [\e[1;32m8\e[1;93m]\033[1;31m > \e[1;97mMONITOR DE USUARIOS CONECTADOS"
  echo -e "\e[1;93m  [\e[1;32m9\e[1;93m]\033[1;31m > \e[1;97mELIMINAR USUARIOS VENCIDOS"
  echo -e "\033[38;5;239m══════════════════\e[100m\e[97m  CONTROLADORES  \e[0m\e[38;5;239m══════════════════"
  echo -e "\e[1;93m [\e[1;32m10\e[1;93m]\033[1;31m > \e[1;97mREINICIAR CONTADOR DE BLOQUEADOS y EXPIRADOS"
  echo -e "\e[1;93m [\e[1;32m11\e[1;93m]\033[1;31m > \e[1;97mBACKUP USUARIOS"
  echo -e "\e[1;93m [\e[1;32m12\e[1;93m]\033[1;31m > \e[1;97mAGREGAR/ELIMINAR BANNER"
  echo -e "\e[1;93m [\e[1;32m13\e[1;93m]\033[1;31m > \e[1;97m⚠️ELIMINAR TODOS LOS USUARIOS⚠️"
  echo -e "\e[1;93m [\e[1;32m14\e[1;93m]\033[1;31m > \e[1;97m🔒 LIMITADOR-DE-CUENTAS 🔒 -- $verificar"
  echo -e "\e[1;93m [\e[1;32m15\e[1;93m]\033[1;31m > \e[1;97m🔓 DESBLOQUEO-AUTOMATICO 🔓 - $desbloqueo"
  echo -e "\e[1;93m [\e[1;32m16\e[1;93m]\033[1;31m > \e[1;97mLOG DE CUENTAS REGISTRADAS"
  echo -e "\e[1;93m [\e[1;32m17\e[1;93m]\033[1;31m > \e[1;97mLIMPIAR LOG DE LIMITADOR "
  [[ -e "/etc/SCRIPT-LATAM/temp/Limiter2.log" ]] && echo -e "\e[1;93m [\e[1;32m18\e[1;93m]\033[1;31m > \e[1;97mVER LOG DE LIMITADOR "
  msg -bar
  echo -e "    \e[97m\033[1;41m ENTER SIN RESPUESTA REGRESA A MENU ANTERIOR \033[0;97m"
  msg -bar
  echo -ne "\033[1;97m    └⊳ Seleccione una Opcion [1-18]: \033[1;32m" && read num
  msg -bar
  case "$num" in
  1) new_user ;;
  2) demo_ssh ;;
  3) remove_user ;;
  4) block_user ;;
  5) edit_user ;;
  6) renew_user ;;
  7) detail_user ;;
  8) monit_user ;;
  9) rm_vencidos ;;
  10) reset_contador ;;
  11) backup_fun ;;
  12) baner_fun ;;
  13) eliminar_all ;;
  14) verif_funx ;;
  15) verif2_funx ;;
  16) rec_total ;;
  17)
    rm -rf /etc/SCRIPT-LATAM/temp/Limiter2.log
    echo -e "\033[1;32m  LOG ELIMINADO CON EXITO"
    msg -bar

    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    controlador_ssh
    ;;
  18)
    clear && clear
    msg -bar
    sed -i -e 's/^[ \t]*//; s/[ \t]*$//; /^$/d' /etc/SCRIPT-LATAM/temp/Limiter2.log
    [[ -e "/etc/SCRIPT-LATAM/temp/Limiter2.log" ]] && {
      msg -tit
      msg -bar
      msg -ama "              REGISTRO DEL LIMITADOR "
      msg -bar
      cat /etc/SCRIPT-LATAM/temp/Limiter2.log
      msg -bar
    }
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    controlador_ssh
    ;;
  *)
    menu
    ;;
  esac

  exit 0

}

#--- MONITOR HTOP
monhtop() {
  clear && clear
  msg -bar
  msg -tit
  msg -bar
  echo -ne " \033[1;93m             MONITOR DE PROCESOS HTOP\n"
  msg -bar
  msg -bra "    RECUERDA SALIR CON : \033[1;96m CTRL + C o FIN + F10 "
  [[ $(dpkg --get-selections | grep -w "htop" | head -1) ]] || apt-get install htop -y &>/dev/null
  msg -bar
  read -t 10 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
  clear && clear
  sudo htop
  msg -bar
  msg -tit
  msg -bar
  echo -ne " \033[1;93m             MONITOR DE PROCESOS HTOP\n"
  msg -bar
  echo -e "\e[97m                  FIN DEL MONITOR"
  msg -bar
}

#--------------------------------========MONITOR DE LOGIN, CADUCIDAD Y NOTI BOT========-------------------------------------

##----PIDS DROPBEAR
dropbear_pids() {
  local pids
  local portasVAR=$(lsof -V -i tcp -P -n | grep -v "ESTABLISHED" | grep -v "COMMAND" | grep "LISTEN")
  local NOREPEAT
  local reQ
  local Port
  while read port; do
    reQ=$(echo ${port} | awk '{print $1}')
    Port=$(echo {$port} | awk '{print $9}' | awk -F ":" '{print $2}')
    [[ $(echo -e $NOREPEAT | grep -w "$Port") ]] && continue
    NOREPEAT+="$Port\n"
    case ${reQ} in
    dropbear)
      [[ -z $DPB ]] && local DPB=""
      DPB+="$Port "
      ;;
    esac
  done <<<"${portasVAR}"
  [[ ! -z $DPB ]] && echo -e $DPB
  #local port_dropbear="$DPB"
  port_drop=$(netstat -nlpt | grep -i dropbear | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2 | xargs | sed -e 's/ /, /g')
  port_dropbear="$port_drop"
  cat /var/log/auth.log | grep -a -i dropbear | grep -a -i "Password auth succeeded" >/var/log/authday.log
  #cat /var/log/auth.log|grep "$(date|cut -d' ' -f2,3)" > /var/log/authday.log
  #cat /var/log/auth.log | tail -1000 >/var/log/authday.log
  local log=/var/log/authday.log
  local loginsukses='Password auth succeeded'
  [[ -z $port_dropbear ]] && return 1
  for port in $(echo $port_dropbear); do
    for pidx in $(ps ax | grep dropbear | grep "$port" | awk -F" " '{print $1}'); do
      pids="${pids}$pidx\n"
    done
  done
  for pid in $(echo -e "$pids"); do
    pidlogs=$(grep $pid $log | grep "$loginsukses" | awk -F" " '{print $3}')
    i=0
    for pidend in $pidlogs; do
      let i++
    done
    if [[ $pidend ]]; then
      login=$(grep $pid $log | grep "$pidend" | grep "$loginsukses")
      PID=$pid
      user=$(echo $login | awk -F" " '{print $10}' | sed -r "s/'//g")
      waktu=$(echo $login | awk -F" " '{print $2"-"$1,$3}')
      [[ -z $user ]] && continue
      echo "$user|$PID|$waktu"
    fi
  done
}

##----PIDS OPENVPN
openvpn_pids() {
  #nome|#loguin|#rcv|#snd|#time
  byte() {
    while read B dummy; do
      [[ "$B" -lt 1024 ]] && echo "${B} bytes" && break
      KB=$(((B + 512) / 1024))
      [[ "$KB" -lt 1024 ]] && echo "${KB} Kb" && break
      MB=$(((KB + 512) / 1024))
      [[ "$MB" -lt 1024 ]] && echo "${MB} Mb" && break
      GB=$(((MB + 512) / 1024))
      [[ "$GB" -lt 1024 ]] && echo "${GB} Gb" && break
      echo $(((GB + 512) / 1024)) terabytes
    done
  }
  mostrar_usuariossh() {
    for u in $(cat /etc/SCRIPT-LATAM/cuentassh | cut -d'|' -f1); do
      echo "$u"
    done
  }

  for user in $(mostrar_usuariossh); do
    user="$(echo $user | sed -e 's/[^a-z0-9 -]//ig')"
    [[ ! $(sed -n "/^${user},/p" /etc/openvpn/openvpn-status.log) ]] && continue
    i=0
    unset RECIVED
    unset SEND
    unset HOUR
    while read line; do
      IDLOCAL=$(echo ${line} | cut -d',' -f2)
      RECIVED+="$(echo ${line} | cut -d',' -f3)+"
      SEND+="$(echo ${line} | cut -d',' -f4)+"
      DATESEC=$(date +%s --date="$(echo ${line} | cut -d',' -f5 | cut -d' ' -f1,2,3,4)")
      TIMEON="$(($(date +%s) - ${DATESEC}))"
      MIN=$(($TIMEON / 60)) && SEC=$(($TIMEON - $MIN * 60)) && HOR=$(($MIN / 60)) && MIN=$(($MIN - $HOR * 60))
      HOUR+="${HOR}h:${MIN}m:${SEC}s\n"
      let i++
    done <<<"$(sed -n "/^${user},/p" /etc/openvpn/openvpn-status.log)"
    RECIVED=$(echo $(echo ${RECIVED}0 | bc) | byte)
    SEND=$(echo $(echo ${SEND}0 | bc) | byte)
    HOUR=$(echo -e $HOUR | sort -n | tail -1)
    echo -e "$user|$i|$RECIVED|$SEND|$HOUR"
  done
}

notibot_expirado() {
  NOM=$(less /etc/SCRIPT-LATAM/temp/idtelegram) >/dev/null 2>&1
  ID=$(echo $NOM) >/dev/null 2>&1
  NOM2=$(less /etc/SCRIPT-LATAM/temp/vpstelegram) >/dev/null 2>&1
  VPS=$(echo $NOM2) >/dev/null 2>&1
  KEY="5179637690:AAExt2gHMurxUgfgghBdKJ6BCHg-D0Uzlt0rM"
  TIMEOUT="10"
  URL="https://api.telegram.org/bot$KEY/sendMessage"
  SONIDO="0"
  TEXTO="❗️═════ *-CUENTA-* ═════ ❗️\n▫️ *>* _$1_\n▫️ *>* VPS: *$VPS* \n🕰 ════ _- EXPIRADA -_ ════ 🕰"
  curl -s --max-time $TIMEOUT -d "parse_mode=Markdown&disable_notification=$SONIDO&chat_id=$ID&disable_web_page_preview=1&text=$(echo -e "$TEXTO")" $URL
  echo "" &>/dev/null
}
notibot_block() {
  NOM=$(less /etc/SCRIPT-LATAM/temp/idtelegram) >/dev/null 2>&1
  ID=$(echo $NOM) >/dev/null 2>&1
  NOM2=$(less /etc/SCRIPT-LATAM/temp/vpstelegram) >/dev/null 2>&1
  VPS=$(echo $NOM2) >/dev/null 2>&1
  KEY="5179637690:AAExt2gHMurxUmuJBdKJ6BCHg-D0Uzlt0rM"
  TIMEOUT="10"
  URL="https://api.telegram.org/bot$KEY/sendMessage"
  SONIDO="0"
  TEXTO="❗️═════ *-CUENTA-* ═════ ❗️\n▫️ *>* _$1_\n▫️ *>* VPS :*$VPS* \n📵 ════ _BLOQUEADA_ ════ 📵"
  curl -s --max-time $TIMEOUT -d "parse_mode=Markdown&disable_notification=$SONIDO&chat_id=$ID&disable_web_page_preview=1&text=$(echo -e "$TEXTO")" $URL
  echo "" &>/dev/null
}

#-BLOQUEO
block_userfun() {
  local USRloked="/etc/SCRIPT-LATAM/temp/userlock"
  local LIMITERLOG="/etc/SCRIPT-LATAM/temp/Limiter.log"
  local LIMITERLOG2="/etc/SCRIPT-LATAM/temp/Limiter2.log"
  if [[ $2 = "-loked" ]]; then
    [[ $(cat ${USRloked} | grep -w "$1") ]] && return 1

    pkill -u $1 &>/dev/null

  fi

  if [[ $(cat ${USRloked} | grep -w "$1") ]]; then
    usermod -U "$1" &>/dev/null
    [[ -e ${USRloked} ]] && {
      newbase=$(cat ${USRloked} | grep -w -v "$1")
      [[ -e ${USRloked} ]] && rm ${USRloked}
      for value in $(echo ${newbase}); do
        echo $value >>${USRloked}
      done
    }
    [[ -e ${LIMITERLOG} ]] && [[ $(cat ${LIMITERLOG} | grep -w "$1") ]] && {
      newbase=$(cat ${LIMITERLOG} | grep -w -v "$1")
      [[ -e ${LIMITERLOG} ]] && rm ${LIMITERLOG}
      for value in $(echo ${newbase}); do
        echo $value >>${LIMITERLOG}
        echo $value >>${LIMITERLOG}
      done
    }
    return 1
  else

    usermod -L "$1" &>/dev/null

    pkill -u $1 &>/dev/null

    # droplim=`droppids|grep -w "$1"|cut -d'|' -f2`
    # kill -9 $droplim &>/dev/null

    droplim=$(dropbear_pids | grep -w "$1" | cut -d'|' -f2)
    kill -9 $droplim &>/dev/null

    openlim=$(openvpn_pids | grep -w "$1" | cut -d'|' -f2)
    kill -9 $openlim &>/dev/null

    echo $1 >>${USRloked}
    return 0
  fi

}

verif_fun() {
  local conexao
  local limite
  local TIMEUS
  declare -A conexao
  declare -A limite
  declare -A TIMEUS
  local USRloked="/etc/SCRIPT-LATAM/temp/userlock"
  local LIMITERLOG="/etc/SCRIPT-LATAM/temp/Limiter.log"
  local LIMITERLOG2="/etc/SCRIPT-LATAM/temp/Limiter2.log"
  [[ $(dpkg --get-selections | grep -w "openssh" | head -1) ]] && local SSH=ON || local SSH=OFF
  [[ $(dpkg --get-selections | grep -w "dropbear" | head -1) ]] && local DROP=ON || local DROP=OFF
  [[ $(dpkg --get-selections | grep -w "openvpn" | head -1) ]] && [[ -e /etc/openvpn/openvpn-status.log ]] && local OPEN=ON || local OPEN=OFF

  unset EXPIRED
  unset ONLINES
  unset BLOQUEADO
  local TimeNOW=$(date +%s)
  # INICIA VERIFICAȃOINICIANDO VERIFICACION

  mostrar_usuariossh() {
    for u in $(cat /etc/SCRIPT-LATAM/cuentassh | cut -d'|' -f1); do
      echo "$u"
    done
  }
  mostrar_usuariohwid() {
    for u in $(cat /etc/SCRIPT-LATAM/cuentahwid | cut -d'|' -f1); do
      echo "$u"
    done
  }
  mostrar_usuariotoken() {
    for u in $(cat /etc/SCRIPT-LATAM/cuentatoken | cut -d'|' -f1); do
      echo "$u"
    done
  }
  [[ -e "/etc/SCRIPT-LATAM/cuentassh" ]] && usuarios_ativos1=($(mostrar_usuariossh))
  [[ -e "/etc/SCRIPT-LATAM/cuentahwid" ]] && usuarios_ativos2=($(mostrar_usuariohwid))
  [[ -e "/etc/SCRIPT-LATAM/cuentatoken" ]] && usuarios_ativos3=($(mostrar_usuariotoken))
  for us in $(echo ${usuarios_ativos1[@]}); do
    echo "${us}"
  done >/etc/SCRIPT-LATAM/cuentasactivast
  for us in $(echo ${usuarios_ativos2[@]}); do
    echo "${us}"
  done >>/etc/SCRIPT-LATAM/cuentasactivast
  for us in $(echo ${usuarios_ativos3[@]}); do
    echo "${us}"
  done >>/etc/SCRIPT-LATAM/cuentasactivast
  mostrar_totales() {
    for u in $(cat /etc/SCRIPT-LATAM/cuentasactivast | cut -d'|' -f1); do
      echo "$u"
    done
  }

  [[ -e "/etc/SCRIPT-LATAM/cuentasactivast" ]] && usuarios_totales=($(mostrar_totales))
  if [[ -z ${usuarios_totales[@]} ]]; then
    echo "" >/dev/null 2>&1
  else

    while read user; do

      ##EXPIRADOS
      local DataUser=$(chage -l "${user}" | grep -i co | awk -F ":" '{print $2}')

      if [[ ! -z "$(echo $DataUser | grep never)" ]]; then
        echo -e "\033[1;31mILIMITADO"
        continue
      fi

      local DataSEC=$(date +%s --date="$DataUser")
      if [[ "$DataSEC" -lt "$TimeNOW" ]]; then
        EXPIRED="1+"
        [[ $(cat ${USRloked} | grep -w "$user") ]] || {

          notibot_expirado $user
          echo "$user" >>/etc/SCRIPT-LATAM/temp/userexp
          echo "$user (EXPIRADO) $(date +%r--%d/%m/%y)" >>$LIMITERLOG2
          echo "USER: $user (LOKED - EXPIRED) $(date +%r)" >>$LIMITERLOG
        }
        block_userfun $user -loked
        continue
      fi

      #----CONTADOR DE ONLINES
      local PID="0+"
      [[ $SSH = ON ]] && PID+="$(ps aux | grep -v grep | grep sshd | grep -w "$user" | grep -v root | wc -l 2>/dev/null)+"
      [[ $DROP = ON ]] && PID+="$(dropbear_pids | grep -w "$user" | wc -l 2>/dev/null)+"
      [[ $OPEN = ON ]] && [[ $(openvpn_pids | grep -w "$user" | cut -d'|' -f2) ]] && PID+="$(openvpn_pids | grep -w "$user" | cut -d'|' -f2)+"
      local ONLINES+="$(echo ${PID}0 | bc)+"
      echo "${ONLINES}0" | bc >/etc/SCRIPT-LATAM/temp/USRonlines

      #----CONTADOR DE LIMITE X USER
      local conexao[$user]="$(echo ${PID}0 | bc)"
      local limite[$user]="$(cat /etc/SCRIPT-LATAM/cuentassh | grep -w "${user}" | cut -d'|' -f4)"
      [[ -z "${limite[$user]}" ]] && continue
      [[ "${limite[$user]}" != +([0-9]) ]] && continue
      if [[ "${conexao[$user]}" -gt "${limite[$user]}" ]]; then
        local lock=$(block_userfun $user -loked)
        usermod -L "$user" &>/dev/null
        notibot_block $user
        # pkill -u $user
        # droplim=$(dropbear_pids | grep -w "$user" | cut -d'|' -f2)
        # kill -9 $droplim &>/dev/null
        # openlim=$(openvpn_pids | grep -w "$user" | cut -d'|' -f2)
        # kill -9 $openlim &>/dev/null
        echo "$user (LIM-MAXIMO) $(date +%r--%d/%m/%y)" >>$LIMITERLOG
        echo "$user (LIM-MAXIMO) $(date +%r--%d/%m/%y)" >>$LIMITERLOG2
        continue
      fi

      echo "${EXPIRED}0" | bc >/etc/SCRIPT-LATAM/temp/USRexpired
    done <<<"$(mostrar_totales)"
  fi
  sed -i '/'-loked'/d' /etc/SCRIPT-LATAM/temp/userlock
  BLOQUEADO="$(wc -l /etc/SCRIPT-LATAM/temp/userlock | awk '{print $1}')"
  BLOQUEADO2="$(echo ${BLOQUEADO} | bc)0"
  BLOQUEADO3="/10"
  echo "${BLOQUEADO2}${BLOQUEADO3}" | bc >/etc/SCRIPT-LATAM/temp/USRbloqueados
  sed -i -e 's/^[ \t]*//; s/[ \t]*$//; /^$/d' /etc/SCRIPT-LATAM/temp/userexp
  EXPIRADO="$(wc -l /etc/SCRIPT-LATAM/temp/userexp | awk '{print $1}')"
  EXPIRADO2="$(echo ${EXPIRADO} | bc)0"
  EXPIRADO3="/10"
  echo "${EXPIRADO2}${EXPIRADO3}" | bc >/etc/SCRIPT-LATAM/temp/USRexpired

  clear
}

# DESBLOQUEO Y LIMPIEZA
desbloqueo_auto() {

  unlockall3() {
    for user in $(cat /etc/passwd | awk -F : '$3 > 900 {print $1}' | grep -v "rick" | grep -vi "nobody"); do
      userpid=$(ps -u $user | awk {'print $1'})

      usermod -U $user &>/dev/null
    done
  }
  mostrar_totales() {
    for u in $(cat /etc/SCRIPT-LATAM/cuentasactivast | cut -d'|' -f1); do
      echo "$u"
    done
  }
  rm_user() {
    userdel --force "$1" &>/dev/null
  }
  rm_vencidos() {

    red=$(tput setaf 1)
    gren=$(tput setaf 2)
    yellow=$(tput setaf 3)
    txtvar=$(printf '%-42s' "\e[1;97m   USUARIOS")
    txtvar+=$(printf '%-1s' "\e[1;32m  VALIDIDEZ")
    echo -e "\033[1;92m${txtvar}"

    expired="${red}Usuario Expirado"
    valid="${gren}Usuario Vigente"
    never="${yellow}Usuario Ilimitado"
    removido="${red}Eliminado"
    DataVPS=$(date +%s)
    mostrar_usuariossh() {
      for u in $(cat /etc/SCRIPT-LATAM/cuentassh | cut -d'|' -f1); do
        echo "$u"
      done
    }
    mostrar_usuariohwid() {
      for u in $(cat /etc/SCRIPT-LATAM/cuentahwid | cut -d'|' -f1); do
        echo "$u"
      done
    }
    mostrar_usuariotoken() {
      for u in $(cat /etc/SCRIPT-LATAM/cuentatoken | cut -d'|' -f1); do
        echo "$u"
      done
    }

    #---SSH NORMAL

    while read user; do
      DataUser=$(chage -l "${user}" | grep -i co | awk -F ":" '{print $2}')
      usr=$user
      while [[ ${#usr} -lt 34 ]]; do
        usr=$usr" "
      done
      [[ "$DataUser" = " never" ]] && {
        echo -e "\e[1;97m$usr $never"
        continue
      }
      DataSEC=$(date +%s --date="$DataUser")
      if [[ "$DataSEC" -lt "$DataVPS" ]]; then
        echo -ne "\e[1;97m$usr $expired"
        pkill -u $user &>/dev/null
        droplim=$(dropbear_pids | grep -w "$user" | cut -d'|' -f2)
        kill -9 $droplim &>/dev/null
        # droplim=`droppids|grep -w "$user"|cut -d'|' -f2`
        # kill -9 $droplim &>/dev/null
        rm_user "$user" && echo -e " y ($removido)"
        userb=$(cat /etc/SCRIPT-LATAM/cuentassh | grep -n -w $user | cut -d'|' -f1 | cut -d':' -f1)
        sed -i "${userb}d" /etc/SCRIPT-LATAM/cuentassh
      else
        echo -e "\e[1;97m$usr $valid"
      fi
    done <<<"$(mostrar_usuariossh)"
    #---SSH HWID
    while read user; do
      DataUser=$(chage -l "${user}" | grep -i co | awk -F ":" '{print $2}')
      usr=$user
      while [[ ${#usr} -lt 34 ]]; do
        usr=$usr" "
      done
      [[ "$DataUser" = " never" ]] && {
        echo -e "\e[1;97m$usr $never"
        continue
      }
      DataSEC=$(date +%s --date="$DataUser")
      if [[ "$DataSEC" -lt "$DataVPS" ]]; then
        echo -ne "\e[1;97m$usr $expired"
        pkill -u $user &>/dev/null
        droplim=$(dropbear_pids | grep -w "$user" | cut -d'|' -f2)
        kill -9 $droplim &>/dev/null
        # droplim=`droppids|grep -w "$user"|cut -d'|' -f2`
        # kill -9 $droplim &>/dev/null
        rm_user "$user" && echo -e " y ($removido)"
        sed -i '/'$user'/d' /etc/SCRIPT-LATAM/cuentahwid
      else
        echo -e "\e[1;97m$usr $valid"
      fi
    done <<<"$(mostrar_usuariohwid)"

    #---SSH TOKEN
    while read user; do
      DataUser=$(chage -l "${user}" | grep -i co | awk -F ":" '{print $2}')
      usr=$user
      while [[ ${#usr} -lt 34 ]]; do
        usr=$usr" "
      done
      [[ "$DataUser" = " never" ]] && {
        echo -e "\e[1;97m$usr $never"
        continue
      }
      DataSEC=$(date +%s --date="$DataUser")
      if [[ "$DataSEC" -lt "$DataVPS" ]]; then
        echo -ne "\e[1;97m$usr $expired"
        pkill -u $user &>/dev/null
        droplim=$(dropbear_pids | grep -w "$user" | cut -d'|' -f2)
        kill -9 $droplim &>/dev/null
        # droplim=`droppids|grep -w "$user"|cut -d'|' -f2`
        # kill -9 $droplim &>/dev/null
        rm_user "$user" && echo -e "y ($removido)"
        sed -i '/'$user'/d' /etc/SCRIPT-LATAM/cuentatoken
      else
        echo -e "\e[1;97m$usr $valid"
      fi
    done <<<"$(mostrar_usuariotoken)"

    rm -rf /etc/SCRIPT-LATAM/temp/userlock
    rm -rf /etc/SCRIPT-LATAM/temp/userexp
    unlockall2

  }
  unlockall3 &>/dev/null
  rm_vencidos &>/dev/null
}

#--- LIMITADOR V2RAY
lim_expv2ray() {
  expirados() {
    VPSsec=$(date +%s)
    local HOST="/etc/SCRIPT-LATAM/RegV2ray"
    local HOST2="/etc/SCRIPT-LATAM/RegV2ray"
    local RETURN="$(cat $HOST | cut -d'|' -f2)"
    local IDEUUID="$(cat $HOST | cut -d'|' -f1)"
    if [[ -z $RETURN ]]; then
      echo ""
      return 0
    else
      i=1
      while read hostreturn; do
        delbug() {
          invaliduuid() {
            exit
          }
          [[ $(sed -n '/'${hostreturn}'/=' /etc/v2ray/config.json | head -1) ]] || invaliduuid
          lineP=$(sed -n '/'${hostreturn}'/=' /etc/v2ray/config.json)
          linePre=$(sed -n '/'${hostreturn}'/=' /etc/SCRIPT-LATAM/RegV2ray)
          sed -i "${linePre}d" /etc/SCRIPT-LATAM/RegV2ray
          numl1=2
          let resta=$lineP-$numl1
          sed -i "${resta}d" /etc/v2ray/config.json
          sed -i "${resta}d" /etc/v2ray/config.json
          sed -i "${resta}d" /etc/v2ray/config.json
          sed -i "${resta}d" /etc/v2ray/config.json
          sed -i "${resta}d" /etc/v2ray/config.json
        }
        DateExp="$(cat /etc/SCRIPT-LATAM/RegV2ray | grep -w "$hostreturn" | cut -d'|' -f3)"
        if [[ ! -z $DateExp ]]; then
          DataSec=$(date +%s --date="$DateExp")
          [[ "$VPSsec" -gt "$DataSec" ]] && EXPTIME= delbug || EXPTIME="\e[92m[$(($(($DataSec - $VPSsec)) / 86400))]\e[97m Dias"
        else
          EXPTIME="\e[91m[ S/R ]"
        fi
        local contador_secuencial+="\e[93m$hostreturn \n"
        if [[ $i -gt 30 ]]; then
          echo -e "$contador_secuencial"
          unset contador_secuencial
          unset i
        fi
        let i++
      done <<<"$IDEUUID"

      [[ ! -z $contador_secuencial ]] && {
        linesss=$(cat /etc/SCRIPT-LATAM/RegV2ray | wc -l)
        echo -e "$contador_secuencial "
      }
    fi
  }
  expirados
  v2ray restart >/dev/null 2>&1

}

# LIMITADOR AUTO
if [[ "$1" = "verificar" ]]; then
  verif_fun
  exit
fi

# DESBLOQUEO AUTO
if [[ "$1" = "desbloqueo" ]]; then
  desbloqueo_auto
  exit
fi

# LIMMITADOR V2RAY
if [[ "$1" = "exlimv2ray" ]]; then
  lim_expv2ray
  exit
fi

#--- FIREWALL
firewall_fun() {

  PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
  export PATH
  declare -A cor=([0]="\033[1;37m" [1]="\033[1;34m" [2]="\033[1;31m" [3]="\033[1;33m" [4]="\033[1;32m")

  sh_ver="1.0.11"
  Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
  Info="${Green_font_prefix}[Informacion]${Font_color_suffix}"
  Error="${Red_font_prefix}[Error]${Font_color_suffix}"

  smtp_port="25,26,465,587"
  pop3_port="109,110,995"
  imap_port="143,218,220,993"
  other_port="24,50,57,105,106,158,209,1109,24554,60177,60179"
  bt_key_word="torrent
.torrent
peer_id=
announce
info_hash
get_peers
find_node
BitTorrent
announce_peer
BitTorrent protocol
announce.php?passkey=
magnet:
xunlei
sandai
Thunder
XLLiveUD"

  check_sys() {
    if [[ -f /etc/redhat-release ]]; then
      release="centos"
    elif cat /etc/issue | grep -q -E -i "debian"; then
      release="debian"
    elif cat /etc/issue | grep -q -E -i "ubuntu"; then
      release="ubuntu"
    elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
      release="centos"
    elif cat /proc/version | grep -q -E -i "debian"; then
      release="debian"
    elif cat /proc/version | grep -q -E -i "ubuntu"; then
      release="ubuntu"
    elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
      release="centos"
    fi
    bit=$(uname -m)
  }
  check_BT() {
    Cat_KEY_WORDS
    BT_KEY_WORDS=$(echo -e "$Ban_KEY_WORDS_list" | grep "torrent")
  }
  check_SPAM() {
    Cat_PORT
    SPAM_PORT=$(echo -e "$Ban_PORT_list" | grep "${smtp_port}")
  }
  Cat_PORT() {
    Ban_PORT_list=$(iptables -t filter -L OUTPUT -nvx --line-numbers | grep "REJECT" | awk '{print $13}')
  }
  Cat_KEY_WORDS() {
    Ban_KEY_WORDS_list=""
    Ban_KEY_WORDS_v6_list=""
    if [[ ! -z ${v6iptables} ]]; then
      Ban_KEY_WORDS_v6_text=$(${v6iptables} -t mangle -L OUTPUT -nvx --line-numbers | grep "DROP")
      Ban_KEY_WORDS_v6_list=$(echo -e "${Ban_KEY_WORDS_v6_text}" | sed -r 's/.*\"(.+)\".*/\1/')
    fi
    Ban_KEY_WORDS_text=$(${v4iptables} -t mangle -L OUTPUT -nvx --line-numbers | grep "DROP")
    Ban_KEY_WORDS_list=$(echo -e "${Ban_KEY_WORDS_text}" | sed -r 's/.*\"(.+)\".*/\1/')
  }
  View_PORT() {
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    Cat_PORT
    echo -e "\e[97m=========${Red_background_prefix}  Puerto Bloqueado Actualmente  ${Font_color_suffix}==========="
    echo -e "$Ban_PORT_list"
  }
  View_KEY_WORDS() {
    Cat_KEY_WORDS
    echo -e "\e[97m=============${Red_background_prefix}  Actualmente Prohibido  ${Font_color_suffix}=============="
    echo -e "$Ban_KEY_WORDS_list"
  }
  View_ALL() {
    echo
    View_PORT
    View_KEY_WORDS
    msg -bar2

    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    firewall_fun
  }
  Save_iptables_v4_v6() {
    if [[ ${release} == "centos" ]]; then
      if [[ ! -z "$v6iptables" ]]; then
        service ip6tables save
        chkconfig --level 2345 ip6tables on
      fi
      service iptables save
      chkconfig --level 2345 iptables on
    else
      if [[ ! -z "$v6iptables" ]]; then
        ip6tables-save >/etc/ip6tables.up.rules
        echo -e "#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules\n/sbin/ip6tables-restore < /etc/ip6tables.up.rules" >/etc/network/if-pre-up.d/iptables
      else
        echo -e "#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules" >/etc/network/if-pre-up.d/iptables
      fi
      iptables-save >/etc/iptables.up.rules
      chmod +x /etc/network/if-pre-up.d/iptables
    fi
  }
  Set_key_word() {
    $1 -t mangle -$3 OUTPUT -m string --string "$2" --algo bm --to 65535 -j DROP
  }
  Set_tcp_port() {
    [[ "$1" = "$v4iptables" ]] && $1 -t filter -$3 OUTPUT -p tcp -m multiport --dports "$2" -m state --state NEW,ESTABLISHED -j REJECT --reject-with icmp-port-unreachable
    [[ "$1" = "$v6iptables" ]] && $1 -t filter -$3 OUTPUT -p tcp -m multiport --dports "$2" -m state --state NEW,ESTABLISHED -j REJECT --reject-with tcp-reset
  }
  Set_udp_port() { $1 -t filter -$3 OUTPUT -p udp -m multiport --dports "$2" -j DROP; }
  Set_SPAM_Code_v4() {
    for i in ${smtp_port} ${pop3_port} ${imap_port} ${other_port}; do
      Set_tcp_port $v4iptables "$i" $s
      Set_udp_port $v4iptables "$i" $s
    done
  }
  Set_SPAM_Code_v4_v6() {
    for i in ${smtp_port} ${pop3_port} ${imap_port} ${other_port}; do
      for j in $v4iptables $v6iptables; do
        Set_tcp_port $j "$i" $s
        Set_udp_port $j "$i" $s
      done
    done
  }
  Set_PORT() {
    if [[ -n "$v4iptables" ]] && [[ -n "$v6iptables" ]]; then
      Set_tcp_port $v4iptables $PORT $s
      Set_udp_port $v4iptables $PORT $s
      Set_tcp_port $v6iptables $PORT $s
      Set_udp_port $v6iptables $PORT $s
    elif [[ -n "$v4iptables" ]]; then
      Set_tcp_port $v4iptables $PORT $s
      Set_udp_port $v4iptables $PORT $s
    fi
    Save_iptables_v4_v6
  }
  Set_KEY_WORDS() {
    key_word_num=$(echo -e "${key_word}" | wc -l)
    for ((integer = 1; integer <= ${key_word_num}; integer++)); do
      i=$(echo -e "${key_word}" | sed -n "${integer}p")
      Set_key_word $v4iptables "$i" $s
      [[ ! -z "$v6iptables" ]] && Set_key_word $v6iptables "$i" $s
    done
    Save_iptables_v4_v6
  }
  Set_BT() {
    key_word=${bt_key_word}
    Set_KEY_WORDS
    Save_iptables_v4_v6
  }
  Set_SPAM() {
    if [[ -n "$v4iptables" ]] && [[ -n "$v6iptables" ]]; then
      Set_SPAM_Code_v4_v6
    elif [[ -n "$v4iptables" ]]; then
      Set_SPAM_Code_v4
    fi
    Save_iptables_v4_v6
  }
  Set_ALL() {
    Set_BT
    Set_SPAM
  }
  Ban_BT() {
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    echo -e "\e[1;93m              PANEL DE FIREWALL LATAM"
    msg -bar
    check_BT
    [[ ! -z ${BT_KEY_WORDS} ]] && echo -e "${Error} Torrent bloqueados y Palabras Claves, no es\nnecesario volver a prohibirlas !" && msg -bar2 && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
    s="A"
    Set_BT
    View_ALL
    echo -e "${Info} Torrent bloqueados y Palabras Claves !"
    msg -bar2
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    firewall_fun
  }
  Ban_SPAM() {
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    echo -e "\e[1;93m              PANEL DE FIREWALL LATAM"
    msg -bar
    check_SPAM
    [[ ! -z ${SPAM_PORT} ]] && echo -e "${Error} Se detectó un puerto SPAM bloqueado, no es\nnecesario volver a bloquear !" && msg -bar2 && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
    s="A"
    Set_SPAM
    View_ALL
    echo -e "${Info} Puertos SPAM Bloqueados !"
    msg -bar2
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    firewall_fun
  }
  Ban_ALL() {
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    echo -e "\e[1;93m              PANEL DE FIREWALL LATAM"
    msg -bar
    check_BT
    check_SPAM
    s="A"
    if [[ -z ${BT_KEY_WORDS} ]]; then
      if [[ -z ${SPAM_PORT} ]]; then
        Set_ALL
        View_ALL
        echo -e "${Info} Torrent bloqueado, Palabras Claves y Puertos SPAM !"
        msg -bar2
      else
        Set_BT
        View_ALL
        echo -e "${Info} Torrent bloqueado y Palabras Claves !"
      fi
    else
      if [[ -z ${SPAM_PORT} ]]; then
        Set_SPAM
        View_ALL
        echo -e "${Info} Puerto SPAM (spam) prohibido !"
      else
        echo -e "${Error} Torrent Bloqueado, Palabras Claves y\n Puertos SPAM,no es necesario volver a prohibir !" && msg -bar2 && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
      fi
    fi
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    firewall_fun
  }
  UnBan_BT() {
    check_BT
    [[ -z ${BT_KEY_WORDS} ]] && echo -e "${Error} Torrent y Palabras Claves no bloqueadas, verifique !" && msg -bar2 && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
    s="D"
    Set_BT
    View_ALL
    echo -e "${Info} Torrent Desbloqueados y Palabras Claves !"
    msg -bar2
  }
  UnBan_SPAM() {
    check_SPAM
    [[ -z ${SPAM_PORT} ]] && echo -e "${Error} Puerto SPAM no detectados, verifique !" && msg -bar2 && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
    s="D"
    Set_SPAM
    View_ALL
    echo -e "${Info} Puertos de SPAM Desbloqueados !"
    msg -bar2
  }
  UnBan_ALL() {
    check_BT
    check_SPAM
    s="D"
    if [[ ! -z ${BT_KEY_WORDS} ]]; then
      if [[ ! -z ${SPAM_PORT} ]]; then
        Set_ALL
        View_ALL
        echo -e "${Info} Torrent, Palabras Claves y Puertos SPAM Desbloqueados !"
        msg -bar2
      else
        Set_BT
        View_ALL
        echo -e "${Info} Torrent, Palabras Claves Desbloqueados !"
        msg -bar2
      fi
    else
      if [[ ! -z ${SPAM_PORT} ]]; then
        Set_SPAM
        View_ALL
        echo -e "${Info} Puertos SPAM Desbloqueados !"
        msg -bar2
      else
        echo -e "${Error} No se  detectan Torrent, Palabras Claves y \nPuertos SPAM Bloqueados, verifique !" && msg -bar && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
      fi
    fi
  }
  ENTER_Ban_KEY_WORDS_type() {
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    echo -e "\e[1;93m              PANEL DE FIREWALL LATAM"
    msg -bar
    Type=$1
    Type_1=$2
    if [[ $Type_1 != "ban_1" ]]; then
      echo -e "Por favor seleccione un tipo de entrada:"
      echo ""
      echo -ne " \e[1;93m [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;97m ENTRADA MANUAL  \e[97m \n"
      echo -ne " \e[1;93m [\e[1;32m2\e[1;93m]\033[1;31m > \033[1;97m LECTURA LOCAL DE ARCHIVOS\e[97m \n"
      echo -ne " \e[1;93m [\e[1;32m3\e[1;93m]\033[1;31m > \033[1;97m LECTURA DESDE DIRECCION DE RED\e[97m \n"
      echo""
      msg -bar
      echo -ne "\e[1;97m(Por defecto: 1. Entrada manual):\033[1;92m " && read key_word_type
    fi
    [[ -z "${key_word_type}" ]] && key_word_type="1"
    if [[ ${key_word_type} == "1" ]]; then
      if [[ $Type == "ban" ]]; then
        ENTER_Ban_KEY_WORDS
      else
        ENTER_UnBan_KEY_WORDS
      fi
    elif [[ ${key_word_type} == "2" ]]; then
      ENTER_Ban_KEY_WORDS_file
    elif [[ ${key_word_type} == "3" ]]; then
      ENTER_Ban_KEY_WORDS_url
    else
      if [[ $Type == "ban" ]]; then
        ENTER_Ban_KEY_WORDS
      else
        ENTER_UnBan_KEY_WORDS
      fi
    fi
  }
  ENTER_Ban_PORT() {
    clear && clear
    msg -bar
    msg -tit
    msg -bar
    echo -e "\e[1;93m              PANEL DE FIREWALL LATAM"
    msg -bar

    echo -e "\e[1;97mIngrese el puerto que desea Bloquear"
    if [[ ${Ban_PORT_Type_1} != "1" ]]; then
      echo -e "
	${Green_font_prefix}======== Ejemplo Descripción ========${Font_color_suffix}
	
 \e[1;97m-Puerto único: 25 
 -Multipuerto: 25, 26, 465, 587 
 -Segmento de puerto: 25:587 " && echo
    fi
    msg -bar
    echo -ne "\e[1;97m(Preciona Intro y Cancela):\033[1;92m " && read PORT
    [[ -z "${PORT}" ]] && echo "Cancelado..." && View_ALL && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
  }
  ENTER_Ban_KEY_WORDS() {

    if [[ ${Type_1} != "ban_1" ]]; then
      echo ""
      echo -e "          ${Green_font_prefix}======== Ejemplo Descripción ========${Font_color_suffix}
	
 -Palabra : youtube o youtube.com o www.youtube.com
 -Palabra : .zip o .tar " && echo
    fi
    echo -ne "\e[1;97m(Intro se cancela por defecto):\033[1;92m " && read key_word
    [[ -z "${key_word}" ]] && echo "Cancelado ..." && View_ALL && echo -ne "\e[1;97m(Intro se cancela por defecto):\033[1;92m " && read portbg
  }
  ENTER_Ban_KEY_WORDS_file() {
    echo""
    echo -e "\e[1;97mIngrese el archivo local de palabras en root"
    echo -ne "\e[1;97m(Leer key_word.txt o ruta):\033[1;92m " && read key_word
    [[ -z "${key_word}" ]] && key_word="/root/key_word.txt"
    if [[ -e "${key_word}" ]]; then
      key_word=$(cat "${key_word}")
      [[ -z ${key_word} ]] && echo -e "${Error} El contenido del archivo está vacío. !" && View_ALL && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
    else
      echo -e "${Error} Archivo no encontrado ${key_word} !" && View_ALL && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
    fi
  }
  ENTER_Ban_KEY_WORDS_url() {
    echo ""
    echo -e "\e[1;97mIngrese la dirección del archivo de red de palabras \nclave que se prohibirá / desbloqueará \n(Ejemplo, http: //xxx.xx/key_word.txt)" && echo
    echo -ne "\e[1;97m(Intro se cancela por defecto):\033[1;92m " && read key_word
    [[ -z "${key_word}" ]] && echo "Cancelado ..." && View_ALL && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
    key_word=$(wget --no-check-certificate -t3 -T5 -qO- "${key_word}")
    [[ -z ${key_word} ]] && echo -e "${Error} El contenido del archivo de red está vacío o se agotó el tiempo de acceso !" && View_ALL && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
  }
  ENTER_UnBan_KEY_WORDS() {
    View_KEY_WORDS
    echo""
    echo -e "Ingrese la palabra clave que desea desbloquear" && echo
    read -e -p "(Intro se cancela por defecto):" key_word
    [[ -z "${key_word}" ]] && echo "Cancelado ..." && View_ALL && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
  }
  ENTER_UnBan_PORT() {
    msg -bar
    echo -e "Ingrese el puerto que desea desempaquetar:\n"
    echo -ne "\e[1;97m(Intro se cancela por defecto):\033[1;92m " && read PORT
    [[ -z "${PORT}" ]] && echo "Cancelado ..." && View_ALL && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
  }
  Ban_PORT() {
    s="A"
    ENTER_Ban_PORT
    Set_PORT
    echo -e "${Info} Puerto bloqueado [ ${PORT} ] !\n"
    Ban_PORT_Type_1="1"
    while true; do
      ENTER_Ban_PORT
      Set_PORT
      echo -e "${Info} Puerto bloqueado [ ${PORT} ] !\n"
    done
    View_ALL
  }
  Ban_KEY_WORDS() {
    s="A"
    ENTER_Ban_KEY_WORDS_type "ban"
    Set_KEY_WORDS
    echo -e "${Info} Palabras clave bloqueadas [ ${key_word} ] !\n"
    while true; do
      ENTER_Ban_KEY_WORDS_type "ban" "ban_1"
      Set_KEY_WORDS
      echo -e "${Info} Palabras clave bloqueadas [ ${key_word} ] !\n"
    done
    View_ALL
  }
  UnBan_PORT() {
    s="D"
    View_PORT
    [[ -z ${Ban_PORT_list} ]] && echo -e "${Error} Se detecta cualquier puerto no bloqueado !" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
    ENTER_UnBan_PORT
    Set_PORT
    echo -e "${Info} Puerto decapsulado [ ${PORT} ] !\n"
    while true; do
      View_PORT
      [[ -z ${Ban_PORT_list} ]] && echo -e "${Error} No se detecta puertos bloqueados !" && msg -bar2 && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
      ENTER_UnBan_PORT
      Set_PORT
      echo -e "${Info} Puerto decapsulado [ ${PORT} ] !\n"
    done
    View_ALL
  }
  UnBan_KEY_WORDS() {
    s="D"
    Cat_KEY_WORDS
    [[ -z ${Ban_KEY_WORDS_list} ]] && echo -e "${Error} No se ha detectado ningún bloqueo !" && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
    ENTER_Ban_KEY_WORDS_type "unban"
    Set_KEY_WORDS
    echo -e "${Info} Palabras clave desbloqueadas [ ${key_word} ] !\n"
    while true; do
      Cat_KEY_WORDS
      [[ -z ${Ban_KEY_WORDS_list} ]] && echo -e "${Error} No se ha detectado ningún bloqueo !" && msg -bar2 && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
      ENTER_Ban_KEY_WORDS_type "unban" "ban_1"
      Set_KEY_WORDS
      echo -e "${Info} Palabras clave desbloqueadas [ ${key_word} ] !\n"
    done
    View_ALL
  }
  UnBan_KEY_WORDS_ALL() {
    Cat_KEY_WORDS
    [[ -z ${Ban_KEY_WORDS_text} ]] && echo -e "${Error} No se detectó ninguna clave, verifique !" && msg -bar2 && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
    if [[ ! -z "${v6iptables}" ]]; then
      Ban_KEY_WORDS_v6_num=$(echo -e "${Ban_KEY_WORDS_v6_list}" | wc -l)
      for ((integer = 1; integer <= ${Ban_KEY_WORDS_v6_num}; integer++)); do
        ${v6iptables} -t mangle -D OUTPUT 1
      done
    fi
    Ban_KEY_WORDS_num=$(echo -e "${Ban_KEY_WORDS_list}" | wc -l)
    for ((integer = 1; integer <= ${Ban_KEY_WORDS_num}; integer++)); do
      ${v4iptables} -t mangle -D OUTPUT 1
    done
    Save_iptables_v4_v6
    View_ALL
    echo -e "${Info} Todas las palabras clave han sido desbloqueadas !"
  }
  check_iptables() {
    v4iptables=$(iptables -V)
    v6iptables=$(ip6tables -V)
    if [[ ! -z ${v4iptables} ]]; then
      v4iptables="iptables"
      if [[ ! -z ${v6iptables} ]]; then
        v6iptables="ip6tables"
      fi
    else
      echo -e "${Error} El firewall de iptables no está instalado !
Por favor, instale el firewall de iptables: 
CentOS Sistema： yum install iptables -y
Debian / Ubuntu Sistema： apt-get install iptables -y"
    fi
  }
  resetiptables() {
    msg -bar
    echo -e "\e[1;97m           Reiniciando Ipetables Espere"
    iptables -F && iptables -X && iptables -t nat -F && iptables -t nat -X && iptables -t mangle -F && iptables -t mangle -X && iptables -t raw -F && iptables -t raw -X && iptables -t security -F && iptables -t security -X && iptables -P INPUT ACCEPT && iptables -P FORWARD ACCEPT && iptables -P OUTPUT ACCEPT
    echo -e "\e[1;92m       >> IPTABLES reiniciadas con EXITO <<"
    msg -bar
    read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n'
    firewall_fun
  }
  check_sys
  check_iptables
  action=$1
  if [[ ! -z $action ]]; then
    [[ $action = "banbt" ]] && Ban_BT && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
    [[ $action = "banspam" ]] && Ban_SPAM && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
    [[ $action = "banall" ]] && Ban_ALL && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
    [[ $action = "unbanbt" ]] && UnBan_BT && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
    [[ $action = "unbanspam" ]] && UnBan_SPAM && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
    [[ $action = "unbanall" ]] && UnBan_ALL && read -t 60 -n 1 -rsp $'\033[1;39m       << Presiona enter para Continuar >>\n' && firewall_fun
  fi
  clear
  clear
  msg -bar
  msg -tit
  msg -bar
  echo -e "\e[1;93m              PANEL DE FIREWALL LATAM"
  echo -e "\033[38;5;239m═══════════════════\e[48;5;1m\e[38;5;230m  BLOQUEAR  \e[0m\e[38;5;239m═════════════════════"

  echo -e "\e[1;93m  [\e[1;32m1\e[1;93m]\033[1;31m > \e[1;97m TORRENT Y PALABRAS CLAVE"              #Ban_BT
  echo -e "\e[1;93m  [\e[1;32m2\e[1;93m]\033[1;31m > \e[1;97m PUERTOS SPAM "                         #Ban_SPAM
  echo -e "\e[1;93m  [\e[1;32m3\e[1;93m]\033[1;31m > \e[1;97m TORRENT PALABRAS CLAVE Y PUERTOS SPAM" #Ban_ALL
  echo -e "\e[1;93m  [\e[1;32m4\e[1;93m]\033[1;31m > \e[1;97m PUERTO PERSONALIZADO"                  #Ban_PORT
  echo -e "\e[1;93m  [\e[1;32m5\e[1;93m]\033[1;31m > \e[1;97m PALABRAS CLAVE PERSONALIZADAS"         #Ban_KEY_WORDS
  echo -e "\033[38;5;239m═════════════════\e[48;5;2m\e[38;5;22m  DESBLOQUEAR  \e[0m\e[38;5;239m════════════════════"
  echo -e "\e[1;93m  [\e[1;32m6\e[1;93m]\033[1;31m > \e[1;97m TORRENT Y PALABRAS CLAVE"                #UnBan_BT
  echo -e "\e[1;93m  [\e[1;32m7\e[1;93m]\033[1;31m > \e[1;97m PUERTOS SPAM"                            #UnBan_SPAM
  echo -e "\e[1;93m  [\e[1;32m8\e[1;93m]\033[1;31m > \e[1;97m TORRENT PALABRAS CLAVE Y PUERTOS SPAM"   #UnBan_ALL
  echo -e "\e[1;93m  [\e[1;32m9\e[1;93m]\033[1;31m > \e[1;97m PUERTO PERSONALIZADO"                    #UnBan_PORT
  echo -e "\e[1;93m [\e[1;32m10\e[1;93m]\033[1;31m > \e[1;97m PALABRA CLAVE PERSONALIZADAS"            #UnBan_KEY_WORDS
  echo -e "\e[1;93m [\e[1;32m11\e[1;93m]\033[1;31m > \e[1;97m TODAS LAS PALABRAS CLAVE PERSONALIZADAS" #UnBan_KEY_WORDS_ALL
  echo -e "\e[1;93m [\e[1;32m12\e[1;93m]\033[1;31m > \e[1;92m REINICIAR TOTAS LAS IPTABLES"            #UnBan_KEY_WORDS_ALL
  echo -e "\033[38;5;239m════════════════════════════════════════════════════"
  echo -e "\e[1;93m [\e[1;32m13\e[1;93m]\033[1;31m > \e[1;93m VER LA LISTA ACTUAL DE PROHIBIDOS" #View_ALL
  msg -bar
  echo -e "    \e[97m\033[1;41m ENTER SIN RESPUESTA REGRESA A MENU ANTERIOR \033[0;97m"
  msg -bar
  echo -ne "\033[1;97m   └⊳ Seleccione una opcion [0-18]: \033[1;32m" && read num
  case "$num" in
  1)
    Ban_BT
    ;;
  2)
    Ban_SPAM
    ;;
  3)
    Ban_ALL
    ;;
  4)
    Ban_PORT
    ;;
  5)
    Ban_KEY_WORDS
    ;;
  6)
    UnBan_BT
    ;;
  7)
    UnBan_SPAM
    ;;
  8)
    UnBan_ALL
    ;;
  9)
    UnBan_PORT
    ;;
  10)
    UnBan_KEY_WORDS
    ;;
  11)
    UnBan_KEY_WORDS_ALL
    ;;
  12)
    resetiptables
    ;;
  13)
    View_ALL
    ;;
  *)
    menu
    ;;
  esac
  exit 0

}

#--- ACTUALIZADOR REMOTO
actulizar_fun() {
  clear && clear
  actu_fun() {
    v1=$(curl -sSL "https://raw.githubusercontent.com/NetVPS/LATAM_Oficial/main/Version")
    echo "$v1" >/etc/SCRIPT-LATAM/temp/version_instalacion
    wget -O /etc/SCRIPT-LATAM/menu.sh https://raw.githubusercontent.com/NetVPS/LATAM_Oficial/main/Codigo-Base/menu.sh &>/dev/null
    chmod +rwx /etc/SCRIPT-LATAM/menu.sh
    wget -O /bin/rebootnb https://raw.githubusercontent.com/NetVPS/LATAM_Oficial/main/Ejecutables/rebootnb.sh &>/dev/null
    chmod +rwx /bin/rebootnb
  }
  msg -bar
  msg -tit
  msg -bar
  echo -e "\a\a\a\a\e[1;93m          >>> ACTULIZAR SCRIPT-LATAM <<< "
  msg -bar
  echo -e "\e[1;97m Cambios Actuales"
  registro=$(curl -sSL "https://raw.githubusercontent.com/NetVPS/LATAM_Oficial/main/cambios")
  echo -ne "$registro"
  echo ""
  echo -e "\e[1;97m Proceder con la Actulizacion?"
  msg -bar
  echo -ne "\033[1;97m Seleccione  \033[1;31m[\033[1;93m S \033[1;31m/\033[1;93m N \033[1;31m]\033[1;97m: \033[1;93m" && read tu_ip
  [[ "$tu_ip" = "s" || "$tu_ip" = "S" ]] && actu_fun &>/dev/null && tput cuu1 && tput dl1 && echo -e " \e[1;32m             >> ACTUALIZACION COMPLETA <<" | pv -qL 10
  msg -bar
}

[[ ! -e /etc/SCRIPT-LATAM/temp/version_instalacion ]] && echo 1 >/etc/SCRIPT-LATAM/temp/version_instalacion
v11=$(cat /etc/SCRIPT-LATAM/temp/version_actual)
v22=$(cat /etc/SCRIPT-LATAM/temp/version_instalacion)
[[ $v11 = $v22 ]] && checkver="\e[1;32m---------| ACTUALIZAR SCRIPT |-----------" || checkver="\e[1;31m----------| ACTUALIZAR SCRIPT |----------"
#MENU PRINCIPAL
echo -e "\033[38;5;239m═══════════════\e[100m\e[97m  CONTROL DE CUENTAS  \e[0m\e[38;5;239m═══════════════"
echo -ne "\e[1;93m  [\e[1;32m1\e[1;93m]\033[1;31m >\e[1;38;5;220m SSH/OPENVPN \e[1;97m|\e[0;97m" && echo -ne "\e[1;93m [\e[1;32m2\e[1;93m]\033[1;31m >\e[1;38;5;220m SS/SSR \e[1;97m|\e[0;97m" && echo -ne "\e[1;93m [\e[1;32m3\e[1;93m]\033[1;31m >\e[1;38;5;220m V2RAY\e[0;97m\n"
echo -e "\e[38;5;239m════════════════════════════════════════════════════"
echo -ne "\e[1;93m  [\e[1;32m4\e[1;93m]\033[1;31m > \e[1;97mINSTALAR PROTOCOLOS\e[0;97m " && echo -ne "\e[1;93m[\e[1;32m5\e[1;93m]\033[1;31m >\e[38;5;76m PUERTOS ACTIVOS \e[0;97m\n"
echo -ne "\e[1;93m  [\e[1;32m6\e[1;93m]\033[1;31m > \e[1;97mHERRAMIENTAS       \e[97m " && echo -ne "\e[1;93m[\e[1;32m7\e[1;93m]\033[1;31m >\e[38;5;42m MONITOR HTOP \e[0;97m\n"
echo -ne "\e[1;93m  [\e[1;32m8\e[1;93m]\033[1;31m > \e[1;97mAJUSTES BASICOS DE FIREWALL\e[97m \n"
echo -ne "\e[1;93m  [\e[1;32m9\e[1;93m]\033[1;31m > \e[1;97mMONITOR DE PROTOCOLOS ----------> ${monitorservi}  \e[97m \n"
echo -ne "\e[1;93m [\e[1;32m10\e[1;93m]\033[1;31m > \e[1;97mAUTO MANTENIMIENTO -------------> ${autolim}  \e[97m \n"
echo -ne "\e[1;93m [\e[1;32m11\e[1;93m]\033[1;31m > \e[1;97mAUTO INICIAR SCRIPT ------------> $AutoRun  \e[97m \n"
echo -ne "\e[1;93m [\e[1;32m12\e[1;93m]\033[1;31m > \e[1;32m$checkver\n"
#msg -bar
echo -ne "\e[1;93m [\e[1;32m13\e[1;93m]\033[1;31m > \e[1;90m-------| TERMINOS Y CONDICIONES |-------- \n"
msg -bar
echo -ne "\e[1;93m [\e[1;32m14\e[1;93m]\033[1;31m > |-DESINSTALAR-|   " && echo -ne "\e[1;93m  [\e[1;32m0\e[1;93m]\033[1;31m > \033[1;41m  ❗️\e[1;97m SALIR ❗️  \e[0m\n"
msg -bar
selection=$(selection_fun 14)
case ${selection} in
1) controlador_ssh ;;
2) controlador_ssr ;;
3) control_v2ray ;;
4) menu_inst ;;
5) mine_port ;;
6) herramientas_fun ;;
7) monhtop ;;
8) firewall_fun ;;
9) monservi_fun ;;
10) autolimpieza_fun ;;
11) fun_autorun ;;
12) actulizar_fun ;;
13) creditoss ;;
14) remove_script ;;
0)
  cd $HOME && clear
  clear
  exit 0
  ;;
esac
#msg -ne "Enter Para Continuar" && read enter
${SCPdir}/menu.sh
