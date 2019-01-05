#!/bin/bash

TMP_FOLDER=$(mktemp -d)
CONFIG_FILE="pegasus.conf"
BINARY_FILE="/usr/local/bin/pegasusd"
CROP_REPO="https://github.com/Cropdev/CropDev.git"
COIN_TGZ='https://www.dropbox.com/s/eso8rf9vqunsmqn/pegasusd.gz'

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'


function compile_error() {
if [ "$?" -gt "0" ];
 then
  echo -e "${RED}Failed to compile $@. Please investigate.${NC}"
  exit 1
fi
}


function checks() {
if [[ $(lsb_release -d) != *16.04* ]]; then
  echo -e "${RED}You are not running Ubuntu 16.04. Installation is cancelled.${NC}"
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}$0 must be run as root.${NC}"
   exit 1
fi

if [ -n "$(pidof pegasusd)" ]; then
  echo -e "${GREEN}\c"
  read -e -p "pegasusd is already running. Do you want to add another MN? [Y/N]" NEW_PEG
  echo -e "{NC}"
  clear
else
  NEW_PEG="new"
fi
}

function prepare_system() {

echo -e "Prepare the system to install pegasus master node."
apt-get update >/dev/null 2>&1
DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y -qq upgrade >/dev/null 2>&1
apt install -y software-properties-common >/dev/null 2>&1
echo -e "${GREEN}Adding bitcoin PPA repository"
apt-add-repository -y ppa:bitcoin/bitcoin >/dev/null 2>&1
echo -e "Installing required packages, it may take some time to finish.${NC}"
apt-get update >/dev/null 2>&1
apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" make software-properties-common \
build-essential libtool autoconf libssl-dev libboost-dev libboost-chrono-dev libboost-filesystem-dev libboost-program-options-dev \
libboost-system-dev libboost-test-dev libboost-thread-dev sudo automake git wget pwgen curl libdb4.8-dev bsdmainutils \
libdb4.8++-dev libminiupnpc-dev libgmp3-dev ufw pwgen
clear
if [ "$?" -gt "0" ];
  then
    echo -e "${RED}Not all required packages were installed properly. Try to install them manually by running the following commands:${NC}\n"
    echo "apt-get update"
    echo "apt -y install software-properties-common"
    echo "apt-add-repository -y ppa:bitcoin/bitcoin"
    echo "apt-get update"
    echo "apt install -y make build-essential libtool software-properties-common autoconf libssl-dev libboost-dev libboost-chrono-dev libboost-filesystem-dev \
libboost-program-options-dev libboost-system-dev libboost-test-dev libboost-thread-dev sudo automake git pwgen curl libdb4.8-dev \
bsdmainutils libdb4.8++-dev libminiupnpc-dev libgmp3-dev ufw"
 exit 1
fi

clear
echo -e "Checking if swap space is needed."
PHYMEM=$(free -g|awk '/^Mem:/{print $2}')
SWAP=$(swapon -s)
if [[ "$PHYMEM" -lt "2" && -z "$SWAP" ]];
  then
    echo -e "${GREEN}Server is running with less than 2G of RAM, creating 2G swap file.${NC}"
    dd if=/dev/zero of=/swapfile bs=1024 count=2M
    chmod 600 /swapfile
    mkswap /swapfile
    swapon -a /swapfile
else
  echo -e "${GREEN}The server running with at least 2G of RAM, or SWAP exists.${NC}"
fi
clear
}

function deploy_binaries() {
  cd $TMP
  wget -q $COIN_TGZ >/dev/null 2>&1
  gunzip pegasusd.gz >/dev/null 2>&1
  chmod +x pegasusd >/dev/null 2>&1
  cp pegasusd /usr/local/bin/ >/dev/null 2>&1
}

function ask_permission() {
 echo -e "${RED}I trust vol and want to use binaries compiled on his server.${NC}."
 echo -e "Please type ${RED}YES${NC} if you want to use precompiled binaries, or type anything else to compile them on your server"
 read -e VOL
}

function compile_pegasus() {
  echo -e "Clone git repo and compile it. This may take some time. Press a key to continue."
  read -n 1 -s -r -p ""

  git clone $PEG_REPO $TMP_FOLDER
  cd $TMP_FOLDER/src
  mkdir obj/support
  mkdir obj/crypto
  make -f makefile.unix
  compile_error pegasus
  cp -a pegasusd $BINARY_FILE
  clear
}

function enable_firewall() {
  echo -e "Installing and setting up firewall to allow incomning access on port ${GREEN}$PEGASUSPORT${NC}"
  ufw allow $PEGASUSPORT/tcp comment "pegasus MN port" >/dev/null
  ufw allow $[PEGASUSPORT+1]/tcp comment "pegasus RPC port" >/dev/null
  ufw allow ssh >/dev/null 2>&1
  ufw limit ssh/tcp >/dev/null 2>&1
  ufw default allow outgoing >/dev/null 2>&1
  echo "y" | ufw enable >/dev/null 2>&1
}

function systemd_pegasus() {
  cat << EOF > /etc/systemd/system/$PEGASUSUSER.service
[Unit]
Description=pegasus service
After=network.target

[Service]

Type=forking
User=$PEGASUSUSER
Group=$PEGASUSUSER
WorkingDirectory=$PEGASUSHOME
ExecStart=$BINARY_FILE -daemon
ExecStop=$BINARY_FILE stop

Restart=always
PrivateTmp=true
TimeoutStopSec=60s
TimeoutStartSec=10s
StartLimitInterval=120s
StartLimitBurst=5

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  sleep 3
  systemctl start $PEGASUSUSER.service
  systemctl enable $PEGASUSUSER.service >/dev/null 2>&1

  if [[ -z $(pidof pegasusd) ]]; then
    echo -e "${RED}pegasusd is not running${NC}, please investigate. You should start by running the following commands as root:"
    echo "systemctl start $PEGASUSUSER.service"
    echo "systemctl status $PEGASUSUSER.service"
    echo "less /var/log/syslog"
    exit 1
  fi
}

function ask_port() {
DEFAULTPEGASUSPORT=17720
read -p "PEGASUS Port: " -i $DEFAULTPEGASUSPORT -e PEGASUSPORT
: ${PEGASUSPORT:=$DEFAULTPEGASUSPORT}
}

function ask_user() {
  DEFAULTPEGASUSUSER="pegasus"
  read -p "pegasus user: " -i $DEFAULTPEGASUSUSER -e PEGASUSUSER
  : ${PEGASUSUSER:=$DEFAULTPEGASUSUSER}

  if [ -z "$(getent passwd $PEGASUSUSER)" ]; then
    useradd -m $PEGASUSUSER
    USERPASS=$(tr -cd '[:alnum:]' < /dev/urandom | fold -w12 | head -n1)
    echo "$PEGASUSUSER:$USERPASS" | chpasswd

    PEGASUSHOME=$(sudo -H -u $PEGASUSUSER bash -c 'echo $HOME')
    DEFAULTPEGASUSFOLDER="$PEGASUSHOME/.pegasus"
    read -p "Configuration folder: " -i $DEFAULTPEGASUSFOLDER -e PEGASUSFOLDER
    : ${PEGASUSFOLDER:=$DEFAULTPEGASUSFOLDER}
    mkdir -p $PEGASUSFOLDER
    chown -R $PEGASUSUSER: $PEGASUSFOLDER >/dev/null
  else
    clear
    echo -e "${RED}User exits. Please enter another username: ${NC}"
    ask_user
  fi
}

function check_port() {
  declare -a PORTS
  PORTS=($(netstat -tnlp | awk '/LISTEN/ {print $4}' | awk -F":" '{print $NF}' | sort | uniq | tr '\r\n'  ' '))
  ask_port

  while [[ ${PORTS[@]} =~ $PEGASUSPORT ]] || [[ ${PORTS[@]} =~ $[PEGASUSPORT+1] ]]; do
    clear
    echo -e "${RED}Port in use, please choose another port:${NF}"
    ask_port
  done
}

function create_config() {
  RPCUSER=$(tr -cd '[:alnum:]' < /dev/urandom | fold -w10 | head -n1)
  RPCPASSWORD=$(tr -cd '[:alnum:]' < /dev/urandom | fold -w22 | head -n1)
  cat << EOF > $PEGASUSFOLDER/$CONFIG_FILE
rpcuser=$RPCUSER
rpcpassword=$RPCPASSWORD
rpcallowip=127.0.0.1
rpcport=$[PEGASUSPORT+1]
listen=1
server=1
daemon=1
port=$PEGASUSPORT
EOF
}

function create_key() {
  echo -e "Enter your ${RED}Masternode Private Key${NC}. Leave it blank to generate a new ${RED}Masternode Private Key${NC} for you:"
  read -e PEGASUSKEY
  if [[ -z "$PEGASUSKEY" ]]; then
  sudo -u $PEGASUSUSER /usr/local/bin/pegasusd -conf=$PEGASUSFOLDER/$CONFIG_FILE -datadir=$PEGASUSFOLDER
  sleep 5
  if [ -z "$(pidof pegasusd)" ]; then
   echo -e "${RED}pegasusd server couldn't start. Check /var/log/syslog for errors.{$NC}"
   exit 1
  fi
 PEGASUSKEY=$(sudo -u $PEGASUSUSER $BINARY_FILE -conf=$PEGASUSFOLDER/$CONFIG_FILE -datadir=$PEGASUSFOLDER masternode genkey)
  sudo -u $PEGASUSUSER $BINARY_FILE -conf=$PEGASUSFOLDER/$CONFIG_FILE -datadir=$PEGASUSFOLDER stop
fi
}

function update_config() {
  sed -i 's/daemon=1/daemon=0/' $PEGASUSFOLDER/$CONFIG_FILE
  NODEIP=$(curl -s4 api.ipify.org)
  cat << EOF >> $PEGASUSFOLDER/$CONFIG_FILE
logtimestamps=1
maxconnections=256
masternode=1
masternodeaddr=$NODEIP:$PEGASUSPORT
masternodeprivkey=$PEGASUSKEY
EOF
  chown -R $PEGASUSUSER: $PEGASUSFOLDER >/dev/null
}

function important_information() {
 echo
 echo -e "================================================================================================================================"
 echo -e "pegasus Masternode is up and running as user ${GREEN}$PEGASUSUSER${NC} and it is listening on port ${GREEN}$PEGASUSPORT${NC}."
 echo -e "${GREEN}$PEGASUSUSER${NC} password is ${RED}$USERPASS${NC}"
 echo -e "Configuration file is: ${RED}$PEGASUSFOLDER/$CONFIG_FILE${NC}"
 echo -e "Start: ${RED}systemctl start $PEGASUSUSER.service${NC}"
 echo -e "Stop: ${RED}systemctl stop $PEGASUSUSER.service${NC}"
 echo -e "VPS_IP:PORT ${RED}$NODEIP:$PEGASUSPORT${NC}"
 echo -e "MASTERNODE PRIVATEKEY is: ${RED}$PEGASUSKEY${NC}"
 echo -e "================================================================================================================================"
}

function setup_node() {
  ask_user
  check_port
  create_config
  create_key
  update_config
  enable_firewall
  systemd_pegasus
  important_information
}


##### Main #####
clear

checks
if [[ ("$NEW_PEG" == "y" || "$NEW_PEG" == "Y") ]]; then
  setup_node
  exit 0
elif [[ "$NEW_PEG" == "new" ]]; then
  prepare_system
  ask_permission
  if [[ "$VOL" == "YES" ]]; then
    deploy_binaries
  else
    compile_pegasus
  fi
  setup_node
else
  echo -e "${GREEN}pegasus already running.${NC}"
  exit 0
fi
