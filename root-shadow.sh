#!/bin/bash 


# Colours (macOS + Linux compatible)
greenColour="\033[0;32m\033[1m"  # \033 en lugar de \e
endColour="\033[0m"              # Simplificado (no necesita \e[0m)
redColour="\033[0;31m\033[1m"
blueColour="\033[0;34m\033[1m"
yellowColour="\033[0;33m\033[1m"
purpleColour="\033[0;35m\033[1m"
turquoiseColour="\033[0;36m\033[1m"
grayColour="\033[0;37m\033[1m"

#Ctrl+C 
function ctrl_c(){
  echo -e "\n\n${redColour}[+] Leaving...${endColour}\n"
  exit 1
}

trap ctrl_c INT


banner="${purpleColour}$(cat << "EOF"  

        ______________________________   _____________  __________________________       __
        ___  __ \_  __ \_  __ \__  __/   __  ___/__  / / /__    |__  __ \_  __ \_ |     / /
        __  /_/ /  / / /  / / /_  /      _____ \__  /_/ /__  /| |_  / / /  / / /_ | /| / / 
        _  _, _// /_/ // /_/ /_  /       ____/ /_  __  / _  ___ |  /_/ // /_/ /__ |/ |/ /  
        /_/ |_| \____/ \____/ /_/        /____/ /_/ /_/  /_/  |_/_____/ \____/ ____/|__/   
                                                                                                                                                                     
                                       -=[ by r4venn ]=-                                        


EOF
)${endColour}"



function logs_enum(){
  echo -e "\n${grayColour}[+] Interesting Logs:${endColour}"
  ls -lah /var/log 2>/dev/null
  find /var/log -type f -name "*.log" 2>/dev/null | xargs -I{} tail -n 20 {} 2>/dev/null
}

function interesting_bins(){
  for bin in nc python perl ruby gcc wget curl nmap find awk vi vim tar less more socat php lua; do
    if command -v $bin &>/dev/null; then
      echo -e "[*] Found: $bin"
    fi
  done
}

user=$(whoami)


function system_enum() {
  local separator="\n${purpleColour}$(printf '=%.0s' {1..100})${endColour}"

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Kernel & Linux OS Version${endColour}$separator"
  uname -a
  [ -f /etc/os-release ] && cat /etc/os-release || cat /etc/*-release 2>/dev/null
  echo -e "\nCurrent runlevel: $(runlevel 2>/dev/null)"

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Loaded Kernel Modules${endColour}$separator"
  lsmod 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Kernel Boot Parameters${endColour}$separator"
  [ -f /proc/cmdline ] && cat /proc/cmdline

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Kernel Sysctl Settings${endColour}$separator"
  sysctl -a 2>/dev/null | grep -E "kernel|fs.suid_dumpable|core_pattern" | grep -vE '^(net|vm)'

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Kernel Symbols (if readable)${endColour}$separator"
  [ -r /proc/kallsyms ] && head -n 10 /proc/kallsyms || echo "Access to /proc/kallsyms denied"
}

function env_enum() {
  local separator="\n${purpleColour}$(printf '=%.0s' {1..100})${endColour}"
  local current_user=$(whoami)

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Current User & PATH${endColour}$separator"
  echo "[+] Current User: $current_user"
  echo "[+] UID: $(id -u) | GID: $(id -g) | Groups: $(id)"
  echo "[+] PATH: $PATH"

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Environment Variables${endColour}$separator"
  printenv | sort

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Shells Configured on System${endColour}$separator"
  [ -f /etc/shells ] && cat /etc/shells || echo "Shells file not found"

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Python Path (PYTHONPATH)${endColour}$separator"
  python3 -c 'import sys; print("\n".join(sys.path))' 2>/dev/null || echo "Python3 not found"

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Files not owned by user but writable by group${endColour}$separator"
  find / -writable ! -user "$(whoami)" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Files owned by our user${endColour}$separator"
  find / -user "$(whoami)" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Temp File Locations${endColour}$separator"
  ls -l /tmp /var/tmp /dev/shm

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Hidden Files Owned by Current User${endColour}$separator"
  find / -type f -name ".*" -user "$current_user" -ls 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Hidden Files not in /proc or /sys${endColour}$separator"
  find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Hidden Directories${endColour}$separator"
  find / -type d -name ".*" -ls 2>/dev/null
}

function user_group_enum() {
  local separator="\n${purpleColour}$(printf '=%.0s' {1..100})${endColour}"

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Users that have previoulsy logged onto the system${endColour}$separator"
  lastlog 2>/dev/null | grep -v "Never" 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Existing Local Users${endColour}$separator"
  grep -E "/home|/bin/bash" /etc/passwd
  sleep 2

  echo -e "$separator\n\t\t\t\t\t${purpleColour}User Login Shells${endColour}$separator"
  awk -F: '{print $1 ": " $7}' /etc/passwd | grep -E "sh$"

  echo -e "$separator\n\t\t\t\t\t${purpleColour}System Groups & Members${endColour}$separator"
  getent group | awk -F: '$4' | column -t -s ":"
  for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null); do id $i; done 2>/dev/null

  readmasterpasswd=$(cat /etc/master.passwd 2>/dev/null)
  if [ "$readmasterpasswd" ]; then 
    echo -e "$separator\n\t\t\t\t\t${purpleColour}We can read master passwd file!${endColour}$separator"
    $readmasterpasswd
  fi

  superman=$(grep -v -E "^#" /etc/passwd 2>/dev/null | awk -F: '$3 == 0 { print $1 }' 2>/dev/null)
  if [ "$superman" ]; then
    echo -e "$separator\n\t\t\t\t\t${purpleColour}Super users account(s)${endColour}$separator"
    $superman
  fi 

  sudoers=$(grep -v -E "^#" /etc/passwd 2>/dev/null | awk -F: '$3 == 0 { print $1 }' 2>/dev/null)
  if [ "$sudoers" ]; then 
    echo -e "$separator\n\t\t\t\t\t${purpleColour}Sudoers Configuration${endColour}$separator"
    $sudoers
  fi 

  sudoperms=$(echo '' | sudo -S -l -k 2>/dev/null)
  if [ "$sudoperms" ]; then 
    echo -e "$separator\n\t\t\t\t\t${purpleColour}We can sudo without password!${endColour}$separator"
    $sudoperms
  fi 

  whohasbeensudo=$(find /home -name .sudo_as_admin_successful 2>/dev/null)
  if [ "$whohasbeensudo" ]; then  
    echo -e "$separator\n\t\t\t\t\t${purpleColour}Accounts that recently used sudo${endColour}$separator"
    $whohasbeensudo
  fi 
}

function job_tasks_enum() {
  local separator="\n${purpleColour}$(printf '=%.0s' {1..100})${endColour}"

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Cron Jobs${endColour}$separator"
  cat /etc/crontab 2>/dev/null
  ls -la /etc/cron* 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Timers and Services (SystemD)${endColour}$separator"
  systemctl list-timers --all 2>/dev/null
  systemctl list-units --type=service --state=running 2>/dev/null
}

function networking_enum() {
  local separator="\n${purpleColour}$(printf '=%.0s' {1..100})${endColour}"

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Connected Routes & Interfaces${endColour}$separator"
  ip a 2>/dev/null || ifconfig 2>/dev/null
  echo -e "\nRouting Table:"
  route -n 2>/dev/null || ip route 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}DNS Resolver Configuration${endColour}$separator"
  cat /etc/resolv.conf 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Hosts known (Comunication)${endColour}$separator"
  arp a 2>/dev/null || echo "ARP command not available"
}

function services_enum() {
  local separator="\n${purpleColour}$(printf '=%.0s' {1..100})${endColour}"

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Docker Images${endColour}$separator"
  docker image ls 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Logrotate Configuration${endColour}$separator"
  cat /etc/logrotate.conf

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Status File for Logrotate${endColour}$separator"
  sudo cat /var/lib/logrotate.status

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Logrotate Version${endColour}$separator"
  logrotate --version
  echo -e "\n[+] ${grayColour} Vulnerable Versions:\n${endColour}${redColour}\t- 3.4.6\n\t- 3.11.0\n\t- 3.15.0\n\t- 3.18.0${endColour}"

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Corresponding Configurations${endColour}$separator"
  ls /etc/logrotate.d/
  cat /etc/logrotate.d/dpkg

  echo -e "$separator\n\t\t\t\t\t${purpleColour}List Mounts${endColour}$separator"
  showmount -e $(ip a | grep tun0 | tail -n 1 | awk '{print $2}' | awk '{print $1}' FS="/")

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Selected Options (/etc/exports)${endColour}$separator"
  cat /etc/exports
}

function permissions_enum() {
  local gtfobins_file="./wordlists/gtfobins.txt"
  local separator="\n${purpleColour}$(printf '=%.0s' {1..100})${endColour}"

  echo -e "$separator\n\t\t\t\t\t${purpleColour}SUID binaries owned by root${endColour}$separator"
  find / -type f -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}SUID+SGID binaries (perm 6000)${endColour}$separator"
  find / -type f -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}All Existing Capabilities For All Binary Executables on Linux System${endColour}$separator"
  find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;

  echo -e "$separator\n\t\t\t\t\t${purpleColour}World-writable files/folders${endColour}$separator"
  find / -type f -perm -2 -ls 2>/dev/null | grep -v "Permission denied"
  find / -type d -perm -2 -ls 2>/dev/null | grep -v "Permission denied"

  if [ -f "$gtfobins_file" ]; then
    echo -e "$separator\n\t\t\t\t\t${purpleColour}Offline GTFOBins Match (SUID)${endColour}$separator"
    for bin in $(find / -perm -4000 -type f 2>/dev/null); do
      basebin=$(basename "$bin")
      if grep -qx "$basebin" "$gtfobins_file"; then
        echo -e "${greenColour}[GTFO]${endColour} Potential privesc: $bin"
      fi
    done
  else
    echo -e "${redColour}[!] Missing GTFOBins file at: $gtfobins_file${endColour}"
    echo -e "${yellowColour}[-] Please place it in ./wordlists/gtfobins.txt${endColour}"
  fi
}

function software_enum() {
  local separator="\n${purpleColour}$(printf '=%.0s' {1..100})${endColour}"

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Compiler Binaries Available${endColour}$separator"
  for bin in gcc clang cc g++ make ld; do
    if command -v $bin &>/dev/null; then
      echo "[+] $bin found: $(command -v $bin)"
    fi
  done

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Linked Shared Libraries (Dynamic Linker)${endColour}$separator"
  ldd --version 2>/dev/null | head -n 1
  find /lib /lib64 /usr/lib /usr/lib64 -type f -name "libc.so.*" 2>/dev/null
}



function options() {
  echo -e "${redColour}▌ 1 ▐${endColour} System"
  echo -e "${redColour}▌ 2 ▐${endColour} Environment"
  echo -e "${redColour}▌ 3 ▐${endColour} User / Group" 
  echo -e "${redColour}▌ 4 ▐${endColour} Permissions"
  echo -e "${redColour}▌ 6 ▐${endColour} Job / Tasks"
  echo -e "${redColour}▌ 6 ▐${endColour} Networking"
  echo -e "${redColour}▌ 7 ▐${endColour} Services"
  echo -e "${redColour}▌ 8 ▐${endColour} Software"
}


function select-options(){
  echo -e "$banner"
  echo -e "\n$(for in in $(seq 1 100); do echo -n '='; done)"
  echo -e "                                       E N U M E R A T E"
  echo -e "$(for in in $(seq 1 100); do echo -n '='; done)"

  #echo -e "\n${cyanColour}$(for i in $(seq 1 45); do echo -n "-"; done)[::] Select an option [::]$(for i in $(seq 1 45); do echo -n '-'; done)${endColour}\n\n"
  echo -e "\n[+] ${grayColour}Select an option:${endColour}\n"
  options 
  echo -ne "\n${purpleColour}[~]${endColour} ${grayColour}Select: ${endColour}"
  read output_show

  if [[ $output_show -eq 1 ]]; then
    system_enum
  elif [[ $output_show -eq 2 ]]; then 
    env_enum
  elif [[ $output_show -eq 3 ]]; then 
     user_group_enum
  elif [[ $output_show -eq 4 ]]; then 
    permissions_enum
  elif [[ $output_show -eq 5 ]]; then 
    job_tasks_enum
  elif [[ $output_show -eq 6 ]]; then 
    networking_enum
  elif [[ $output_show -eq 7 ]]; then
    services_enum
  elif [[ $output_show -eq 8 ]]; then
    software_enum
    
  else 
    echo -e "${redColour}[!] You have to select a number! [1-4]${endColour}"
  fi 


}



function helpPanel(){
  echo -e "$banner"
  echo -e "\n$(for in in $(seq 1 100); do echo -n '='; done)"
  echo -e "                                           Help Panel"
  echo -e "$(for in in $(seq 1 100); do echo -n '='; done)"
  echo -e "\n${yellowColour}[+]${endColour} ${grayColour}Usage${endColour}: \n\t${greenColour}$0 [options] [arguments]${endColour}"
  echo -e "\n${yellowColour}[+]${endColour} ${grayColour}Options${endColour}:"
  echo -e "\t${blueColour}-e${endColour}\t-${grayColour}Show Enumeration Options${endColour}"
  echo -e "\n${yellowColour}[+]${endColour} ${grayColour}Examples:${endColour}"
  echo -e "\t${greenColour}$0 -e${endColour}" 
  local separator="\n$(printf '=%.0s' {1..100})"
  echo -e "$separator\n\t\t\t\t\tModules Overview$separator\n"


  echo -e "\t${purpleColour}ENVIRONMENT ENUMERATION${endColour}"
  echo -e "\t\t[+] ${turquoiseColour}User Path ${endColour}${redColour}|${endColour}${turquoiseColour} Env vars ${endColour}${redColour}|${endColour}${turquoiseColour} CPU ${endColour}${redColour}|${endColour}${turquoiseColour} Shells ${endColour}${redColour}|${endColour}${turquoiseColour} Mounted/Unmounted Filesystems ${endColour}"
  echo -e "\t\t[+] ${turquoiseColour}Network Info (Interfaces, Routes, DNS) ${endColour}${redColour}|${endColour}${turquoiseColour} Users ${endColour}${redColour}|${endColour}${turquoiseColour} Groups${endColour}${redColour}|${endColour}${turquoiseColour} Hidden Files ${endColour}"
  
  echo -e "\n\t${purpleColour}LINUX INTERNALS ENUMERATION${endColour}"
  echo -e "\t\t[+] ${turquoiseColour}Kernel Version ${endColour}${redColour}|${endColour}${turquoiseColour} Boot Parameters ${endColour}${redColour}|${endColour}${turquoiseColour} Loaded Modules${endColour}${redColour}| ${endColour}${turquoiseColour} Systctl Settings ${endColour}"
  echo -e "\t\t[+] ${turquoiseColour}Available Compilers ${endColour}${redColour}|${endColour}${turquoiseColour} libc versions ${endColour}${redColour}|${endColour}${turquoiseColour} Linker Configs ${endColour}"
  
  echo -e "\n\t${purpleColour}PERMISSIONS ENUMERATION${endColour}"
  echo -e "\t\t[+] ${turquoiseColour}SUID/SGID Binaries ${endColour}${redColour}|${endColour}${turquoiseColour} Capabilities ${endColour}${redColour}|${endColour}${turquoiseColour} World/User Writable Files ${endColour}"
  echo -e "\t\t[+] ${turquoiseColour}Offline GTFOBins correlation (local privilege escalation paths)${endColour}"

  echo -e "\n\t${purpleColour}SERVICES ENUMERATION${endColour}"
  echo -e "\t\t[+] ${turquoiseColour}Docker images ${endColour}${redColour}|${endColour}${turquoiseColour} Logrotate Configs & Versions ${endColour}${redColour}|${endColour}${turquoiseColour} NFS mounts${endColour}${redColour}|${endColour}${turquoiseColour} Writeable Paths ${endColour}"
  echo -e "\t\t[+] ${turquoiseColour}Mounted Shares and Exposed Services Configuration ${endColour}"
 
}





declare -i paremeter_counter=0

while getopts "eh" arg; do 
  case $arg in 
    e) let paremeter_counter+=1;;
    h) ;;
  esac 
done 

if [ $paremeter_counter -eq 1 ]; then 
  select-options
else
  helpPanel
fi
