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



user=$(whoami)


function system_enum() {
  
  echo -e "\n$(for i in $(seq 1 100); do echo -n '='; done)\n\t\t\t\tENUMERATING SYSTEM\n$(for i in $(seq 1 100); do echo -n '='; done)"
  sleep 2

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
  echo -e "\n$(for i in $(seq 1 100); do echo -n '='; done)\n\t\t\t\tENUMERATING ENVIRONMENT\n$(for i in $(seq 1 100); do echo -n '='; done)"
  sleep 2
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


  passwdstored=$(grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs 2>/dev/null)
  if [[ $passwdstored ]]; then
    echo -e "$separator\n\t\t\t\t\t${purpleColour}Password and storage information${endColour}$separator"
    $passwdstored
  fi


  }

function user_group_enum() {
  echo -e "\n$(for i in $(seq 1 100); do echo -n '='; done)\n\t\t\t\tENUMERATING USERS & GROUPS\n$(for i in $(seq 1 100); do echo -n '='; done)"
  sleep 2

  local separator="\n${purpleColour}$(printf '=%.0s' {1..100})${endColour}"
  local current_user=$(whoami)

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Previously Logged Users${endColour}$separator"
  lastlog 2>/dev/null | grep -v "Never"

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Local Users with Valid Shells${endColour}$separator"
  grep -E "/home|/bin/bash" /etc/passwd

  echo -e "$separator\n\t\t\t\t\t${purpleColour}User Login Shells${endColour}$separator"
  awk -F: '{print $1 ": " $7}' /etc/passwd | grep -E "sh$"

  echo -e "$separator\n\t\t\t\t\t${purpleColour}System Groups & Members${endColour}$separator"
  getent group | awk -F: '$4' | column -t -s ":"
  for i in $(cut -d":" -f1 /etc/passwd); do id $i; done 2>/dev/null 

  #echo -e "$separator\n\t\t\t\t\t${purpleColour}Files Owned by Current User${endColour}$separator"
  #find / -user "$current_user" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Temporary File Locations${endColour}$separator"
  ls -l /tmp /var/tmp /dev/shm 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Hidden Files Owned by Current User${endColour}$separator"
  find / -type f -name ".*" -user "$current_user" -ls 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Hidden Files Outside /proc or /sys${endColour}$separator"
  find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Hidden Directories${endColour}$separator"
  find / -type d -name ".*" -ls 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Superuser Accounts (UID 0)${endColour}$separator"
  grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1 }'

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Sudoers (UID 0 Users)${endColour}$separator"
  grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1 }'

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Sudo Capabilities for Current User${endColour}$separator"
  echo '' | sudo -S -l -k 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Users that Recently Used sudo${endColour}$separator"
  find /home -name .sudo_as_admin_successful 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}SSH Keys and Related Files${endColour}$separator"
  find / \( -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" \) -exec ls -la {} \; 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Master Passwd File (if accessible)${endColour}$separator"
  cat /etc/master.passwd 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Files Writable but Not Owned by Current User${endColour}$separator"
  find / -writable ! -user "$current_user" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null
}





function job_tasks_enum() {
  echo -e "\n$(for i in $(seq 1 100); do echo -n '='; done)\n\t\t\t\tENUMERATING JOB & TASKS\n$(for i in $(seq 1 100); do echo -n '='; done)"
  sleep 2

  local separator="\n${purpleColour}$(printf '=%.0s' {1..100})${endColour}"

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Cron Directories${endColour}$separator"
  ls -la /etc/cron* 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Crontab Configuration${endColour}$separator"
  cat /etc/crontab 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}World-Writable Cron Jobs${endColour}$separator"
  find /etc/cron* -perm -0002 -type f -exec ls -la {} \; -exec cat {} 2>/dev/null \;

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Crontabs in /var/spool/cron/crontabs${endColour}$separator"
  ls -la /var/spool/cron/crontabs 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Anacron Jobs${endColour}$separator"
  ls -la /etc/anacrontab 2>/dev/null
  cat /etc/anacrontab 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}SystemD Timers and Services${endColour}$separator"
  systemctl list-timers --all 2>/dev/null
  systemctl list-units --type=service --state=running 2>/dev/null
}



function networking_enum() {
  echo -e "\n$(for i in $(seq 1 100); do echo -n '='; done)\n\t\t\t\tENUMERATING NETWORK\n$(for i in $(seq 1 100); do echo -n '='; done)"
  sleep 2

  local separator="\n${purpleColour}$(printf '=%.0s' {1..100})${endColour}"

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Network IP${endColour}$separator"
  /sbin/ifconfig -a 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Listening TCP${endColour}$separator"
  netstat -ntpl 2>/dev/null
  ss -t -l -n 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Listening UDP${endColour}$separator"
  netstat -nupl 2>/dev/null
  ss -u -l -n 2>/dev/null

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
  echo -e "\n$(for i in $(seq 1 100); do echo -n '='; done)\n\t\t\t\tENUMERATING SERVICES\n$(for i in $(seq 1 100); do echo -n '='; done)"
  sleep 2
 
  local separator="\n${purpleColour}$(printf '=%.0s' {1..100})${endColour}"


  echo -e "$separator\n\t\t\t\t\t${purpleColour}Runinng Processes${endColour}$separator"
  ps aux

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Processes Binaries and Associated Permissions${endColour}$separator"
  ps aux 2>/dev/null | awk '{print $11}'|xargs -r ls -la 2>/dev/null |awk '!x[$0]++' 2>/dev/null

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

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Are We Inside a Docker Container?${endColour}$separator"
  grep -i docker /proc/self/cgroup 2>/dev/null
  find / -name "*dockerenv*" -exec ls -la {} \; 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Docker Installed & Running (Host Check)${endColour}$separator"
  docker --version 2>/dev/null
  docker ps -a 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}User is Member of Docker Group${endColour}$separator"
  id | grep -i docker 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Dockerfiles Found on System${endColour}$separator"
  find / -name Dockerfile -exec ls -l {} \; 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}docker-compose.yml Files Found on System${endColour}$separator"
  find / -name docker-compose.yml -exec ls -l {} \; 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Are We Inside an LXC/LXD Container?${endColour}$separator"
  grep -qa container=lxc /proc/1/environ 2>/dev/null && echo "Detected LXC container context"

  echo -e "$separator\n\t\t\t\t\t${purpleColour}User is Member of LXD Group${endColour}$separator"
  id | grep -i lxd 2>/dev/null


}


function software_enum() {

  echo -e "\n$(for i in $(seq 1 100); do echo -n '='; done)\n\t\t\t\tENUMERATING SOFTWARE\n$(for i in $(seq 1 100); do echo -n '='; done)"
  sleep 2
 

  local separator="\n${purpleColour}$(printf '=%.0s' {1..100})${endColour}"

    ## Sudo Version
  echo -e "$separator\n\t\t\t\t\t${purpleColour}Sudo Version${endColour}$separator"
  sudo -V 2>/dev/null | grep "Sudo version" || echo "Sudo not found"

  ## MySQL Version
  echo -e "$separator\n\t\t\t\t\t${purpleColour}MySQL Version${endColour}$separator"
  mysql --version 2>/dev/null || echo "MySQL not installed"

  ## MySQL root:root Login
  echo -e "$separator\n\t\t\t\t\t${purpleColour}MySQL Default Credentials (root/root)${endColour}$separator"
  mysqladmin -uroot -proot version 2>/dev/null || echo "No access with root/root"

  ## MySQL root Login without Password
  echo -e "$separator\n\t\t\t\t\t${purpleColour}MySQL Access without Password (root user)${endColour}$separator"
  mysqladmin -uroot version 2>/dev/null || echo "No access with root and no password"

  ## PostgreSQL Version
  echo -e "$separator\n\t\t\t\t\t${purpleColour}PostgreSQL Version${endColour}$separator"
  psql -V 2>/dev/null || echo "PostgreSQL not installed"

  ## PostgreSQL Default Login Checks
  echo -e "$separator\n\t\t\t\t\t${purpleColour}Postgres Login Check (User: postgres / No Password)${endColour}$separator"
  psql -U postgres -w template0 -c 'select version();' 2>/dev/null | grep version || echo "No access"

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Postgres Login Check (User: postgres / DB: template1)${endColour}$separator"
  psql -U postgres -w template1 -c 'select version();' 2>/dev/null | grep version || echo "No access"

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Postgres Login Check (User: pgsql / DB: template0)${endColour}$separator"
  psql -U pgsql -w template0 -c 'select version();' 2>/dev/null | grep version || echo "No access"

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Postgres Login Check (User: pgsql / DB: template1)${endColour}$separator"
  psql -U pgsql -w template1 -c 'select version();' 2>/dev/null | grep version || echo "No access"

  ## Apache Version
  echo -e "$separator\n\t\t\t\t\t${purpleColour}Apache Version${endColour}$separator"
  apache2 -v 2>/dev/null || httpd -v 2>/dev/null || echo "Apache not installed"

  ## Apache Running User
  echo -e "$separator\n\t\t\t\t\t${purpleColour}Apache Running User / Group${endColour}$separator"
  grep -i 'user\|group' /etc/apache2/envvars 2>/dev/null | awk '{sub(/.*\export /,"")}1' || echo "Not found"

  ## Apache Modules
  echo -e "$separator\n\t\t\t\t\t${purpleColour}Installed Apache Modules${endColour}$separator"
  apache2ctl -M 2>/dev/null || httpd -M 2>/dev/null || echo "No modules info"

  ## htpasswd Discovery
  echo -e "$separator\n\t\t\t\t\t${purpleColour}htpasswd Files Found${endColour}$separator"
  find / -name .htpasswd -exec echo -e "[*] Found: {}" \; -exec cat {} \; 2>/dev/null || echo "None found"

  ## Apache Home Directory Contents (Optional: thorough only)
  if [ "$thorough" = "1" ]; then
    echo -e "$separator\n\t\t\t\t\t${purpleColour}Apache Web Root Contents (Thorough Scan)${endColour}$separator"
    ls -alhR /var/www/ 2>/dev/null
    ls -alhR /srv/www/htdocs/ 2>/dev/null
    ls -alhR /usr/local/www/apache2/data/ 2>/dev/null
    ls -alhR /opt/lampp/htdocs/ 2>/dev/null
  fi

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

function interesting_files_enum() {

  echo -e "\n$(for i in $(seq 1 100); do echo -n '='; done)\n\t\t\t\tINTERESTING FILES (PERMISSIONS)\n$(for i in $(seq 1 100); do echo -n '='; done)"
  sleep 2

  local separator="\n${purpleColour}$(printf '=%.0s' {1..100})${endColour}"

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Useful Binary Locations${endColour}$separator"
  which nc 2>/dev/null
  which netcat 2>/dev/null
  which wget 2>/dev/null
  which curl 2>/dev/null
  which gcc 2>/dev/null
  which nmap 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Installed Compilers${endColour}$separator"
  dpkg --list 2>/dev/null | grep compiler | grep -v decompiler
  yum list installed 'gcc*' 2>/dev/null | grep gcc

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Permissions on Sensitive Files${endColour}$separator"
  ls -la /etc/passwd /etc/group /etc/profile /etc/shadow /etc/master.passwd 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}SUID Files on the System${endColour}$separator"
  find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}SGID Files on the System${endColour}$separator"
  find / -perm -2000 -type f -exec ls -la {} \; 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Files with POSIX Capabilities${endColour}$separator"
  getcap -r / 2>/dev/null || /sbin/getcap -r / 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Users with Specific Capabilities${endColour}$separator"
  grep -v '^#\|none\|^$' /etc/security/capability.conf 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Private SSH Keys (Thorough Mode)${endColour}$separator"
  [ "$thorough" = "1" ] && grep -rl "PRIVATE KEY-----" /home 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}AWS Secret Keys (Thorough Mode)${endColour}$separator"
  [ "$thorough" = "1" ] && grep -rli "aws_secret_access_key" /home 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Git Credentials${endColour}$separator"
  [ "$thorough" = "1" ] && find / -name ".git-credentials" 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Interesting Logs${endColour}$separator"
  ls -lah /var/log 2>/dev/null
  find /var/log -type f -name "*.log" 2>/dev/null | xargs -I{} tail -n 20 {} 2>/dev/null

  echo -e "$separator\n\t\t\t\t\t${purpleColour}Interesting Binaries${endColour}$separator"
  for bin in nc python perl ruby gcc wget curl nmap find awk vi vim tar less more socat php lua; do
    if command -v $bin &>/dev/null; then
      echo -e "[*] Found: $bin"
    fi
  done

}




function options() {
  echo -e "${redColour}▌ 1 ▐${endColour} System"
  echo -e "${redColour}▌ 2 ▐${endColour} Environment"
  echo -e "${redColour}▌ 3 ▐${endColour} User / Group" 
  echo -e "${redColour}▌ 4 ▐${endColour} Services"
  echo -e "${redColour}▌ 5 ▐${endColour} Job / Tasks"
  echo -e "${redColour}▌ 6 ▐${endColour} Networking"
  echo -e "${redColour}▌ 7 ▐${endColour} Software"
  echo -e "${redColour}▌ 8 ▐${endColour} Interesting Files"
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
    services_enum
  elif [[ $output_show -eq 5 ]]; then 
    job_tasks_enum
  elif [[ $output_show -eq 6 ]]; then 
    networking_enum
  elif [[ $output_show -eq 7 ]]; then
    software_enum
  elif [[ $output_show -eq 8 ]]; then
    interesting_files_enum
    
  else 
    echo -e "${redColour}[!] You have to select a number! [1-8]${endColour}"
  fi 


}



function helpPanel(){
  echo -e "$banner"
  echo -e "\n$(for in in $(seq 1 100); do echo -n '='; done)"
  echo -e "                                           Help Panel"
  echo -e "$(for in in $(seq 1 100); do echo -n '='; done)"
  echo -e "\n${yellowColour}[+]${endColour} ${grayColour}Usage${endColour}: \n\t${purpleColour}$0 [options] [arguments]${endColour}"
  echo -e "\n${yellowColour}[+]${endColour} ${grayColour}Options${endColour}:"
  echo -e "\t${greenColour}-o${endColour}\t-${greenColour}Show Enumeration Options${endColour} ${yellowColour}(Interactive Mode)${endColour}"
  echo -e "\n${yellowColour}[+]${endColour} ${grayColour}Enumerate${endColour}:"
  echo -e "\t${greenColour}-s${endColour}\t-${greenColour}System${endColour}"
  echo -e "\t${greenColour}-e${endColour}\t-${greenColour}Environment${endColour}"
  echo -e "\t${greenColour}-u${endColour}\t-${greenColour}Users & Groups${endColour}"
  echo -e "\t${greenColour}-v${endColour}\t-${greenColour}Services${endColour}"
  echo -e "\t${greenColour}-j${endColour}\t-${greenColour}Jobs / Tasks${endColour}"
  echo -e "\t${greenColour}-n${endColour}\t-${greenColour}Network${endColour}"
  echo -e "\t${greenColour}-w${endColour}\t-${greenColour}Software${endColour}"
  echo -e "\t${greenColour}-f${endColour}\t-${greenColour}Interesting Files${endColour}"
  echo -e "\n${yellowColour}[+]${endColour} ${grayColour}Examples:${endColour}"
  echo -e "\t${purpleColour}$0 -e${endColour}" 
  echo -e "\t${purpleColour}$0 -s${endColour}" 
  echo -e "\t${purpleColour}$0 -j${endColour}" 
  echo -e "\t${purpleColour}$0 -n${endColour}" 
  local separator="\n$(printf '=%.0s' {1..100})" 
 
}





declare -i paremeter_counter=0

while getopts "oseuvjnwfh" arg; do 
  case $arg in 
    o) let paremeter_counter+=1;;
    s) let parameter_counter+=2;;
    e) let parameter_counter+=3;;
    u) let parameter_counter+=4;;
    v) let parameter_counter+=5;;
    j) let parameter_counter+=6;;
    n) let parameter_counter+=7;;
    w) let parameter_counter+=8;;
    f) let parameter_counter+=9;;
    h) ;;
  esac 
done 

if [ $paremeter_counter -eq 1 ]; then 
  select-options
elif [[ $parameter_counter -eq 2 ]]; then
  system_enum
elif [[ $parameter_counter -eq 3 ]]; then
  env_enum
elif [[ $parameter_counter -eq 4 ]]; then
  user_group_enum
elif [[ $parameter_counter -eq 5 ]]; then
  services_enum
elif [[ $parameter_counter -eq 6 ]]; then
  job_tasks_enum
elif [[ $parameter_counter -eq 7 ]]; then
  networking_enum
elif [[ $parameter_counter -eq 8 ]]; then
  software_enum
elif [[ $parameter_counter -eq 9 ]]; then
  interesting_files_enum
else
  helpPanel
fi
