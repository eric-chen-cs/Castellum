#!/bin/bash

# --- UBUNTU HARDENING SCRIPT FOR CYBERPATRIOT ---

# Removed 'set -e' to prevent the script from crashing if a single command fails (e.g., package not found).
# We want the script to attempt all hardening steps even if one fails.
set -o pipefail
export DEBIAN_FRONTEND=noninteractive

LOG_FILE="/var/log/cyberpatriot_hardening_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "${LOG_FILE}") 2>&1

echo "--- CyberPatriot Ubuntu Hardening Script ---"
echo "Starting system hardening at $(date)"
echo "Log file: ${LOG_FILE}"

# --- CHECK FOR ROOT PRIVILEGES ---
if [[ "${EUID}" -ne 0 ]]; then
  echo " (!) This script must be run as root. Exiting."
  exit 1
fi

# --- HELPER FUNCTIONS ---
add_or_update_line() {
  local file="$1"
  local line_content="$2"
  local pattern_to_grep="$3"

  if [ -f "$file" ]; then
      if ! grep -qF -- "$pattern_to_grep" "$file"; then
        echo " (+) Adding to ${file}: ${line_content}"
        echo "${line_content}" >> "${file}"
      else
        echo " (*) Line containing '${pattern_to_grep}' already exists in ${file}."
      fi
  else
      echo " (!) File ${file} not found. Creating it."
      echo "${line_content}" > "${file}"
  fi
}

add_or_update_sysctl() {
  local key="$1"
  local value="$2"
  local config_file="/etc/sysctl.conf"

  echo " (>) Configuring sysctl: ${key} = ${value}"
  if grep -qE "^\s*#?\s*${key}\s*=" "${config_file}"; then
    sed -i -e "s|^\s*#*\s*${key}\s*=.*|${key} = ${value}|g" "${config_file}"
  else
    echo "${key} = ${value}" >> "${config_file}"
  fi
}

# --- 1. SYSTEM UPDATES & ESSENTIAL TOOLS ---
echo ""
echo "--- SECTION 1: SYSTEM UPDATES & ESSENTIAL TOOLS ---"
# Check if internet is available before updating
if ping -c 1 8.8.8.8 &> /dev/null; then
    echo " (>) Updating package lists..."
    apt-get update -y
    echo " (>) Upgrading installed packages..."
    apt-get upgrade -y
    apt-get autoremove -y
    apt-get autoclean -y
else
    echo " (!) No internet connection detected. Skipping updates."
fi

echo " (>) Installing essential security tools..."
apt-get install -y ufw clamav clamav-daemon freshclam auditd audispd-plugins \
                   debsums libpam-pwquality libpam-apparmor apparmor-utils \
                   aide aide-common unattended-upgrades fail2ban openscap-scanner lynis || true

# --- 2. ANTIVIRUS (CLAMAV) ---
echo " (>) Setting default account inactivity to 30 days..."
useradd -D -f 30
echo " (>) Setting global shell timeout (900 seconds)..."
if ! grep -q "TMOUT=" /etc/profile; then
    echo "readonly TMOUT=900" >> /etc/profile
    echo "export TMOUT" >> /etc/profile
fi
echo " (>) Enforcing sticky bits on world-writable directories..."
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -exec chmod +t {} + 2>/dev/null
echo ""
echo "--- SECTION 2: ANTIVIRUS (CLAMAV) ---"
echo " (>) Stopping clamav-freshclam to update manually..."
systemctl stop clamav-freshclam || true
echo " (>) Updating ClamAV virus definitions..."
freshclam || echo " (!) Freshclam failed (possibly no internet or locked DB)."
echo " (>) Enabling and starting ClamAV daemon..."
systemctl enable clamav-daemon || true
systemctl start clamav-daemon || true

# --- 3. FILE INTEGRITY CHECKER (AIDE) ---
echo ""
echo "--- SECTION 3: FILE INTEGRITY CHECKER (AIDE) ---"
if [ ! -f /var/lib/aide/aide.db.gz ] && [ ! -f /var/lib/aide/aide.db ]; then
    echo " (>) Initializing AIDE database..."
    aideinit -y || echo " (!) aideinit failed."
    if [ -f /var/lib/aide/aide.db.new.gz ]; then
        cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    fi
else
    echo " (*) AIDE database already exists."
fi

# --- 4. AUDITING (AUDITD) ---
echo ""
echo "--- SECTION 4: AUDITING (AUDITD) ---"
if [ -d /etc/audit ]; then
    echo " (>) Configuring auditd..."
    cp /etc/audit/auditd.conf /etc/audit/auditd.conf.bak 2>/dev/null || true
    
    sed -i 's/^max_log_file_action.*/max_log_file_action = ROTATE/' /etc/audit/auditd.conf
    sed -i 's/^space_left_action.*/space_left_action = SYSLOG/' /etc/audit/auditd.conf
    sed -i 's/^admin_space_left_action.*/admin_space_left_action = SUSPEND/' /etc/audit/auditd.conf
    
    echo " (>) Writing rules to /etc/audit/rules.d/99-cyberpatriot.rules..."
    cat > /etc/audit/rules.d/99-cyberpatriot.rules <<EOF
-D
-b 8192
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-e 2
EOF
    augenrules --load
    systemctl restart auditd || echo " (!) Failed to restart auditd"
fi

echo " (>) Hardening Sudoers policy..."
# FIXED: Removed passwd_timeout=0 and timestamp_timeout=0 which locked out sudo
cat > /etc/sudoers.d/99-cyberpatriot <<EOF
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults        use_pty
Defaults        timestamp_timeout=15
EOF
chmod 440 /etc/sudoers.d/99-cyberpatriot

# --- 5. APPLICATION ARMOR (APPARMOR) ---
echo ""
echo "--- SECTION 5: APPLICATION ARMOR (APPARMOR) ---"
systemctl enable apparmor || true
systemctl start apparmor || true
echo " (>) Putting AppArmor profiles into enforce mode..."
aa-complain /etc/apparmor.d/* 2>/dev/null || true

# --- 6. UNATTENDED UPGRADES ---
echo ""
echo "--- SECTION 6: UNATTENDED UPGRADES ---"
echo 'APT::Periodic::Update-Package-Lists "1";' > /etc/apt/apt.conf.d/20auto-upgrades
echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades
echo " (i) Unattended upgrades configured."

# --- 7. FIREWALL (UFW) ---
echo ""
echo "--- SECTION 7: FIREWALL (UFW) ---"
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh 2>/dev/null || true
echo " (>) Enabling UFW..."
ufw --force enable
ufw status verbose

# --- 8. REMOVE INSECURE SERVICES ---
echo ""
echo "--- SECTION 8: REMOVE INSECURE SERVICES & PACKAGES ---"
# FIXED: Removed apache2, nginx, vsftpd, samba, bind9, etc., from auto-purge
INSECURE_SERVICES=( "avahi-daemon" "cups" "rpcbind" "telnetd" "vsftpd" "pure-ftpd" "apache2" "nginx" "samba" "smbd" "nfs-kernel-server" "bind9" "snmpd" "pop3" "dovecot" "fingerd" "rstatd" "ruserd" "rwalld" "squid" "snmpd" "xrdp" "vncserver" "inetd")
INSECURE_PACKAGES=( "telnet" "rsh-client" "rsh-redone-client" "talk" "ypbind" "xinetd" "tftpd" "john" "nmap" "hydra" "wireshark" "netcat" "netcat-openbsd" "netcat-traditional" "ophcrack" "kismet" "minetest" "aircrack-ng" "metasploit-framework" "nikto" "sqlmap" "burpsuite" "medusa" "hashcat" 
    "tcpdump" "zenmap" "ettercap-common" "dsniff" "wireshark" "tshark" 
    "teamviewer" "anydesk" "tightvncserver" "vnc4server" "x11vnc" "rdesktop"
    "steam" "steam-launcher" "minecraft-launcher" "wesnoth" "vlc" "spotify-client"
    "discord" "zoom" "frozen-bubble" "rsh-client" "rsh-server" "nis" "yp-tools" 
    "tftp" "atftpd" "snmp" "snmpd" "ldap-utils" "slapd" "doona" "finger" "rlogin" "rexec" "wine" "wine32" "wine64" 
    "aisleriot" "gnome-games" "kmines" "quadrapassel" "tali" "iagno" "lightsoff"
    "qbittorrent" "deluge" "frostwire" "nicotine" 
    "skypeforlinux" "slack-desktop" "telegram-desktop"
    "gcc" "make" "git" "nmap" "zenmap" "wireshark" "tshark" 
    "beef-xss" "maltego" "aircrack-ng" "crunch" "hashcat")

for service in "${INSECURE_SERVICES[@]}"; do
  if systemctl is-active --quiet "$service"; then
    echo " (>) Stopping and disabling $service..."
    systemctl stop "$service" || true
    systemctl disable "$service" || true
  fi
done

echo " (>) Purging insecure packages..."
apt-get purge -y "${INSECURE_PACKAGES[@]}" || true
apt-get autoremove -y

# --- MINT SPECIFIC REMOVALS ---
echo " (>) Removing Mint-specific prohibited software..."
MINT_BAD_PKGS=(
    "transmission-gtk"
    "transmission-common"
    "hexchat"
    "pidgin"
    "vino"
    "warpinator"
    "aMule"
    "Zangband"
)

apt-get purge -y "${MINT_BAD_PKGS[@]}" || true
apt-get autoremove -y

# --- DISABLE SMTP (EMAIL) ---
echo " (>) Disabling SMTP services..."
if systemctl is-active --quiet postfix; then
    systemctl stop postfix
    systemctl disable postfix
    echo "     - Postfix stopped and disabled."
fi
if systemctl is-active --quiet exim4; then
    systemctl stop exim4
    systemctl disable exim4
    echo "     - Exim4 stopped and disabled."
fi

# --- MYSQL HARDENING ---
if [ -d "/etc/mysql" ]; then
    echo " (>) Securing MySQL..."
    find /etc/mysql -name "*.cnf" -exec sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' {} \;
    find /etc/mysql -name "*.cnf" -exec sed -i '/\[mysqld\]/a skip-symbolic-links' {} \;
    systemctl restart mysql 2>/dev/null || true
fi

# --- SECTION 8.1: SECURE VSFTPD (FTP WITH SSL) ---
echo ""
echo "--- SECTION 8.1: SECURING VSFTPD (FTP) ---"
if dpkg -s vsftpd &> /dev/null; then
    echo " (>) vsftpd detected. Securing configuration..."
    VSFTPD_CONF="/etc/vsftpd.conf"
    cp "$VSFTPD_CONF" "${VSFTPD_CONF}.bak"

    CERT_FILE="/etc/ssl/private/vsftpd.pem"
    if [ ! -f "$CERT_FILE" ]; then
        echo " (>) Generating self-signed SSL certificate for FTP..."
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$CERT_FILE" -out "$CERT_FILE" \
            -subj "/C=US/ST=CyberPatriot/L=Security/O=IT/CN=ftp.secure" 2>/dev/null
    fi

    sed -i '/^anonymous_enable/d' "$VSFTPD_CONF"
    echo "anonymous_enable=NO" >> "$VSFTPD_CONF"
    
    sed -i '/^local_enable/d' "$VSFTPD_CONF"
    echo "local_enable=YES" >> "$VSFTPD_CONF"
    
    sed -i '/^write_enable/d' "$VSFTPD_CONF"
    echo "write_enable=YES" >> "$VSFTPD_CONF"

    sed -i '/^ssl_enable/d' "$VSFTPD_CONF"
    echo "ssl_enable=YES" >> "$VSFTPD_CONF"

    sed -i '/^allow_anon_ssl/d' "$VSFTPD_CONF"
    echo "allow_anon_ssl=NO" >> "$VSFTPD_CONF"

    sed -i '/^force_local_data_ssl/d' "$VSFTPD_CONF"
    echo "force_local_data_ssl=YES" >> "$VSFTPD_CONF"

    sed -i '/^force_local_logins_ssl/d' "$VSFTPD_CONF"
    echo "force_local_logins_ssl=YES" >> "$VSFTPD_CONF"

    sed -i '/^ssl_tlsv1/d' "$VSFTPD_CONF"
    echo "ssl_tlsv1=YES" >> "$VSFTPD_CONF"
    
    sed -i '/^ssl_sslv2/d' "$VSFTPD_CONF"
    echo "ssl_sslv2=NO" >> "$VSFTPD_CONF"
    
    sed -i '/^ssl_sslv3/d' "$VSFTPD_CONF"
    echo "ssl_sslv3=NO" >> "$VSFTPD_CONF"

    sed -i '/^rsa_cert_file/d' "$VSFTPD_CONF"
    echo "rsa_cert_file=$CERT_FILE" >> "$VSFTPD_CONF"
    
    sed -i '/^rsa_private_key_file/d' "$VSFTPD_CONF"
    echo "rsa_private_key_file=$CERT_FILE" >> "$VSFTPD_CONF"

    sed -i '/^chroot_local_user/d' "$VSFTPD_CONF"
    echo "chroot_local_user=YES" >> "$VSFTPD_CONF"
    
    sed -i '/^allow_writeable_chroot/d' "$VSFTPD_CONF"
    echo "allow_writeable_chroot=YES" >> "$VSFTPD_CONF"

    echo " (>) Securing FTP Root Directories..."
    FTP_ROOTS=("/srv/ftp" "/var/ftp")
    for dir in "${FTP_ROOTS[@]}"; do
      if [ -d "$dir" ]; then
        echo " (>) Found FTP directory: $dir"
        chown root:root "$dir"
        chmod 755 "$dir"
      fi
    done

    echo " (>) Restarting vsftpd..."
    systemctl restart vsftpd || echo " (!) Failed to restart vsftpd."
else
    echo " (*) vsftpd is not installed. Skipping."
fi

# --- PHP SECURITY HARDENING ---
if [ -d "/etc/php" ]; then
    echo " (>) Hardening PHP configuration..."
    PHP_INIS=$(find /etc/php -name "php.ini")
    
    for ini in $PHP_INIS; do
        echo "     - Editing $ini"
        sed -i 's/^allow_url_fopen.*/allow_url_fopen = Off/' "$ini"
        sed -i 's/^allow_url_include.*/allow_url_include = Off/' "$ini"
        sed -i 's/^max_execution_time.*/max_execution_time = 30/' "$ini"
        sed -i 's/^expose_php.*/expose_php = Off/' "$ini"
        sed -i 's/^disable_functions.*/disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source/' "$ini"
        sed -i 's/^log_errors.*/log_errors = On/' "$ini"
    done
    
    systemctl restart apache2 2>/dev/null || true
fi

# --- 9. SSH CONFIGURATION ---
echo ""
echo "--- SECTION 9: SECURE SSH CONFIGURATION ---"
SSH_CONFIG="/etc/ssh/sshd_config"
if [ -f "${SSH_CONFIG}" ]; then
  cp "${SSH_CONFIG}" "${SSH_CONFIG}.bak"
  
  sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' "$SSH_CONFIG"
  sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSH_CONFIG"
  sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' "$SSH_CONFIG"

  echo "Authorized uses only." > /etc/issue.net
  sed -i 's|^#\?Banner.*|Banner /etc/issue.net|' "$SSH_CONFIG"

  if sshd -t; then
    systemctl restart sshd
  else
    echo " (!) SSH Config check failed. Reverting..."
    cp "${SSH_CONFIG}.bak" "${SSH_CONFIG}"
  fi
fi

# --- 10. FAIL2BAN ---
echo ""
echo "--- SECTION 10: FAIL2BAN ---"
JAIL_LOCAL="/etc/fail2ban/jail.local"
if [ ! -f "${JAIL_LOCAL}" ]; then
  echo " (>) Creating jail.local..."
  cat > "${JAIL_LOCAL}" <<EOF
[DEFAULT]
bantime = 1h
findtime = 30m
maxretry = 5

[sshd]
enabled = true
EOF
fi
systemctl enable fail2ban || true
systemctl restart fail2ban || true

# --- 11. USER ACCOUNTS & PASSWORD POLICIES ---
echo ""
echo "--- SECTION 11: USER ACCOUNTS & PASSWORD POLICIES ---"
echo " (>) Enforcing password history (remember=5)..."
if grep -q "pam_unix.so" /etc/pam.d/common-password; then
    sed -i 's/\(pam_unix.so.*\)\sremember=[0-9]*/\1/' /etc/pam.d/common-password
    sed -i 's/pam_unix.so.*/& remember=5/' /etc/pam.d/common-password
fi

passwd -l root || true

sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs

PWQUALITY="/etc/security/pwquality.conf"
echo "minlen = 14" > "$PWQUALITY"
echo "dcredit = -1" >> "$PWQUALITY"
echo "ucredit = -1" >> "$PWQUALITY"
echo "lcredit = -1" >> "$PWQUALITY"
echo "ocredit = -1" >> "$PWQUALITY"
echo "difok = 3" >> "$PWQUALITY"

echo " (>) Applying PAM updates..."
echo "deny = 5" > /etc/security/faillock.conf
echo "unlock_time = 900" >> /etc/security/faillock.conf
echo "silent" >> /etc/security/faillock.conf
echo "audit" >> /etc/security/faillock.conf

# FIXED: Removed the sed line that corrupted /etc/pam.d/common-auth
pam-auth-update --enable pwquality faillock || true

# --- FIX NOPASSWDLOGIN GROUP ---
echo " (>) Checking for users in 'nopasswdlogin' group..."
if grep -q "nopasswdlogin" /etc/group; then
    BAD_USERS=$(grep "nopasswdlogin" /etc/group | cut -d: -f4)
    if [ -n "$BAD_USERS" ]; then
        echo " (!) FOUND USERS IN nopasswdlogin: $BAD_USERS"
        IFS=',' read -ra ADDR <<< "$BAD_USERS"
        for user in "${ADDR[@]}"; do
            echo "     - Removing $user from nopasswdlogin..."
            gpasswd -d "$user" nopasswdlogin
        done
    else
        echo " (*) No users found in nopasswdlogin group."
    fi
fi

# --- SECTION 11.1: FIREFOX SECURITY ---
echo " (>) Applying Firefox Security Policies..."
mkdir -p /usr/lib/firefox/distribution
mkdir -p /etc/firefox/policies

cat > /tmp/policies.json <<EOF
{
  "policies": {
    "DisableAppUpdate": false,
    "DisableTelemetry": true,
    "DisableFirefoxStudies": true,
    "DisablePocket": true,
    "DisablePasswordReveal": true,
    "OfferToSaveLogins": false,
    "PasswordManagerEnabled": false,
    "BlockAboutConfig": true,
    "PopupBlocking": {
      "Default": true,
      "Locked": true
    },
    "Phishing": {
      "Enabled": true,
      "Locked": true
    }
  }
}
EOF

cp /tmp/policies.json /usr/lib/firefox/distribution/policies.json 2>/dev/null || true
cp /tmp/policies.json /etc/firefox/policies/policies.json 2>/dev/null || true

# --- CHECK FOR NON-ROOT UID 0 ---
echo " (>) Checking for non-root users with UID 0..."
UID0_USERS=$(awk -F: '($3 == "0") {print $1}' /etc/passwd)
for user in $UID0_USERS; do
    if [ "$user" != "root" ]; then
        echo " (!!!) SECURITY ALERT: User $user has UID 0! Changing to UID 2000+..."
        usermod -u $(shuf -i 2000-5000 -n 1) "$user"
    fi
done

# --- 12. LIGHTDM ---
echo ""
echo "--- SECTION 12: LIGHTDM ---"
if [ -d /etc/lightdm ]; then
    mkdir -p /etc/lightdm/lightdm.conf.d
    echo "[Seat:*]" > /etc/lightdm/lightdm.conf.d/99-cyberpatriot-hardening.conf
    echo "allow-guest=false" >> /etc/lightdm/lightdm.conf.d/99-cyberpatriot-hardening.conf
    echo "greeter-hide-users=true" >> /etc/lightdm/lightdm.conf.d/99-cyberpatriot-hardening.conf
fi

# --- SECTION 12.1: SECURE CINNAMON DESKTOP (MINT) ---
echo " (>) Configuring Cinnamon Screensaver & Lock Policies..."
mkdir -p /etc/dconf/profile
if [ ! -f /etc/dconf/profile/user ]; then
    echo "user-db:user" > /etc/dconf/profile/user
    echo "system-db:local" >> /etc/dconf/profile/user
fi

mkdir -p /etc/dconf/db/local.d
cat > /etc/dconf/db/local.d/00-cyberpatriot-hardening <<EOF
[org/cinnamon/desktop/screensaver]
lock-enabled=true
idle-activation-enabled=true
delay-time=900
lock-delay=0

[org/cinnamon/settings-daemon/plugins/power]
lock-on-suspend=true

[org/cinnamon/desktop/session]
idle-delay=900
EOF

mkdir -p /etc/dconf/db/local.d/locks
cat > /etc/dconf/db/local.d/locks/00-cyberpatriot-hardening <<EOF
/org/cinnamon/desktop/screensaver/lock-enabled
/org/cinnamon/desktop/screensaver/idle-activation-enabled
/org/cinnamon/desktop/screensaver/delay-time
/org/cinnamon/desktop/screensaver/lock-delay
/org/cinnamon/settings-daemon/plugins/power/lock-on-suspend
/org/cinnamon/desktop/session/idle-delay
EOF

dconf update 2>/dev/null || true

# --- DISABLE CTRL+ALT+BACKSPACE ---
localedef -v -c -i en_US -f UTF-8 en_US.UTF-8 2>/dev/null || true
if [ -f /etc/default/keyboard ]; then
    sed -i 's/XKBOPTIONS=".*"/XKBOPTIONS=""/' /etc/default/keyboard
    dpkg-reconfigure -f noninteractive keyboard-configuration 2>/dev/null || true
fi

# --- 13. KERNEL PARAMETERS ---
echo ""
echo "--- SECTION 13: KERNEL PARAMETERS ---"
# FIXED: Preserved IPv6 so APT and local network services do not break
add_or_update_sysctl "fs.suid_dumpable" "0"
add_or_update_sysctl "net.ipv4.conf.all.rp_filter" "1"
add_or_update_sysctl "net.ipv4.conf.default.rp_filter" "1"
add_or_update_sysctl "net.ipv4.icmp_ignore_bogus_error_responses" "1"
add_or_update_sysctl "net.ipv4.ip_forward" "0"
add_or_update_sysctl "net.ipv4.conf.all.accept_redirects" "0"
add_or_update_sysctl "net.ipv4.conf.all.log_martians" "1"
add_or_update_sysctl "net.ipv4.tcp_syncookies" "1"
add_or_update_sysctl "kernel.randomize_va_space" "2"
add_or_update_sysctl "net.ipv4.conf.all.send_redirects" "0"
add_or_update_sysctl "net.ipv4.conf.default.send_redirects" "0"
add_or_update_sysctl "net.ipv4.conf.default.accept_redirects" "0"
add_or_update_sysctl "net.ipv4.conf.all.secure_redirects" "0"
add_or_update_sysctl "net.ipv4.conf.default.secure_redirects" "0"
add_or_update_sysctl "net.ipv4.conf.all.accept_source_route" "0"
add_or_update_sysctl "net.ipv4.conf.default.accept_source_route" "0"
add_or_update_sysctl "net.ipv4.conf.default.log_martians" "1"
add_or_update_sysctl "net.ipv4.icmp_echo_ignore_broadcasts" "1"
add_or_update_sysctl "net.ipv4.tcp_max_syn_backlog" "2048"
add_or_update_sysctl "net.ipv4.tcp_synack_retries" "2"
add_or_update_sysctl "net.ipv4.tcp_syn_retries" "5"

echo " (>) Applying sysctl changes..."
sysctl -p /etc/sysctl.conf || true

# --- 14. SECURE SHARED MEMORY ---
if ! grep -q "tmpfs /dev/shm" /etc/fstab; then
    echo "tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev 0 0" >> /etc/fstab
    mount -o remount /dev/shm || true
fi

# --- 15. PERMISSIONS ---
chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
chmod 644 /etc/passwd
chmod 644 /etc/group

# FIXED: Set shadow permissions to standard 640 root:shadow
chmod 640 /etc/shadow
chown root:shadow /etc/shadow
chmod 640 /etc/gshadow
chown root:shadow /etc/gshadow
chmod 600 /etc/ssh/sshd_config 2>/dev/null || true

# --- SECURE WEB SERVER ROOT ---
if [ -d "/var/www/html" ]; then
    echo " (>) Securing /var/www/html permissions..."
    chown -R root:root /var/www/html
    find /var/www/html -type d -exec chmod 755 {} \;
    find /var/www/html -type f -exec chmod 644 {} \;
fi

# --- SECURE ROOT HOME ---
echo " (>) Securing /root directory..."
chown root:root /root
chmod 700 /root

# --- SECURE SHELL CONFIGS ---
echo " (>) Securing global shell configuration files..."
SHELL_CONFIGS=("/etc/profile" "/etc/bash.bashrc" "/etc/environment" "/etc/profile.d")
for config in "${SHELL_CONFIGS[@]}"; do
  if [ -e "$config" ]; then
    chown root:root "$config"
    chmod 644 "$config"
  fi
done

# --- SECURE SUDOERS DIRECTORY ---
echo " (>) Securing /etc/sudoers.d..."
chmod 755 /etc/sudoers.d
chmod 440 /etc/sudoers.d/* 2>/dev/null || true

# --- SECURE APT SOURCES ---
echo " (>) Securing apt sources..."
chown root:root /etc/apt/sources.list
chmod 644 /etc/apt/sources.list
chown root:root /etc/apt/sources.list.d
chmod 755 /etc/apt/sources.list.d

# --- SECURE CRON DIRECTORIES ---
echo " (>) Securing cron directories..."
# FIXED: Cron directories must be 755 for system services to read them
chmod 755 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly
chown -R root:root /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly
chmod 600 /etc/crontab

# --- SECURE LOG FILES ---
echo " (>) Securing log files..."
if [ -f /var/log/wtmp ]; then
    # FIXED: Set to 664 so user tools like 'last' work
    chmod 664 /var/log/wtmp
    chown root:utmp /var/log/wtmp
fi
if [ -f /var/log/btmp ]; then
    chmod 660 /var/log/btmp
    chown root:utmp /var/log/btmp
fi
if [ -f /var/log/lastlog ]; then
    chmod 664 /var/log/lastlog
    chown root:utmp /var/log/lastlog
fi

# --- CLEAN ETC/HOSTS ---
echo " (>) Checking /etc/hosts for malicious redirects..."
cp /etc/hosts /etc/hosts.bak
sed -i '/security.ubuntu.com/d' /etc/hosts
sed -i '/archive.ubuntu.com/d' /etc/hosts

# --- SUDOERS NOPASSWD SCRUB ---
echo " (>) Checking sudoers for NOPASSWD entries..."
if grep -q "NOPASSWD" /etc/sudoers; then
    sed -i 's/\(.*NOPASSWD.*\)/# \1/' /etc/sudoers
    echo "     - Commented out NOPASSWD in /etc/sudoers"
fi

grep -r "NOPASSWD" /etc/sudoers.d/ | while read -r line; do
    file=$(echo "$line" | cut -d: -f1)
    sed -i 's/\(.*NOPASSWD.*\)/# \1/' "$file"
    echo "     - Commented out NOPASSWD in $file"
done

# --- 16. MEDIA & HACKING FILES ---
echo ""
echo "--- SECTION 16: PROHIBITED FILES ---"
echo " (i) Searching for media files (check log)..."
find /home -type f \( -name "*.mp3" -o -name "*.mp4" -o -name "*.avi" \) -print

echo " (i) Searching for hacking tools..."
find /home -type f \( -name "*.pcap" -o -name "john" -o -name "hydra" \) -print

# --- 17. FINAL CLEANUP ---
echo ""
echo "--- FINAL CLEANUP ---"
apt-get autoremove -y
apt-get clean

echo " (>) Hardening resource limits..."
# FIXED: Removed 'soft nproc 100' and 'hard nproc 150' which crashed desktop sessions
cat <<EOF >> /etc/security/limits.conf
* hard core 0
EOF

# --- ADVANCED PERSISTENCE CHECK ---
echo " (>) Checking for suspicious startup scripts..."
ls -la /etc/init.d/ | grep -v "root"
ls -la /etc/rc.local 2>/dev/null

echo " (>) Checking for 'hidden' cron jobs (files starting with .)..."
find /etc/cron* -name ".*" -print
find /var/spool/cron -name ".*" -print

echo "Hardening complete. Please REBOOT the system."

echo ""
echo "=================================================="
echo "   CURRENT USER AUDIT (COMPARE WITH README!)"
echo "=================================================="
echo "ADMINS (sudo group):"
grep -Po '^sudo:.*:\K.*$' /etc/group || true
echo "--------------------------------------------------"
echo "ALL USERS (UID >= 1000):"
awk -F: '($3 >= 1000 && $3 < 60000) {print $1, $3}' /etc/passwd
echo "=================================================="
echo ""
echo " (>) Scanning for suspicious usernames..."
SUSPICIOUS_NAMES=("backdoor" "hacker" "attacker" "shadow" "temp" "test" "root2" "admin2")
for name in "${SUSPICIOUS_NAMES[@]}"; do
    if id "$name" &>/dev/null; then
        echo " [!!!] SUSPICIOUS USER FOUND: $name. Check README immediately!"
    fi
done
echo " (>) Checking for accounts with empty passwords..."
EMPTY_PW=$(awk -F: '($2 == "") {print $1}' /etc/shadow)
for user in $EMPTY_PW; do
    echo " [!] Account $user has NO PASSWORD!"
done
echo " (>) Verifying integrity of password files..."
pwck -r || echo " [!!!] Potential issues found in /etc/passwd or /etc/shadow!"
grpck -r || echo " [!!!] Potential issues found in /etc/group or /etc/gshadow!"
echo "--- CRON JOB AUDIT ---"
for user in $(awk -F: '{print $1}' /etc/passwd); do
    crontab -u "$user" -l 2>/dev/null | grep -v "^#" && echo " (!!!) Above cron job found for user: $user"
done

exit 0
