#!/usr/bin/env bash
#
# non-panel-audit.sh
# ---------------------------------------------------------------------------
# Security & health audit script for servers WITHOUT a control panel
# (no cPanel / Plesk / DirectAdmin etc).
#
# Distro support : AlmaLinux, RHEL, CentOS, Rocky, CloudLinux, Ubuntu,
#                  Debian and other common systemd-based distros.
# Web server     : Apache and/or Nginx (auto-detected, both supported).
#
# Output style mirrors the cPanel audit script:
#   GREEN = Active / Enabled / Good
#   RED   = Inactive / Disabled / Needs attention
#   BLUE  = N/A (not applicable / not installed on this server)
#   YELLOW= Not checked automatically / needs manual confirmation
#
# This script is READ-ONLY. It does not change any server configuration,
# stop/start services, delete files, or modify cron/firewall rules.
# ---------------------------------------------------------------------------

set -uo pipefail

# ----------------------------- Colours --------------------------------------
GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
BLUE=$'\033[0;34m'
YELLOW=$'\033[0;33m'
BOLD=$'\033[1m'
NC=$'\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
NA_COUNT=0
WARN_COUNT=0

REPORT_HOST="$(hostname -f 2>/dev/null || hostname)"
REPORT_DATE="$(date '+%Y-%m-%d %H:%M:%S %Z')"

# ----------------------------- Helpers ---------------------------------------
section() {
    echo
    echo -e "${BOLD}=============================================================${NC}"
    echo -e "${BOLD} $1${NC}"
    echo -e "${BOLD}=============================================================${NC}"
}

subsection() {
    echo
    echo -e "${BOLD}-- $1 --${NC}"
}

row() {
    # row "<label>" "<value/status text>"
    printf "  %-38s : %s\n" "$1" "$2"
}

pass()  { row "$1" "${GREEN}GREEN${NC}  - $2"; PASS_COUNT=$((PASS_COUNT+1)); }
fail()  { row "$1" "${RED}RED${NC}    - $2";   FAIL_COUNT=$((FAIL_COUNT+1)); }
na()    { row "$1" "${BLUE}N/A${NC}    - $2";  NA_COUNT=$((NA_COUNT+1)); }
warn()  { row "$1" "${YELLOW}CHECK${NC}  - $2"; WARN_COUNT=$((WARN_COUNT+1)); }

cmd_exists() { command -v "$1" >/dev/null 2>&1; }

service_active() {
    # service_active <name> -> returns 0 if active
    systemctl is-active --quiet "$1" 2>/dev/null
}

need_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}This script must be run as root for a complete audit.${NC}"
        exit 1
    fi
}

# ----------------------------- OS detection -----------------------------------
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-unknown}"
        OS_PRETTY="${PRETTY_NAME:-unknown}"
    else
        OS_ID="unknown"
        OS_VERSION="unknown"
        OS_PRETTY="$(uname -s -r)"
    fi

    case "$OS_ID" in
        almalinux|rocky|rhel|centos|cloudlinux|fedora)
            PKG_FAMILY="rpm"
            ;;
        ubuntu|debian)
            PKG_FAMILY="deb"
            ;;
        *)
            PKG_FAMILY="unknown"
            ;;
    esac

    if cmd_exists dnf; then
        PKG_MGR="dnf"
    elif cmd_exists yum; then
        PKG_MGR="yum"
    elif cmd_exists apt-get; then
        PKG_MGR="apt-get"
    else
        PKG_MGR=""
    fi
}

# ----------------------------- OS / CMS EOL tables ----------------------------
# Returns "EOL" or "SUPPORTED" via echo
os_eol_status() {
    local id="$1" ver="$2" majver
    majver="${ver%%.*}"
    case "$id" in
        centos)
            case "$majver" in
                6|7|8) echo "EOL" ;;
                *) echo "SUPPORTED" ;;
            esac
            ;;
        cloudlinux)
            case "$majver" in
                6|7) echo "EOL" ;;
                *) echo "SUPPORTED" ;;
            esac
            ;;
        rhel|almalinux|rocky)
            case "$majver" in
                6|7) echo "EOL" ;;
                *) echo "SUPPORTED" ;;
            esac
            ;;
        ubuntu)
            case "$ver" in
                14.04|16.04|18.04|20.04) echo "EOL" ;;
                *) echo "SUPPORTED" ;;
            esac
            ;;
        debian)
            case "$majver" in
                8|9|10) echo "EOL" ;;
                *) echo "SUPPORTED" ;;
            esac
            ;;
        *)
            echo "UNKNOWN"
            ;;
    esac
}

php_eol_status() {
    local ver="$1"
    case "$ver" in
        5.*|7.0|7.0.*|7.1|7.1.*|7.2|7.2.*|7.3|7.3.*|7.4|7.4.*|8.0|8.0.*)
            echo "EOL" ;;
        8.1*|8.1.*)
            echo "EOL_SOON" ;;
        *)
            echo "SUPPORTED" ;;
    esac
}

# Returns EOL / SUPPORTED / UNKNOWN for MariaDB / MySQL major.minor versions
db_eol_status() {
    local type="$1" ver="$2" majmin
    majmin="${ver%.*}"
    case "$type" in
        mariadb)
            case "$majmin" in
                10.1|10.2|10.3|10.4|10.5|10.6) echo "EOL" ;;
                10.11|11.4) echo "SUPPORTED" ;;   # current LTS lines
                *) echo "UNKNOWN" ;;
            esac
            ;;
        mysql)
            case "$majmin" in
                5.5|5.6|5.7|8.0) echo "EOL" ;;     # 8.0 EOL Apr 2026
                8.4|9.*) echo "SUPPORTED" ;;
                *) echo "UNKNOWN" ;;
            esac
            ;;
        *)
            echo "UNKNOWN"
            ;;
    esac
}

# ------------------------------------------------------------------------------
# check_scan_health <label> <"bin1 bin2 ..."> <cron_keyword_regex> <"report_glob1 report_glob2 ...">
#
# Verifies malware/rootkit scanning end-to-end instead of trusting a report
# file by itself:
#   1. Is a scanner binary actually installed?
#   2. Is there a cron job that actually runs it (crontab/cron.d/cron.daily etc)?
#   3. Is the most recent matching report file recent (<= 7 days old)?
# Only if ALL THREE hold is it marked GREEN. A report file existing on its
# own (e.g. because the wrapper script prints headings even when the
# underlying scanner never ran) is NOT treated as proof of anything.
# ------------------------------------------------------------------------------
check_scan_health() {
    local label="$1" bins="$2" cron_regex="$3" report_globs="$4"
    local b bin_found=0

    for b in $bins; do
        cmd_exists "$b" && bin_found=1 && break
    done

    if [ "$bin_found" -eq 0 ]; then
        fail "$label" "No scanner installed (checked: $bins) - install and configure one; a report file alone is not proof scanning is happening"
        return
    fi

    # Gather cron sources: user crontab, system cron.d/crontab, and the
    # periodic cron directories (checking both filenames and file contents,
    # since scan scripts are often just dropped in cron.daily/cron.weekly).
    local cron_blob f
    cron_blob=$( { crontab -l 2>/dev/null; cat /etc/cron.d/* /etc/crontab 2>/dev/null; \
        for f in /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do \
            [ -f "$f" ] && { echo "$f"; cat "$f" 2>/dev/null; }; done; } 2>/dev/null )

    if ! echo "$cron_blob" | grep -qEi "$cron_regex"; then
        fail "$label" "Scanner is installed but no scheduled cron job found for it - schedule regular scans"
        return
    fi

    # Find the most recently modified matching report file, if any.
    local latest_report="" latest_ts=0 pattern ts
    for pattern in $report_globs; do
        for f in $pattern; do
            [ -f "$f" ] || continue
            ts=$(stat -c %Y "$f" 2>/dev/null || echo 0)
            if [ "$ts" -gt "$latest_ts" ]; then
                latest_ts=$ts
                latest_report="$f"
            fi
        done
    done

    if [ -z "$latest_report" ]; then
        warn "$label" "Scanner installed and cron job found, but no report file located - verify the cron job is actually executing"
        return
    fi

    local now age_days
    now=$(date +%s)
    age_days=$(( (now - latest_ts) / 86400 ))
    if [ "$age_days" -le 7 ]; then
        pass "$label" "Scanner installed, cron job found, latest report '$latest_report' is $age_days day(s) old"
    else
        fail "$label" "Latest report '$latest_report' is $age_days day(s) old - stale, verify the scan is actually running (not just installed)"
    fi
}

# ==============================================================================
# 1. SYSTEM INFO
# ==============================================================================
audit_system_info() {
    section "SYSTEM INFORMATION"
    row "Hostname" "$REPORT_HOST"
    row "Audit Date" "$REPORT_DATE"
    row "OS" "$OS_PRETTY"
    row "Kernel" "$(uname -r)"
    row "Uptime" "$(uptime -p 2>/dev/null || uptime)"
    PRIMARY_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
    row "Primary IP" "${PRIMARY_IP:-Unknown}"
}

# ==============================================================================
# 2. THREAT PROTECTION
# ==============================================================================
audit_threat_protection() {
    section "THREAT PROTECTION"

    # --- Firewall ---
    if cmd_exists firewall-cmd && service_active firewalld; then
        pass "System Firewall" "firewalld active"
    elif cmd_exists ufw && ufw status 2>/dev/null | grep -qi "active"; then
        pass "System Firewall" "ufw active"
    elif cmd_exists iptables && [ "$(iptables -L 2>/dev/null | wc -l)" -gt 8 ]; then
        pass "System Firewall" "iptables rules present"
    elif cmd_exists nft && nft list ruleset 2>/dev/null | grep -q .; then
        pass "System Firewall" "nftables rules present"
    else
        fail "System Firewall" "No active firewall detected (firewalld/ufw/iptables/nft)"
    fi

    # --- Malware Scanner ---
    if service_active clamd || cmd_exists clamscan || cmd_exists maldet; then
        pass "Malware Scanner" "$(cmd_exists clamscan && echo ClamAV || echo Maldet) installed"
    else
        fail "Malware Scanner" "No malware scanner found - recommend installing and configuring ClamAV or Maldet"
    fi

    # --- Failed Login Detection ---
    if service_active fail2ban; then
        pass "Failed Login Detection" "fail2ban active"
    elif service_active sshguard; then
        pass "Failed Login Detection" "sshguard active"
    elif cmd_exists denyhosts; then
        pass "Failed Login Detection" "denyhosts installed"
    else
        fail "Failed Login Detection" "No brute-force protection (fail2ban/sshguard/denyhosts)"
    fi

    # --- Web Application Firewall ---
    WAF_FOUND=0
    if cmd_exists apachectl || cmd_exists httpd || cmd_exists apache2; then
        if apachectl -M 2>/dev/null | grep -qi security2 || \
           httpd -M 2>/dev/null | grep -qi security2 || \
           apache2ctl -M 2>/dev/null | grep -qi security2; then
            WAF_FOUND=1
        fi
    fi
    if [ -d /etc/nginx ] && grep -rq "modsecurity on" /etc/nginx 2>/dev/null; then
        WAF_FOUND=1
    fi
    if [ "$WAF_FOUND" -eq 1 ]; then
        pass "Web Application Firewall" "mod_security / ModSecurity enabled"
    else
        fail "Web Application Firewall" "mod_security not detected/enabled"
    fi

    # --- Rootkit Scanner ---
    if cmd_exists rkhunter; then
        pass "Rootkit Scanner" "rkhunter installed"
    elif cmd_exists chkrootkit; then
        pass "Rootkit Scanner" "chkrootkit installed"
    else
        fail "Rootkit Scanner" "No rootkit scanner found - recommend installing and configuring rkhunter or chkrootkit"
    fi
}

# ==============================================================================
# 3. SOFTWARE UPDATES
# ==============================================================================
audit_software_updates() {
    section "SOFTWARE UPDATES"

    na "Control Panel" "No control panel installed on this server"

    # --- OS updates ---
    UPGRADABLE_PKGS=""
    if [ "$PKG_FAMILY" = "rpm" ]; then
        UPDATE_RAW=$("$PKG_MGR" -q check-update 2>/dev/null | grep -v "^$")
        UPDATES=$(echo "$UPDATE_RAW" | grep -vc "^$" 2>/dev/null || echo 0)
        UPGRADABLE_PKGS=$(echo "$UPDATE_RAW" | awk '{print $1}' | sed 's/\..*$//')
    elif [ "$PKG_FAMILY" = "deb" ]; then
        apt-get -s upgrade >/tmp/.audit_apt_check 2>/dev/null
        UPDATES=$(grep -c "^Inst " /tmp/.audit_apt_check 2>/dev/null)
        UPGRADABLE_PKGS=$(grep "^Inst " /tmp/.audit_apt_check 2>/dev/null | awk '{print $2}')
        rm -f /tmp/.audit_apt_check
    else
        UPDATES="unknown"
    fi
    if [ "$UPDATES" = "unknown" ]; then
        warn "Operating System" "Could not determine package manager"
    elif [ "$UPDATES" -eq 0 ] 2>/dev/null; then
        pass "Operating System" "No pending OS package updates"
    else
        fail "Operating System" "$UPDATES pending OS package update(s) available"
    fi

    # --- PHP ---
    PHP_BIN="$(command -v php || command -v php-cli || true)"
    if [ -n "$PHP_BIN" ]; then
        PHP_VER="$($PHP_BIN -r 'echo PHP_VERSION;' 2>/dev/null)"
        EOL_STATUS="$(php_eol_status "$PHP_VER")"
        if [ "$EOL_STATUS" = "SUPPORTED" ]; then
            pass "PHP" "Version $PHP_VER (supported)"
        elif [ "$EOL_STATUS" = "EOL_SOON" ]; then
            warn "PHP" "Version $PHP_VER (nearing EOL, upgrade to 8.2+ recommended)"
        else
            fail "PHP" "Version $PHP_VER is EOL - upgrade to 8.1+ recommended"
        fi
    else
        na "PHP" "PHP not installed"
    fi

    # --- CMS detection ---
    subsection "CMS Detection (scanning web roots, including staging/sub folders)"
    WEB_ROOTS="/var/www /home/*/public_html /usr/share/nginx/html /srv/www"
    CMS_FOUND=0

    for root_glob in $WEB_ROOTS; do
        for dir in $root_glob; do
            [ -d "$dir" ] || continue

            # WordPress - no depth limit so nested/staging installs (e.g.
            # public_html/stage_jan21) are found too, not just the top level.
            while IFS= read -r wpconf; do
                [ -z "$wpconf" ] && continue
                CMS_FOUND=1
                site_dir=$(dirname "$wpconf")
                ver_file="$site_dir/wp-includes/version.php"
                WP_VER=""
                if [ -f "$ver_file" ]; then
                    # Match only the real assignment line (no leading '*',
                    # which is what a docblock comment line starts with).
                    WP_VER=$(grep -E '^\$wp_version[[:space:]]*=' "$ver_file" | head -1 | sed -E "s/.*=\s*'([^']+)'.*/\1/")
                fi
                printf "  %-25s %-15s %s\n" "WordPress" "${WP_VER:-unknown}" "$site_dir"
            done < <(find "$dir" -type f -iname "wp-config.php" 2>/dev/null)

            # Joomla - a Joomla site has configuration.php AT ITS ROOT plus a
            # real joomla.xml manifest. Many WordPress plugins (WooCommerce,
            # Jetpack, etc.) ship their own unrelated "configuration.php"
            # files deep inside vendor/ folders - skip those false matches.
            while IFS= read -r jconf; do
                [ -z "$jconf" ] && continue
                site_dir=$(dirname "$jconf")
                manifest="$site_dir/administrator/manifests/files/joomla.xml"
                [ -f "$manifest" ] || continue
                CMS_FOUND=1
                jver=$(grep -m1 "<version>" "$manifest" | sed -E 's/.*<version>([^<]+)<\/version>.*/\1/')
                printf "  %-25s %-15s %s\n" "Joomla" "${jver:-unknown}" "$site_dir"
            done < <(find "$dir" -maxdepth 3 -type f -iname "configuration.php" 2>/dev/null)

            # Drupal
            while IFS= read -r dsettings; do
                [ -z "$dsettings" ] && continue
                CMS_FOUND=1
                site_dir=$(echo "$dsettings" | sed 's|/sites/default/settings.php||')
                printf "  %-25s %-15s %s\n" "Drupal" "unknown" "$site_dir"
            done < <(find "$dir" -type f -iname "settings.php" -path "*sites/default*" 2>/dev/null)
        done
    done

    if [ "$CMS_FOUND" -eq 1 ]; then
        fail "CMS" "CMS installation(s) found (see list above) - verify each is on the latest version"
    else
        na "CMS" "No common CMS (WordPress/Joomla/Drupal) detected under web roots"
    fi

    # --- Web server ---
    # Check what's actually RUNNING (not just installed binaries) so
    # LiteSpeed/OpenLiteSpeed and similar servers aren't missed.
    RUNNING_WS=$(ps -eo comm= 2>/dev/null | grep -Ei '^(apache2|httpd|nginx|litespeed|openlitespeed|lshttpd|caddy)$' | sort -u)

    WS_FOUND=0
    if echo "$RUNNING_WS" | grep -qiE 'apache2|httpd'; then
        AVER=$( (apachectl -v 2>/dev/null || httpd -v 2>/dev/null || apache2 -v 2>/dev/null) | head -1)
        pass "Web Server (Apache)" "${AVER:-Apache is running}"
        WS_FOUND=1
    fi
    if echo "$RUNNING_WS" | grep -qi nginx; then
        NVER=$(nginx -v 2>&1)
        pass "Web Server (Nginx)" "$NVER"
        WS_FOUND=1
    fi
    if echo "$RUNNING_WS" | grep -qiE 'litespeed|lshttpd'; then
        LSWS_VER=""
        if [ -f /usr/local/lsws/VERSION ]; then
            LSWS_VER=$(cat /usr/local/lsws/VERSION 2>/dev/null)
        elif [ -x /usr/local/lsws/bin/lshttpd ]; then
            LSWS_VER=$(/usr/local/lsws/bin/lshttpd -v 2>&1 | head -1)
        fi
        pass "Web Server (LiteSpeed)" "LiteSpeed/OpenLiteSpeed running${LSWS_VER:+ - $LSWS_VER}"
        WS_FOUND=1
    fi
    if [ "$WS_FOUND" -eq 0 ]; then
        # Fall back to binary presence in case the process name didn't match
        if cmd_exists apachectl || cmd_exists httpd || cmd_exists apache2 || cmd_exists nginx || [ -d /usr/local/lsws ]; then
            warn "Web Server" "Web server binary found but not confirmed running - verify manually"
        else
            na "Web Server" "No Apache/Nginx/LiteSpeed installation detected"
        fi
    fi

    # --- Database server ---
    DB_TYPE=""
    DB_VER=""
    if cmd_exists mysql; then
        DB_RAW="$(mysql --version)"
        pass "Database Server" "$DB_RAW"
        if echo "$DB_RAW" | grep -qi mariadb; then
            DB_TYPE="mariadb"
            DB_VER=$(echo "$DB_RAW" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        else
            DB_TYPE="mysql"
            DB_VER=$(echo "$DB_RAW" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        fi
    elif cmd_exists psql; then
        DB_RAW="$(psql --version)"
        pass "Database Server" "$DB_RAW"
        DB_TYPE="postgresql"
        DB_VER=$(echo "$DB_RAW" | grep -oE '[0-9]+\.[0-9]+' | head -1)
    else
        na "Database Server" "No MySQL/MariaDB/PostgreSQL detected"
    fi

    # --- Other software (mail, DNS) ---
    OTHER=""
    cmd_exists postfix && OTHER="$OTHER postfix"
    cmd_exists exim && OTHER="$OTHER exim"
    cmd_exists named && OTHER="$OTHER bind9 named"

    if [ -z "$OTHER" ]; then
        na "Other Softwares" "No mail/DNS daemons detected"
    else
        OTHER_PENDING=""
        for pkg in $OTHER; do
            if echo "$UPGRADABLE_PKGS" | grep -qiw "$pkg"; then
                OTHER_PENDING="$OTHER_PENDING $pkg"
            fi
        done
        if [ -n "$OTHER_PENDING" ]; then
            fail "Other Softwares" "Other software updates are available on the server ($OTHER_PENDING)"
        else
            pass "Other Softwares" "Detected:$OTHER - no pending updates"
        fi
    fi
}

# ==============================================================================
# 4. SERVER HEALTH
# ==============================================================================
audit_server_health() {
    section "SERVER HEALTH"

    row "Server Uptime" "$(uptime -p 2>/dev/null || uptime)"

    if [ -n "${PRIMARY_IP:-}" ] && cmd_exists curl; then
        if curl -o /dev/null -s -m 5 -w "%{http_code}" "http://127.0.0.1" | grep -qE "^[23]"; then
            pass "HTTP Uptime" "Local HTTP responds"
        else
            warn "HTTP Uptime" "No HTTP response on localhost (may be normal if no web server)"
        fi
    else
        na "HTTP Uptime" "curl not available"
    fi

    # CPU
    CPU_LOAD=$(cut -d' ' -f1 /proc/loadavg 2>/dev/null)
    NCPU=$(nproc 2>/dev/null || echo 1)
    row "CPU Usage" "Load avg (1m): $CPU_LOAD on $NCPU core(s)"

    # RAM
    if cmd_exists free; then
        MEM_LINE=$(free -m | awk '/^Mem:/ {printf "%.0f%% used (%sMB / %sMB)", $3/$2*100, $3, $2}')
        MEM_PCT=$(free -m | awk '/^Mem:/ {printf "%.0f", $3/$2*100}')
        if [ "$MEM_PCT" -ge 90 ] 2>/dev/null; then
            fail "RAM Usage" "$MEM_LINE"
        else
            pass "RAM Usage" "$MEM_LINE"
        fi
    fi

    # Disk
    subsection "Disk Space Usage"
    while read -r line; do
        USE=$(echo "$line" | awk '{print $5}' | tr -d '%')
        MNT=$(echo "$line" | awk '{print $6}')
        FS=$(echo "$line" | awk '{print $1}')
        if [ "$USE" -ge 90 ] 2>/dev/null; then
            fail "Disk ($MNT)" "$USE% used on $FS - CRITICAL"
        elif [ "$USE" -ge 80 ] 2>/dev/null; then
            warn "Disk ($MNT)" "$USE% used on $FS - monitor"
        else
            pass "Disk ($MNT)" "$USE% used on $FS"
        fi
    done < <(df -hP -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | tail -n +2)

    # Mail queue
    if cmd_exists mailq; then
        QCOUNT=$(mailq 2>/dev/null | grep -c "^[A-F0-9]" )
        if [ "$QCOUNT" -gt 50 ]; then
            fail "Email Queue" "$QCOUNT messages queued - investigate"
        else
            pass "Email Queue" "$QCOUNT messages queued"
        fi
    else
        na "Email Queue" "No local MTA / mailq not available"
    fi

    # --- IP Reputation: real check via public DNSBLs (no API key needed) ---
    if [ -n "${PRIMARY_IP:-}" ] && cmd_exists dig; then
        REV_IP=$(echo "$PRIMARY_IP" | awk -F. '{print $4"."$3"."$2"."$1}')
        DNSBL_ZONES="zen.spamhaus.org bl.spamcop.net dnsbl.sorbs.net b.barracudacentral.org"
        LISTED_ON=""
        for zone in $DNSBL_ZONES; do
            RESULT=$(dig +short +time=3 +tries=1 "${REV_IP}.${zone}" A 2>/dev/null)
            # DNSBL convention: a real listing returns an address in the
            # 127.0.0.0/8 range. Some resolvers/networks return a bogus
            # non-empty answer for ANY query (DNS hijacking/captive portals),
            # which would otherwise show every zone as "listed" incorrectly -
            # so only trust results that actually follow the 127.x convention.
            if echo "$RESULT" | grep -qE '^127\.'; then
                LISTED_ON="$LISTED_ON $zone($RESULT)"
            fi
        done
        if [ -n "$LISTED_ON" ]; then
            fail "IP Reputation" "$PRIMARY_IP is LISTED on:$LISTED_ON - request delisting after resolving the cause"
        else
            pass "IP Reputation" "$PRIMARY_IP not listed on: $DNSBL_ZONES"
        fi
        row "IP Reputation (note)" "Please also double-check in an online blacklist checker (e.g. MXToolbox, mxtoolbox.com/blacklists.aspx) to confirm"
    else
        warn "IP Reputation" "dig not available or IP unknown - please check in a blacklist checker (e.g. MXToolbox) manually"
    fi
}

# ==============================================================================
# 5. BACKUP
# ==============================================================================
audit_backup() {
    section "BACKUP"

    BACKUP_DIRS="/backup /backups /home/backup /var/backups"
    FOUND_DIR=""
    for d in $BACKUP_DIRS; do
        [ -d "$d" ] && FOUND_DIR="$d" && break
    done

    if [ -n "$FOUND_DIR" ]; then
        pass "Local Backup" "Backup directory found: $FOUND_DIR"
    else
        fail "Local Backup" "No standard local backup directory found"
    fi

    if cmd_exists rclone || cmd_exists restic || cmd_exists duplicity || cmd_exists s3cmd; then
        TOOL=$(cmd_exists rclone && echo rclone || cmd_exists restic && echo restic || cmd_exists duplicity && echo duplicity || echo s3cmd)
        pass "Remote Backup" "Remote backup tool detected: $TOOL"
    else
        fail "Remote Backup" "No remote/offsite backup tool detected (rclone/restic/duplicity/s3cmd)"
    fi

    # Cron based backup jobs
    CRON_BACKUP=$( (crontab -l 2>/dev/null; cat /etc/cron.d/* /etc/crontab 2>/dev/null) | grep -iE "backup|rsync|tar |mysqldump" | grep -v "^#")
    if [ -n "$CRON_BACKUP" ]; then
        pass "Scheduled Backup Job" "Cron backup job(s) found"
        DAILY=$(echo "$CRON_BACKUP" | grep -cE "^[0-9\*]+ [0-9\*]+ \* \* \*")
        [ "$DAILY" -gt 0 ] && pass "Daily Backup" "$DAILY daily cron backup job(s)" || na "Daily Backup" "None matched daily pattern"
    else
        fail "Scheduled Backup Job" "No backup-related cron jobs found"
        na "Daily Backup" "N/A"
        na "Weekly Backup" "N/A"
        na "Monthly Backup" "N/A"
    fi

    if [ -n "$FOUND_DIR" ]; then
        LATEST=$(find "$FOUND_DIR" -maxdepth 2 -type f -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1)
        if [ -n "$LATEST" ]; then
            LAST_TS=$(echo "$LATEST" | awk '{print $1}')
            LAST_FILE=$(echo "$LATEST" | cut -d' ' -f2-)
            NOW=$(date +%s)
            AGE_DAYS=$(( (NOW - ${LAST_TS%.*}) / 86400 ))
            SIZE=$(du -h "$LAST_FILE" 2>/dev/null | cut -f1)
            if [ "$AGE_DAYS" -le 2 ]; then
                pass "Recent Last Backup" "$LAST_FILE - $AGE_DAYS day(s) old"
            else
                fail "Recent Last Backup" "$LAST_FILE - $AGE_DAYS day(s) old (stale)"
            fi
            row "Size Of Last Backup" "$SIZE"
        else
            fail "Recent Last Backup" "No backup files found inside $FOUND_DIR"
        fi
    fi
}

# ==============================================================================
# 6. SOFTWARE LIFE TIME (EOL)
# ==============================================================================
audit_software_lifetime() {
    section "SOFTWARE LIFE TIME"

    na "Control Panel" "No control panel installed on this server"

    OS_STATUS="$(os_eol_status "$OS_ID" "$OS_VERSION")"
    case "$OS_STATUS" in
        EOL)      fail "Operating System" "$OS_PRETTY is EOL - plan migration to a supported release" ;;
        SUPPORTED) pass "Operating System" "$OS_PRETTY is within support" ;;
        *)        warn "Operating System" "$OS_PRETTY - EOL status unknown, verify manually" ;;
    esac

    if [ -n "${PHP_VER:-}" ]; then
        case "$(php_eol_status "$PHP_VER")" in
            EOL)      fail "PHP Lifetime" "PHP $PHP_VER is EOL" ;;
            EOL_SOON) warn "PHP Lifetime" "PHP $PHP_VER nearing EOL" ;;
            *)        pass "PHP Lifetime" "PHP $PHP_VER is supported" ;;
        esac
    else
        na "PHP Lifetime" "PHP not installed"
    fi

    if [ "$CMS_FOUND" -eq 1 ] 2>/dev/null; then
        warn "CMS Lifetime" "CMS detected - manually verify against latest release"
    else
        na "CMS Lifetime" "No CMS detected"
    fi

    if [ -n "${DB_TYPE:-}" ] && [ -n "${DB_VER:-}" ]; then
        case "$(db_eol_status "$DB_TYPE" "$DB_VER")" in
            EOL)       fail "Database Server Lifetime" "$DB_TYPE $DB_VER is EOL - upgrade recommended" ;;
            SUPPORTED) pass "Database Server Lifetime" "$DB_TYPE $DB_VER is within support" ;;
            *)         warn "Database Server Lifetime" "$DB_TYPE $DB_VER - EOL status unknown, verify manually" ;;
        esac
    else
        na "Database Server Lifetime" "No database server detected"
    fi

    if cmd_exists apachectl || cmd_exists httpd || cmd_exists apache2 || cmd_exists nginx; then
        warn "Web Server Lifetime" "Confirm Apache/Nginx version is still receiving security updates from the OS vendor"
    else
        na "Web Server Lifetime" "No Apache/Nginx installation detected"
    fi
}

# ==============================================================================
# 7. PROACTIVE DEFENCE
# ==============================================================================
audit_proactive_defence() {
    section "PROACTIVE DEFENCE"

    # /tmp security
    TMP_OPTS=$(findmnt -no OPTIONS /tmp 2>/dev/null)
    if echo "$TMP_OPTS" | grep -q "noexec"; then
        pass "/tmp Security" "/tmp mounted with noexec ($TMP_OPTS)"
    else
        fail "/tmp Security" "/tmp is NOT secured with noexec - executable scripts can run from /tmp"
    fi

    warn "Reboot Procedure" "Confirm remote/DC reboot access & credentials are documented"

    # IP RDNS
    if [ -n "${PRIMARY_IP:-}" ] && cmd_exists dig; then
        PTR=$(dig +short -x "$PRIMARY_IP" 2>/dev/null)
        if [ -n "$PTR" ]; then
            pass "IP RDNS" "PTR record: $PTR"
        else
            fail "IP RDNS" "No PTR (reverse DNS) record configured for $PRIMARY_IP"
        fi
    else
        warn "IP RDNS" "dig not available or IP unknown - check manually"
    fi

    # Malware & rootkit scanning: verified end-to-end (binary + cron +
    # recent report) rather than trusting any single signal on its own -
    # a report file existing (even one printing empty section headings)
    # is never by itself treated as proof scanning is configured correctly.
    check_scan_health "Malware Scan" \
        "clamscan maldet" \
        "clamscan|clamdscan|maldet|malware-scan|malware.scan" \
        "/root/scripts/*malware*report* /root/scripts/*malware-scan* /var/log/clamav/*.log /usr/local/maldetect/logs/* /var/log/maldet/*"

    check_scan_health "Rootkit Check" \
        "rkhunter chkrootkit" \
        "rkhunter|chkrootkit|rootkit" \
        "/root/scripts/*rootkit*report* /root/scripts/*malware*report* /var/log/rkhunter.log /var/log/chkrootkit.log /var/log/chkrootkit/*"

    # SSH root login
    SSHD_CONF="/etc/ssh/sshd_config"
    if [ -f "$SSHD_CONF" ]; then
        ROOT_LOGIN=$(grep -iE "^\s*PermitRootLogin" "$SSHD_CONF" | awk '{print $2}' | tail -1)
        if [ -z "$ROOT_LOGIN" ] || [ "$ROOT_LOGIN" = "yes" ]; then
            fail "SSH Root Access Security" "PermitRootLogin is enabled (yes/default) - disable direct root SSH login"
        else
            pass "SSH Root Access Security" "PermitRootLogin set to '$ROOT_LOGIN'"
        fi
    else
        na "SSH Root Access Security" "sshd_config not found"
    fi

    # PHP dangerous functions
    if [ -n "${PHP_BIN:-}" ]; then
        DISABLED=$($PHP_BIN -r 'echo ini_get("disable_functions");' 2>/dev/null)
        DANGEROUS="exec shell_exec system passthru proc_open popen show_source"
        MISSING=""
        for f in $DANGEROUS; do
            echo "$DISABLED" | grep -qw "$f" || MISSING="$MISSING $f"
        done
        if [ -z "$MISSING" ]; then
            pass "PHP Functions Security" "All common dangerous functions are disabled"
        else
            fail "PHP Functions Security" "Dangerous functions still enabled:$MISSING"
        fi
    else
        na "PHP Functions Security" "PHP not installed"
    fi

    # Root password age
    if cmd_exists chage; then
        LAST_CHANGE=$(chage -l root 2>/dev/null | grep "Last password change" | cut -d: -f2 | sed 's/^ //')
        if [ "$LAST_CHANGE" = "never" ] || [ -z "$LAST_CHANGE" ]; then
            fail "Root Password Health" "Root password change date unknown/never set"
        else
            LAST_EPOCH=$(date -d "$LAST_CHANGE" +%s 2>/dev/null)
            NOW_EPOCH=$(date +%s)
            if [ -n "$LAST_EPOCH" ]; then
                AGE=$(( (NOW_EPOCH - LAST_EPOCH) / 86400 ))
                if [ "$AGE" -le 90 ]; then
                    pass "Root Password Health" "Changed $AGE day(s) ago ($LAST_CHANGE)"
                else
                    fail "Root Password Health" "Changed $AGE day(s) ago ($LAST_CHANGE) - exceeds 90-day policy"
                fi
            else
                warn "Root Password Health" "Could not parse last change date: $LAST_CHANGE"
            fi
        fi
    else
        na "Root Password Health" "chage not available"
    fi
}

# ==============================================================================
# 8. USER PASSWORD AGE (all interactive users, 90-day policy)
# ==============================================================================
audit_password_policy() {
    section "USER PASSWORD AGE (90-DAY POLICY)"
    if ! cmd_exists chage; then
        na "Password Age Check" "chage not available on this system"
        return
    fi
    NOW_EPOCH=$(date +%s)
    while IFS=: read -r user _ uid _ _ home shell; do
        [ "$uid" -lt 1000 ] 2>/dev/null && continue
        case "$shell" in
            */nologin|*/false) continue ;;
        esac
        LAST_CHANGE=$(chage -l "$user" 2>/dev/null | grep "Last password change" | cut -d: -f2 | sed 's/^ //')
        if [ "$LAST_CHANGE" = "never" ] || [ -z "$LAST_CHANGE" ]; then
            fail "User: $user" "Password never changed / unknown"
            continue
        fi
        LAST_EPOCH=$(date -d "$LAST_CHANGE" +%s 2>/dev/null)
        if [ -z "$LAST_EPOCH" ]; then
            warn "User: $user" "Could not parse date: $LAST_CHANGE"
            continue
        fi
        AGE=$(( (NOW_EPOCH - LAST_EPOCH) / 86400 ))
        if [ "$AGE" -le 90 ]; then
            pass "User: $user" "Changed $AGE day(s) ago"
        else
            fail "User: $user" "Changed $AGE day(s) ago - exceeds 90-day policy"
        fi
    done < /etc/passwd
}

# ==============================================================================
# SUMMARY
# ==============================================================================
audit_summary() {
    section "AUDIT SUMMARY"
    row "Total GREEN (Good)" "$PASS_COUNT"
    row "Total RED (Action Needed)" "$FAIL_COUNT"
    row "Total N/A" "$NA_COUNT"
    row "Total Manual Check Needed" "$WARN_COUNT"
    echo
    echo "Report generated for $REPORT_HOST on $REPORT_DATE"
}

# ==============================================================================
# MAIN
# ==============================================================================
main() {
    need_root
    detect_os
    audit_system_info
    audit_threat_protection
    audit_software_updates
    audit_server_health
    audit_backup
    audit_software_lifetime
    audit_proactive_defence
    audit_password_policy
    audit_summary
}

main "$@"
