#!/bin/bash

# Automatic UFW rule compaction - cron-friendly version
# Usage: sudo ./compact-ufw-rules-auto.sh
# Can be added to crontab to run periodically (e.g., weekly)

set -euo pipefail

LOG_FILE="/var/log/ufw-compact.log"
MIN_IPS_PER_SUBNET=2
DRY_RUN=false

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log "Error: This script must be run as root"
        exit 1
    fi
}

extract_ip() {
    local rule="$1"
    grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' <<< "$rule" | head -1 || return 1
}

get_subnet() {
    local ip="$1"
    echo "$ip" | cut -d'.' -f1-3
}

check_root

declare -A subnet_ips
declare -A subnet_rules
declare -A processed_subnets

log "Starting UFW rule compaction"

# Parse ufw rules
# Format: "1    Anywhere                   DENY        192.168.1.1"
while IFS= read -r line; do
    if [[ -z "$line" ]] || [[ "$line" =~ ^"Status:" ]] || [[ "$line" =~ ^"--" ]]; then
        continue
    fi
    
    # Look for DENY rules with individual IPs (not CIDR notation like /24)
    if [[ "$line" =~ "DENY" ]] && ! [[ "$line" =~ "/" ]]; then
        if ip=$(extract_ip "$line"); then
            subnet=$(get_subnet "$ip")
            
            if [[ -z "${subnet_ips[$subnet]:-}" ]]; then
                subnet_ips[$subnet]=""
            fi
            subnet_ips[$subnet]+="$ip "
            
            # Extract rule number from beginning of line (first non-whitespace token)
            rule_num=$(echo "$line" | awk '{print $1}')
            if [[ $rule_num =~ ^[0-9]+$ ]]; then
                if [[ -z "${subnet_rules[$subnet]:-}" ]]; then
                    subnet_rules[$subnet]=""
                fi
                subnet_rules[$subnet]+="$rule_num "
            fi
        fi
    fi
done < <(sudo ufw status numbered 2>/dev/null | tail -n +4)

consolidations=0
for subnet in "${!subnet_ips[@]}"; do
    ip_count=$(echo "${subnet_ips[$subnet]}" | wc -w)
    
    if [[ $ip_count -ge $MIN_IPS_PER_SUBNET ]]; then
        consolidations=$((consolidations + 1))
        
        # Check if we already have a /24 rule for this subnet
        if sudo ufw status | grep -q "$subnet\.0/24"; then
            log "Subnet $subnet.0/24 already has a rule, skipping"
            continue
        fi
        
        log "Consolidating $ip_count IPs in $subnet.0/24"
        
        # Add the /24 rule
        if sudo ufw insert 1 deny from "$subnet.0/24" >/dev/null 2>&1; then
            log "Added rule: deny from $subnet.0/24"
            
            # Delete individual IPs (in reverse order)
            if [[ -n "${subnet_rules[$subnet]:-}" ]]; then
                rules_array=(${subnet_rules[$subnet]})
                for ((i=${#rules_array[@]}-1; i>=0; i--)); do
                    rule_num=${rules_array[i]}
                    if sudo ufw delete "$rule_num" <<< "y" >/dev/null 2>&1; then
                        log "Removed individual rule #$rule_num"
                    fi
                done
            fi
        else
            log "Failed to add rule for $subnet.0/24"
        fi
    fi
done

log "Consolidation complete. Processed $consolidations subnets"

# Output stats
total_rules=$(sudo ufw status numbered 2>/dev/null | grep -c "DENY" || echo 0)
log "Current total rules: $total_rules"
