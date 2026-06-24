#!/bin/bash

# Automatic UFW rule compaction - cron-friendly version
# Usage: sudo ./compact-ufw-rules-auto.sh
# Can be added to crontab to run periodically (e.g., weekly)

set -euo pipefail

LOG_FILE="/var/log/ufw-compact.log"
MIN_IPS_PER_SUBNET=2

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

if [[ $EUID -ne 0 ]]; then
    log "Error: This script must be run as root"
    exit 1
fi

extract_ip() {
    grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' <<< "$1" | head -1 || return 1
}

get_subnet() {
    echo "$1" | cut -d'.' -f1-3
}

declare -A subnet_ips

log "Starting UFW rule compaction"

# Phase 1: Parse all DENY rules with individual IPs
# Format: "[721] Anywhere                   DENY IN     172.71.184.67"
while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^"Status:" || "$line" =~ ^"--" ]] && continue

    if [[ "$line" =~ "DENY" ]] && ! [[ "$line" =~ "/" ]]; then
        if ip=$(extract_ip "$line"); then
            subnet=$(get_subnet "$ip")
            subnet_ips[$subnet]+="$ip "
        fi
    fi
done < <(sudo ufw status numbered 2>/dev/null | tail -n +4)

# Phase 2: Identify subnets to consolidate
subnets_to_consolidate=()
subnets_to_cleanup=()
for subnet in "${!subnet_ips[@]}"; do
    ip_count=$(echo "${subnet_ips[$subnet]}" | wc -w)

    if [[ $ip_count -ge $MIN_IPS_PER_SUBNET ]]; then
        if sudo ufw status | grep -q "$subnet\.0/24"; then
            # /24 rule exists but individual IPs still need cleaning up
            subnets_to_cleanup+=("$subnet")
            log "Subnet $subnet.0/24 already has a rule, will clean up $ip_count individual IPs"
        else
            subnets_to_consolidate+=("$subnet")
            log "Will consolidate $ip_count IPs in $subnet.0/24"
        fi
    fi
done

all_subnets=("${subnets_to_consolidate[@]}" "${subnets_to_cleanup[@]}")

if [[ ${#all_subnets[@]} -eq 0 ]]; then
    log "Nothing to consolidate"
    exit 0
fi

# Phase 3: Collect ALL rule numbers to delete across all subnets
# Re-read numbered rules to get current numbers
rules_to_delete=()
while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^"Status:" || "$line" =~ ^"--" ]] && continue

    if [[ "$line" =~ "DENY" ]] && ! [[ "$line" =~ "/" ]]; then
        if ip=$(extract_ip "$line"); then
            subnet=$(get_subnet "$ip")
            for target in "${all_subnets[@]}"; do
                if [[ "$subnet" == "$target" ]]; then
                    rule_num=$(echo "$line" | awk '{print $1}' | tr -d '[]')
                    if [[ $rule_num =~ ^[0-9]+$ ]]; then
                        rules_to_delete+=("$rule_num")
                    fi
                    break
                fi
            done
        fi
    fi
done < <(sudo ufw status numbered 2>/dev/null | tail -n +4)

# Phase 4: Delete ALL individual rules in one pass, highest number first
IFS=$'\n' sorted_rules=($(printf '%s\n' "${rules_to_delete[@]}" | sort -rn))
unset IFS

log "Deleting ${#sorted_rules[@]} individual rules (descending: ${sorted_rules[*]})"

for rule_num in "${sorted_rules[@]}"; do
    if sudo ufw delete "$rule_num" <<< "y" >/dev/null 2>&1; then
        log "Removed rule #$rule_num"
    else
        log "Warning: Failed to remove rule #$rule_num"
    fi
done

# Phase 5: Add /24 rules only for newly consolidated subnets
if [[ ${#subnets_to_consolidate[@]} -gt 0 ]]; then
    for subnet in "${subnets_to_consolidate[@]}"; do
        if sudo ufw insert 1 deny from "$subnet.0/24" >/dev/null 2>&1; then
            log "Added rule: deny from $subnet.0/24"
        else
            log "Failed to add rule for $subnet.0/24"
        fi
    done
fi

total_rules=$(sudo ufw status numbered 2>/dev/null | grep -c "DENY" || echo 0)
log "Consolidation complete. New: ${#subnets_to_consolidate[@]}, cleaned up: ${#subnets_to_cleanup[@]}. Total rules now: $total_rules"