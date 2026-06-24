#!/bin/bash

# Verbose version - shows all errors and deletion attempts
# Usage: sudo ./compact-ufw-rules-verbose.sh

set -euo pipefail

LOG_FILE="/var/log/ufw-compact.log"
MIN_IPS_PER_SUBNET=2

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

log "Starting UFW rule compaction (VERBOSE MODE)"

# Parse ufw rules
while IFS= read -r line; do
    if [[ -z "$line" ]] || [[ "$line" =~ ^"Status:" ]] || [[ "$line" =~ ^"--" ]]; then
        continue
    fi

    if [[ "$line" =~ "DENY" ]] && ! [[ "$line" =~ "/" ]]; then
        if ip=$(extract_ip "$line"); then
            subnet=$(get_subnet "$ip")

            if [[ -z "${subnet_ips[$subnet]:-}" ]]; then
                subnet_ips[$subnet]=""
            fi
            subnet_ips[$subnet]+="$ip "

            rule_num=$(echo "$line" | awk '{print $1}' | tr -d '[]')
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

        if sudo ufw status | grep -q "$subnet\.0/24"; then
            log "Subnet $subnet.0/24 already has a rule, skipping"
            continue
        fi

        log "Consolidating $ip_count IPs in $subnet.0/24"
        log "  IPs: ${subnet_ips[$subnet]}"
        log "  Rule numbers stored: ${subnet_rules[$subnet]}"

        # DELETE individual IPs FIRST
        if [[ -n "${subnet_rules[$subnet]:-}" ]]; then
            rules_array=(${subnet_rules[$subnet]})
            log "  Array has ${#rules_array[@]} elements: [${rules_array[*]}]"

            echo "═══════════════════════════════════════"
            echo "BEFORE DELETION:"
            sudo ufw status numbered | grep "$subnet" || true
            echo

            log "  Starting deletion (highest rule number first)..."
            for ((i=${#rules_array[@]}-1; i>=0; i--)); do
                rule_num=${rules_array[i]}
                echo "    → Attempting to delete rule #$rule_num..."
                if sudo ufw delete "$rule_num" <<< "y" 2>&1 | tee -a "$LOG_FILE"; then
                    log "    ✓ Successfully removed rule #$rule_num"
                else
                    log "    ✗ FAILED to remove rule #$rule_num"
                fi
            done

            echo
            echo "AFTER DELETION:"
            sudo ufw status numbered | grep "$subnet" || echo "  (no matching rules found)"
            echo "═══════════════════════════════════════"
            echo
        fi

        # THEN add the /24 rule
        log "  Adding /24 rule: deny from $subnet.0/24"
        if sudo ufw insert 1 deny from "$subnet.0/24" 2>&1 | tee -a "$LOG_FILE"; then
            log "  ✓ Successfully added /24 rule"
        else
            log "  ✗ FAILED to add /24 rule"
        fi
    fi
done

log "Consolidation complete. Processed $consolidations subnets"

echo
echo "═══════════════════════════════════════"
echo "FINAL UFW STATUS:"
echo "═══════════════════════════════════════"
sudo ufw status numbered | grep "DENY"