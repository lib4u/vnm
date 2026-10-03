#!/usr/bin/env bash
# Flow stand (tests.md §1): a node with an uplink, an exit and a downstream
# tunnel-like interface, and an "internet" with an RU site, a foreign site and
# an RU client. Runs inside `unshare -Urnm --map-auto --pid --fork`; the outer network
# namespace is the node, and every process dies with the script.
#
# The script only measures. Every scenario prints one line, "<id> <result>",
# where the result is what the far side saw ("src=<addr>") or the error the
# client got ("err=<reason>"); the Go test decides what is right.
#
#   stand.sh <dir> <enforce|observe>
# <dir> holds vnm.nft, routing.sh, probe.py, resolver.json and the vnm binary;
# $RESOLVER_UID is the user the resolver runs as.
set -euo pipefail

dir=$1
mode=$2
probe="python3 $dir/probe.py"

NODE=192.0.2.100      # the node's public address, on the uplink
EXIT_EGRESS=198.18.0.2 # where traffic leaving through the exit appears from
RU_SITE=198.51.100.10
RU_CLIENT=198.51.100.50
FOREIGN=203.0.113.10
# An RU domain on a foreign address — like 2ip.ru on Hetzner: only DNS can
# tell it belongs to the policy.
RU_ON_FOREIGN=203.0.113.20
RU_ON_FOREIGN2=203.0.113.21
RU_ON_FOREIGN3=203.0.113.22
RU_ON_FOREIGN4=203.0.113.23
DNS_UPSTREAM=203.0.113.53
# A source in the guard's list; and the management address, in the list too
# but exempt.
SCANNER=203.0.113.66
MGMT=192.0.2.200
# What a container behind DNAT listens on, in the downstream namespace.
CONTAINER=10.77.0.2
# The resolver a host or a client asks on its own.
USUAL_DNS=1.1.1.1
# IPv6: the node's address, an RU site, a foreign site, a scanner.
NODE6=2001:db8:1::100
RU_SITE6=2001:db8:100::10
FOREIGN6=2001:db8:200::10
SCANNER6=2001:db8:666::66

mount -t tmpfs tmpfs /run
mkdir -p /run/netns
for ns in inet warp client ruc; do ip netns add "$ns"; done
nsx() { local ns=$1; shift; ip netns exec "$ns" "$@"; }

link() { # link <nsA|-> <ifA> <nsB> <ifB>
	ip link add "$2" type veth peer name "$4"
	[ "$1" = - ] || ip link set "$2" netns "$1"
	ip link set "$4" netns "$3"
}

# node — inet (uplink)
link - up0 inet i-node
ip addr add $NODE/24 dev up0
nsx inet ip addr add 192.0.2.254/24 dev i-node
ip addr add $NODE6/64 dev up0 nodad
nsx inet ip addr add 2001:db8:1::254/64 dev i-node nodad
# node — warp (exit)
link - warp warp w-node
ip addr add 172.16.0.2/30 dev warp
nsx warp ip addr add 172.16.0.1/30 dev w-node
# node — client (downstream tunnel)
link - dn0 client c0
ip addr add 10.77.0.1/24 dev dn0
nsx client ip addr add 10.77.0.2/24 dev c0
# warp — inet (the exit's own way out)
link warp w-up inet i-warp
nsx warp ip addr add $EXIT_EGRESS/30 dev w-up
nsx inet ip addr add 198.18.0.1/30 dev i-warp
# ruc — inet
link ruc r0 inet i-ruc
nsx ruc ip addr add 10.99.0.2/30 dev r0
nsx ruc ip addr add $RU_CLIENT/32 dev r0
nsx inet ip addr add 10.99.0.1/30 dev i-ruc
# sites
nsx inet ip link add sites type dummy
nsx inet ip addr add $RU_SITE/32 dev sites
nsx inet ip addr add $FOREIGN/32 dev sites
for a in $RU_SITE6 $FOREIGN6 $SCANNER6; do nsx inet ip addr add $a/128 dev sites nodad; done
nsx inet ip addr add $MGMT/32 dev i-node
for a in $RU_ON_FOREIGN $RU_ON_FOREIGN2 $RU_ON_FOREIGN3 $RU_ON_FOREIGN4 $DNS_UPSTREAM $USUAL_DNS $SCANNER; do nsx inet ip addr add $a/32 dev sites; done

for ns in "" inet warp client ruc; do
	for dev in $(${ns:+nsx $ns} ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1); do
		${ns:+nsx $ns} ip link set "$dev" up
	done
done

ip route add default via 192.0.2.254 dev up0
ip -6 route add default via 2001:db8:1::254 dev up0
sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv4.conf.warp.rp_filter=2
nsx inet sysctl -qw net.ipv4.ip_forward=1
nsx inet ip route add $RU_CLIENT/32 via 10.99.0.2
nsx warp sysctl -qw net.ipv4.ip_forward=1
# A real WireGuard exit is point-to-point; the veth standing in for it needs
# proxy ARP on the far side, or "default dev warp" would ARP for every
# destination.
nsx warp sysctl -qw net.ipv4.conf.w-node.proxy_arp=1
nsx warp ip route add default via 198.18.0.1
nsx warp nft add table ip nat
nsx warp nft 'add chain ip nat post { type nat hook postrouting priority srcnat; }'
nsx warp nft add rule ip nat post oifname w-up masquerade
nsx client ip route add default via 10.77.0.1
nsx ruc ip route add default via 10.99.0.1 src $RU_CLIENT

# What a tunnel service does on a real node: masquerade its clients on the
# uplink. The agent does not rely on it for the exit (ТЗ §3.3).
nft add table ip stand
nft 'add chain ip stand post { type nat hook postrouting priority srcnat; }'
nft add rule ip stand post ip saddr 10.77.0.0/24 oifname up0 masquerade
# And what Docker does: publish a port of a container by DNAT.
nft 'add chain ip stand pre { type nat hook prerouting priority dstnat; }'
nft add rule ip stand pre iifname up0 tcp dport 8080 dnat to $CONTAINER:9090

# Servers. Their output is detached: a server holding stdout open would keep
# the caller waiting. They die with the script's PID namespace.
serve() { "$@" >/dev/null 2>&1 & }
serve $probe serve $NODE 22 8851,443
serve nsx inet $probe serve $RU_SITE 80,443 80,443
serve nsx inet $probe serve $FOREIGN 80,6881 80,443,6881
serve nsx inet $probe serve $RU_ON_FOREIGN 80 80
serve nsx inet $probe serve $RU_ON_FOREIGN2 80 80
serve nsx inet $probe serve $RU_ON_FOREIGN3 80 80
serve nsx inet $probe serve $RU_ON_FOREIGN4 80 80
serve nsx inet $probe serve $SCANNER 80 80
serve nsx inet $probe serve $RU_SITE6 80 ""
serve nsx inet $probe serve $FOREIGN6 80 ""
serve $probe serve $NODE6 22 ""
serve nsx client $probe serve $CONTAINER 9090 ""
# The upstream the node's resolver asks, and the resolver a host or a client
# asks on its own: the same answers.
serve nsx inet dnsmasq --no-daemon --pid-file= --no-resolv --no-hosts \
	--listen-address=$DNS_UPSTREAM --listen-address=$USUAL_DNS --bind-interfaces \
	--address=/twoip.ru/$RU_ON_FOREIGN --address=/twoip2.ru/$RU_ON_FOREIGN2 \
	--address=/twoip3.ru/$RU_ON_FOREIGN3 --address=/twoip4.ru/$RU_ON_FOREIGN4 \
	--address=/foreign.test/$FOREIGN
serve nsx ruc $probe serve $RU_CLIENT 9999 9999
sleep 0.5

# F-12 needs a connection that is older than the rules.
flag=$(mktemp -u)
$probe hold $RU_SITE 80 "$flag" >"$dir/f12" &
held=$!
sleep 0.3

nft -f "$dir/vnm.nft"
sh "$dir/routing.sh"
# The node's resolver, run as the unit runs it: as its own user, whose upstream
# queries the host redirect lets out, with CAP_NET_ADMIN alone.
# Its binary goes where its user can run it: <dir> may be private to ours. The
# config comes on standard input, opened by root, as the unit passes it.
mkdir -m 755 /run/vnm-dns
install -m 755 "$dir/vnm" /run/vnm-dns/vnm
setpriv --reuid="$RESOLVER_UID" --regid="$RESOLVER_UID" --clear-groups \
	--inh-caps=+net_admin --ambient-caps=+net_admin \
	/run/vnm-dns/vnm dns serve -config - <"$dir/resolver.json" >"$dir/resolver.log" 2>&1 &
sleep 0.5
touch "$flag"
wait $held
echo "F-12 $(cat "$dir/f12")"

report() { local id=$1; shift; echo "$id $("$@")"; }

report F-1 $probe tcp $RU_SITE 80
report F-3 $probe udp $RU_SITE 80
report F-2 nsx ruc $probe tcp $NODE 22
report F-4 nsx ruc $probe udp $NODE 8851
report F-5 $probe udp $RU_CLIENT 9999 --bind 8851
report F-5x $probe udp $RU_CLIENT 9999
report F-6 nsx client $probe tcp $RU_SITE 80
report F-6u nsx client $probe udp $RU_SITE 80
report F-7 nsx client $probe tcp $FOREIGN 80
report F-7u nsx client $probe udp $FOREIGN 80
# F-9 asks twice over one connection, the second time a moment later.
flag9=$(mktemp -u)
(sleep 0.3; touch "$flag9") &
report F-9 $probe hold $RU_SITE 443 "$flag9"
report F-10 nsx client $probe udp $RU_SITE 443
report F-11 nsx ruc $probe udp $NODE 443
report F-13 $probe udp $RU_SITE 443 --bind 443
report L-1 $probe tcp $FOREIGN 80
# IPv6: exits carry IPv4 only, so an RU destination over IPv6 is blocked; the
# rest of IPv6 is untouched.
report V6-1 $probe tcp $RU_SITE6 80
report V6-2 $probe tcp $FOREIGN6 80

# DNS: a tunnel client asks its usual resolver; the node redirects the query.
report D-3 nsx client $probe tcp $RU_ON_FOREIGN2 80
report D-1 nsx client $probe resolve-tcp $USUAL_DNS twoip.ru 80
report D-2 nsx client $probe resolve-tcp $USUAL_DNS foreign.test 80
report D-3b nsx client $probe resolve-tcp $USUAL_DNS twoip2.ru 80
report D-4 nsx ruc $probe udp $NODE 5353
# The host's own DNS takes the same way — the resolver's own upstream queries
# excepted, or it would ask itself.
report D-5 $probe resolve-tcp $USUAL_DNS twoip3.ru 80
# The resolver is down: the agent empties dns_ports, and DNS goes where it was
# sent, so the node keeps resolving.
nft flush set inet vnm dns_ports
report D-6 $probe resolve-tcp $USUAL_DNS twoip4.ru 80
nft add element inet vnm dns_ports { 53 }

# Guard: new connections from a listed source never reach the node.
report G-0 nsx inet $probe tcp $NODE 22 --src $FOREIGN
report G-1 nsx inet $probe tcp $NODE 22 --src $SCANNER
report G-1u nsx inet $probe udp $NODE 8851 --src $SCANNER
report G-1d nsx inet $probe tcp $NODE 8080 --src $SCANNER
report G-0d nsx inet $probe tcp $NODE 8080 --src $FOREIGN
report G-2 $probe tcp $SCANNER 80
report G-3 nsx inet $probe tcp $NODE 22 --src $MGMT
report G-5 nsx client $probe tcp $SCANNER 80
report G-0v6 nsx inet $probe tcp $NODE6 22 --src $FOREIGN6
report G-1v6 nsx inet $probe tcp $NODE6 22 --src $SCANNER6

# P2P (p2p ТЗ §8): BitTorrent signatures never leave through the uplink, from
# the node's own processes or from a tunnel client; packets that only resemble
# one, and the excluded ports, pass.
# uTP ST_SYN v1: type/ver 0x41, no extension, connection id, timestamp,
# timestamp_difference 0, window, seq, ack — the 20-byte header alone.
UTP_SYN=4100abcd00000001000000000010000000010000
# DHT ping query: d1:ad2:id20:<20 bytes>e1:q4:ping1:t2:aa1:y1:qe
DHT_PING=$(printf 'd1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe' | od -An -tx1 | tr -d ' \n')
# UDP tracker connect: protocol id, action 0, transaction id.
TRACKER=0000041727101980000000001a2b3c4d
# The plaintext handshake: 19, "BitTorrent protocol", reserved, info hash, peer id.
BT_HS=$(printf '\x13BitTorrent protocol' | od -An -tx1 | tr -d ' \n')0000000000000000$(printf '%040d' 0)$(printf '%040d' 0)
# TURN ChannelData on channel 0x4100, 16 bytes of data: its first byte is the
# uTP SYN's, its fields are not.
TURN_CD=41000010deadbeefcafebabe0102030405060708
# STUN binding request: type 0x0001, length 0, magic cookie, transaction id.
STUN=000100002112a442000102030405060708090a0b
report P-1 $probe udp $FOREIGN 6881 --payload $UTP_SYN
report P-1t nsx client $probe udp $FOREIGN 6881 --payload $UTP_SYN
report P-2 $probe udp $FOREIGN 6881 --payload $DHT_PING
report P-2t nsx client $probe udp $FOREIGN 6881 --payload $DHT_PING
report P-3 $probe udp $FOREIGN 6881 --payload $TRACKER
report P-4 $probe tcp $FOREIGN 6881 --payload $BT_HS
report P-4t nsx client $probe tcp $FOREIGN 6881 --payload $BT_HS
report P-N1 $probe udp $FOREIGN 6881 --payload $TURN_CD
report P-N2 $probe udp $FOREIGN 6881 --payload $STUN
report P-N3 $probe udp $FOREIGN 6881
report P-N4 $probe udp $FOREIGN 443 --payload $UTP_SYN
report P-N5 $probe tcp $FOREIGN 6881

counter() { nft list counter inet vnm "$1" 2>/dev/null | awk '/packets/ {print $2}'; }
echo "CNT-p2p $(counter p_utp_syn)"
echo "CNT-decide $(counter r0_ru_ip_4)"
echo "CNT-listen $(counter listen_bypass)"
echo "CNT-guard $(counter g_scanners_4)"

[ "$mode" = enforce ] || exit 0

# Fail-closed, layer 1: the agent declares the exit dead. The route stays.
nft add element inet vnm dead_exits { 0x0000ca6c }
report FC-1 $probe tcp $RU_SITE 80
report FC-2 nsx client $probe tcp $RU_SITE 80
report FC-3 nsx client $probe tcp $FOREIGN 80
report FC-4 nsx ruc $probe tcp $NODE 22
# The exit's own health probe: bypass bit plus the exit mark.
report FC-8 $probe tcp $RU_SITE 80 --mark 0x1ca6c

# Fail-closed, layer 2: no agent at all, and the exit's interface is gone.
nft flush set inet vnm dead_exits
ip link del warp
report FC-5 $probe tcp $RU_SITE 80
report FC-6 nsx client $probe tcp $RU_SITE 80
report FC-7 nsx client $probe tcp $FOREIGN 80
