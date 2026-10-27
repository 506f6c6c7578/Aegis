#!/usr/bin/env sh
set -eu

interface="${AEGIS_EGRESS_INTERFACE:-aegis-egress}"
resolvers="${AEGIS_DNS_SERVERS:-1.1.1.1,9.9.9.9}"
chain="AEGIS-EGRESS"

forbidden_ranges="
0.0.0.0/8
10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.0.0.0/24
192.0.2.0/24
192.31.196.0/24
192.52.193.0/24
192.88.99.0/24
192.168.0.0/16
192.175.48.0/24
198.18.0.0/15
198.51.100.0/24
203.0.113.0/24
224.0.0.0/4
240.0.0.0/4
"

usage() {
    echo "Usage : $0 apply|remove|status" >&2
    exit 2
}

remove() {
    while iptables -C DOCKER-USER -i "$interface" -j "$chain" 2>/dev/null; do
        iptables -D DOCKER-USER -i "$interface" -j "$chain"
    done
    iptables -F "$chain" 2>/dev/null || true
    iptables -X "$chain" 2>/dev/null || true
}

apply() {
    iptables -N "$chain" 2>/dev/null || iptables -F "$chain"
    iptables -A "$chain" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    for resolver in $(echo "$resolvers" | tr ',' ' '); do
        address="${resolver%%:*}"
        for protocol in udp tcp; do
            iptables -A "$chain" -p "$protocol" -m conntrack --ctorigdst "$address" --ctorigdstport 53 -j RETURN
        done
    done
    for range in $forbidden_ranges; do
        iptables -A "$chain" -m conntrack --ctorigdst "$range" -j DROP
    done
    for port in 80 443; do
        iptables -A "$chain" -p tcp -m conntrack --ctorigdstport "$port" -j RETURN
    done
    iptables -A "$chain" -j DROP

    iptables -C DOCKER-USER -i "$interface" -j "$chain" 2>/dev/null || iptables -I DOCKER-USER 1 -i "$interface" -j "$chain"
}

case "${1:-}" in
    apply) apply ;;
    remove) remove ;;
    status) iptables -S "$chain" ;;
    *) usage ;;
esac
