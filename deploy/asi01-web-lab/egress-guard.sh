#!/bin/sh
set -eu

# This one-shot container shares only the lab DVAA network namespace. DVAA
# starts only after this policy is installed. Established replies to ingress
# remain possible; every new connection in the namespace may reach only the fixture.
test "$(id -u)" = 0
test "$#" = 3
fixture_ip="$1"
fixture_port="$2"
target_uid="$3"
case "$fixture_ip" in 172.30.79.3) ;; *) exit 2 ;; esac
case "$fixture_port:$target_uid" in 8787:1000) ;; *) exit 2 ;; esac

iptables -w -N SECAGENT_WEB_EGRESS
iptables -w -A SECAGENT_WEB_EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -w -A SECAGENT_WEB_EGRESS -p tcp -d "$fixture_ip" --dport "$fixture_port" \
  -m conntrack --ctstate NEW -j ACCEPT
iptables -w -A SECAGENT_WEB_EGRESS -j REJECT
iptables -w -I OUTPUT 1 -j SECAGENT_WEB_EGRESS
iptables -w -C OUTPUT -j SECAGENT_WEB_EGRESS
iptables -w -C SECAGENT_WEB_EGRESS -j REJECT
ip6tables -w -N SECAGENT_WEB_EGRESS6
ip6tables -w -A SECAGENT_WEB_EGRESS6 -j REJECT
ip6tables -w -I OUTPUT 1 -j SECAGENT_WEB_EGRESS6
ip6tables -w -C OUTPUT -j SECAGENT_WEB_EGRESS6
echo 'SecAgent Web Lab namespace egress guard installed.'
