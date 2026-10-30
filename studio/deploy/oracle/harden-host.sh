#!/usr/bin/env bash
# Targets bash on the Oracle VM (Ubuntu 24.04). Hardens the host around the Studio stack; run
# it as root after a fresh VM and after changing it (sudo ./harden-host.sh). Idempotent.
# Sources: CIS-style Ubuntu 24.04 checklists, Docker's daemon options, the OpenSSH 9.6 manual.
# Before closing the SSH session that ran it, open a second one to check the login still works.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi
export DEBIAN_FRONTEND=noninteractive

# SSH: keys only, for the ubuntu user only, modern algorithms only. The file sorts before
# Ubuntu's own drop-ins, and sshd takes the first value it reads.
cat >/etc/ssh/sshd_config.d/10-mivais-hardening.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
PermitEmptyPasswords no
AllowUsers ubuntu
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
PermitTunnel no
PermitUserEnvironment no
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256
EOF
sshd -t
# Open sessions stay; new logins get the new settings.
systemctl restart ssh.service

# Brute-force noise on port 22: ban an address for an hour after five failed logins.
apt-get install -y -qq fail2ban python3-systemd lynis >/dev/null
cat >/etc/fail2ban/jail.d/10-mivais-sshd.local <<'EOF'
[sshd]
enabled = true
backend = systemd
maxretry = 5
findtime = 10m
bantime = 1h
EOF
systemctl enable fail2ban >/dev/null 2>&1
systemctl restart fail2ban

# rpcbind (port 111) serves NFS, which this VM does not use.
for unit in rpcbind.socket rpcbind.service; do
  systemctl disable --now "$unit" >/dev/null 2>&1 || true
  systemctl mask "$unit" >/dev/null 2>&1
done

# Security updates are installed daily already (20auto-upgrades); reboot for a new kernel at
# 02:30 UTC, when no participant should be in a session.
cat >/etc/apt/apt.conf.d/52mivais-unattended <<'EOF'
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:30";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF

# IPv6 has no address on this VCN; if one is added later, only SSH and ICMPv6 come in, as on
# IPv4 (Oracle's image already rejects all but SSH there).
ip6tables -C INPUT -i lo -j ACCEPT 2>/dev/null || {
  ip6tables -A INPUT -i lo -j ACCEPT
  ip6tables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
  ip6tables -A INPUT -p ipv6-icmp -j ACCEPT
  ip6tables -A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
  ip6tables -A INPUT -j REJECT --reject-with icmp6-adm-prohibited
}
# Only the IPv6 rules are saved; the IPv4 file also holds Docker's chains, which Docker writes itself.
ip6tables-save >/etc/iptables/rules.v6

# Kernel: no redirects or source routing, log martians, hide kernel pointers, harden the BPF JIT.
cat >/etc/sysctl.d/60-mivais-hardening.conf <<'EOF'
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
fs.suid_dumpable = 0
fs.protected_fifos = 2
fs.protected_regular = 2
EOF
sysctl --system >/dev/null

# Docker: no privilege gain in any container, rotated logs, containers keep running while the
# daemon restarts for an update. Restarting the daemon restarts the stack once.
mkdir -p /etc/docker
cat >/etc/docker/daemon.json.new <<'EOF'
{
  "no-new-privileges": true,
  "live-restore": true,
  "userland-proxy": false,
  "log-driver": "local",
  "log-opts": { "max-size": "10m", "max-file": "5" }
}
EOF
if ! cmp -s /etc/docker/daemon.json.new /etc/docker/daemon.json; then
  mv /etc/docker/daemon.json.new /etc/docker/daemon.json
  systemctl restart docker
else
  rm /etc/docker/daemon.json.new
fi

# Secrets and the checkout are root's only.
chmod 700 /opt/mivais
chmod 600 /opt/mivais/*.env

systemctl enable --now mivais-deploy.timer >/dev/null 2>&1 || true
echo "Host hardened."
