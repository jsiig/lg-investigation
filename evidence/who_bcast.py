#!/usr/bin/env python3
# Passively wait for outgoing UDP packets to given ports and report which
# process owns the sending socket. Usage: who_bcast.py <seconds> <port> [port...]
import socket, struct, sys, time, os
DUR = int(sys.argv[1]); PORTS = {int(p) for p in sys.argv[2:]}
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)); s.bind(('wlan0', 0)); s.settimeout(1)

def owner(lport):
    inodes = set()
    for line in open('/proc/net/udp').readlines()[1:]:
        f = line.split()
        if int(f[1].split(':')[1], 16) == lport: inodes.add(f[9])
    res = []
    for pid in os.listdir('/proc'):
        if not pid.isdigit(): continue
        try:
            for fd in os.listdir('/proc/%s/fd' % pid):
                try:
                    l = os.readlink('/proc/%s/fd/%s' % (pid, fd))
                    if l.startswith('socket:[') and l[8:-1] in inodes:
                        res.append((pid, open('/proc/%s/cmdline' % pid).read().replace('\0', ' ').strip()))
                except Exception: pass
        except Exception: pass
    return res

t0 = time.time(); done = set()
while time.time() - t0 < DUR and len(done) < len(PORTS):
    try: pkt, addr = s.recvfrom(65535)
    except socket.timeout: continue
    if addr[2] != 4 or len(pkt) < 42 or pkt[12:14] != b'\x08\x00' or pkt[23] != 17: continue
    ihl = (pkt[14] & 0xF) * 4; sp, dp = struct.unpack('!HH', pkt[14 + ihl:18 + ihl])
    if dp in PORTS and dp not in done:
        o = owner(sp)
        print('dport', dp, 'sport', sp, 'owner', o, 't', round(time.time() - t0, 1), flush=True)
        if o: done.add(dp)
