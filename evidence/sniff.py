#!/usr/bin/env python3
# Passive metadata sniffer for the TV's wlan0. Read-only: opens an AF_PACKET
# socket, never sends anything, never touches system config.
# Usage: python3 sniff.py <seconds> <outfile>
import socket, struct, sys, time, os, json

DUR = int(sys.argv[1]); OUT = open(sys.argv[2], 'w', buffering=1)
IFACE = 'wlan0'
TV_IP = '192.168.1.138'
t0 = time.time()

def log(kind, **kw):
    kw['t'] = round(time.time() - t0, 2); kw['k'] = kind
    OUT.write(json.dumps(kw) + '\n')

dns = {}          # ip -> name
flows = {}        # (proto, remote_ip, rport) -> [out_bytes, in_bytes, pkts, first_t, last_t, sni]
seen_tcp_data = {}  # (lport, rip, rport) -> count of data pkts inspected

def ip4(b): return socket.inet_ntoa(b)

def dns_name(buf, off):
    labels = []; jumped = False; end = off; hops = 0
    while off < len(buf) and hops < 50:
        hops += 1
        l = buf[off]
        if l == 0:
            off += 1
            break
        if l & 0xC0 == 0xC0:
            if off + 1 >= len(buf): break
            ptr = ((l & 0x3F) << 8) | buf[off + 1]
            if not jumped: end = off + 2
            off = ptr; jumped = True; continue
        labels.append(buf[off + 1:off + 1 + l].decode('ascii', 'replace')); off += 1 + l
    if not jumped: end = off
    return '.'.join(labels), end

def parse_dns(p, outgoing, mdns=False):
    try:
        tid, flags, qd, an, ns, ar = struct.unpack('!HHHHHH', p[:12])
        off = 12; qs = []
        for _ in range(qd):
            n, off = dns_name(p, off); qt = struct.unpack('!H', p[off:off + 2])[0]; off += 4; qs.append((n, qt))
        ans = []
        for _ in range(an):
            n, off = dns_name(p, off)
            t, c, ttl, rl = struct.unpack('!HHIH', p[off:off + 10]); off += 10
            rd = p[off:off + rl]
            if t == 1 and rl == 4:
                ans.append((n, ip4(rd)));
                if not mdns: dns[ip4(rd)] = n
            elif t == 5:
                ans.append((n, 'CNAME:' + dns_name(p, off)[0]))
            elif t == 12:
                ans.append((n, 'PTR:' + dns_name(p, off)[0]))
            off += rl
        return flags, qs, ans
    except Exception as e:
        return None, [], []

def sni_from_clienthello(d):
    try:
        if d[0] != 0x16 or d[5] != 0x01: return None
        off = 5 + 4 + 2 + 32
        sl = d[off]; off += 1 + sl
        cl = struct.unpack('!H', d[off:off + 2])[0]; off += 2 + cl
        ml = d[off]; off += 1 + ml
        el = struct.unpack('!H', d[off:off + 2])[0]; off += 2; end = off + el
        while off + 4 <= end:
            et, ln = struct.unpack('!HH', d[off:off + 4]); off += 4
            if et == 0:
                nl = struct.unpack('!H', d[off + 3:off + 5])[0]
                return d[off + 5:off + 5 + nl].decode('ascii', 'replace')
            off += ln
    except Exception:
        return None

# socket -> process mapping
def proc_snapshot():
    inode2proc = {}
    for pid in os.listdir('/proc'):
        if not pid.isdigit(): continue
        try:
            comm = open('/proc/%s/comm' % pid).read().strip()
            for fd in os.listdir('/proc/%s/fd' % pid):
                try:
                    l = os.readlink('/proc/%s/fd/%s' % (pid, fd))
                    if l.startswith('socket:['): inode2proc[l[8:-1]] = comm
                except Exception: pass
        except Exception: pass
    res = []
    for proto in ('tcp', 'udp'):
        try:
            for line in open('/proc/net/' + proto).readlines()[1:]:
                f = line.split()
                la, ra, st, inode = f[1], f[2], f[3], f[9]
                rip_hex, rport_hex = ra.split(':')
                rip = socket.inet_ntoa(struct.pack('<I', int(rip_hex, 16))); rport = int(rport_hex, 16)
                lport = int(la.split(':')[1], 16)
                if rip in ('0.0.0.0', '127.0.0.1'): continue
                res.append((proto, rip, rport, lport, st, inode2proc.get(inode, '?')))
        except Exception: pass
    return res

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
s.bind((IFACE, 0)); s.settimeout(1.0)
last_snap = 0; last_sum = time.time(); procseen = set()
while time.time() - t0 < DUR:
    now = time.time()
    if now - last_snap > 5:
        last_snap = now
        for (proto, rip, rport, lport, st, comm) in proc_snapshot():
            key = (proto, rip, rport, comm)
            if key not in procseen:
                procseen.add(key); log('sock', proto=proto, rip=rip, rport=rport, lport=lport, st=st, proc=comm, name=dns.get(rip))
    if now - last_sum > 60:
        last_sum = now
        log('summary', flows=[[k[0], k[1], k[2], dns.get(k[1]), v[0], v[1], v[2], v[5]] for k, v in flows.items()])
    try:
        pkt, addr = s.recvfrom(65535)
    except socket.timeout:
        continue
    outgoing = addr[2] == 4
    if len(pkt) < 14: continue
    et = struct.unpack('!H', pkt[12:14])[0]; p = pkt[14:]
    if et == 0x0806:
        op = struct.unpack('!H', p[6:8])[0]
        log('arp', out=outgoing, op=op, spa=ip4(p[14:18]), tpa=ip4(p[24:28]))
        continue
    if et == 0x86DD:
        log('ipv6', out=outgoing, nh=p[6], src=socket.inet_ntop(socket.AF_INET6, p[8:24]), dst=socket.inet_ntop(socket.AF_INET6, p[24:40]))
        continue
    if et != 0x0800:
        log('eth', out=outgoing, type=hex(et)); continue
    ihl = (p[0] & 0xF) * 4; proto = p[9]; src = ip4(p[12:16]); dst = ip4(p[16:20]); tot = struct.unpack('!H', p[2:4])[0]
    l4 = p[ihl:tot]
    rip = dst if outgoing else src
    if proto == 17 and len(l4) >= 8:
        sp, dp = struct.unpack('!HH', l4[:4]); pl = l4[8:]
        rport = dp if outgoing else sp; lport = sp if outgoing else dp
        if 53 in (sp, dp):
            flags, qs, ans = parse_dns(pl, outgoing)
            log('dns', out=outgoing, q=qs, a=ans)
        elif 5353 in (sp, dp):
            flags, qs, ans = parse_dns(pl, outgoing, mdns=True)
            if outgoing or dst == TV_IP: log('mdns', out=outgoing, src=src, dst=dst, q=qs, a=ans[:10])
            else: log('mdns_lan', src=src, nq=len(qs), na=len(ans), q=[q[0] for q in qs][:5], a=[a[0] for a in ans][:5])
            continue
        elif 1900 in (sp, dp) or dst == '239.255.255.250':
            first = pl[:600].decode('latin1', 'replace')
            hdr = {l.split(':', 1)[0].upper(): l.split(':', 1)[1].strip() for l in first.split('\r\n')[1:] if ':' in l}
            log('ssdp', out=outgoing, src=src, dst=dst, sport=sp, dport=dp, line=first.split('\r\n')[0], st=hdr.get('ST') or hdr.get('NT'), server=hdr.get('SERVER'), loc=hdr.get('LOCATION'))
            continue
        elif dst.startswith('224.') or dst.startswith('239.') or dst.endswith('.255'):
            log('mcast', out=outgoing, src=src, dst=dst, sport=sp, dport=dp, n=len(pl), head=pl[:60].hex())
            continue
        k = ('udp', rip, rport)
        f = flows.setdefault(k, [0, 0, 0, now - t0, 0, None])
        f[0 if outgoing else 1] += len(pl); f[2] += 1; f[4] = now - t0
        if f[2] == 1: log('udpflow', out=outgoing, rip=rip, rport=rport, lport=lport, name=dns.get(rip), head=pl[:48].hex())
    elif proto == 6 and len(l4) >= 20:
        sp, dp, seq, ack, offf = struct.unpack('!HHIIB', l4[:13]); fl = l4[13]
        doff = (offf >> 4) * 4; pl = l4[doff:]
        rport = dp if outgoing else sp; lport = sp if outgoing else dp
        k = ('tcp', rip, rport)
        f = flows.setdefault(k, [0, 0, 0, now - t0, 0, None])
        f[0 if outgoing else 1] += len(pl); f[2] += 1; f[4] = now - t0
        if (fl & 0x02) and not (fl & 0x10):
            log('syn', out=outgoing, rip=rip, rport=rport, lport=lport, name=dns.get(rip))
        if pl and outgoing:
            sk = (lport, rip, rport); c = seen_tcp_data.get(sk, 0)
            if c < 3:
                seen_tcp_data[sk] = c + 1
                sni = sni_from_clienthello(pl)
                if sni:
                    f[5] = sni; log('tls', rip=rip, rport=rport, lport=lport, sni=sni, name=dns.get(rip))
                elif pl[:4] in (b'GET ', b'POST', b'PUT ', b'HEAD') or pl[:5] == b'PATCH':
                    txt = pl[:1500].decode('latin1', 'replace')
                    log('http', rip=rip, rport=rport, lport=lport, name=dns.get(rip), req=txt)
                elif rip.startswith('192.168.') and c == 0:
                    log('lan_tcp_data', rip=rip, rport=rport, lport=lport, head=pl[:200].decode('latin1', 'replace'))
log('summary', final=True, flows=[[k[0], k[1], k[2], dns.get(k[1]), v[0], v[1], v[2], v[5]] for k, v in flows.items()])
