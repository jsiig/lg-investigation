#!/usr/bin/env python3
# Per-phase summary of a sniff.py capture: TLS SNI / DNS names and bytes per
# external destination. Usage: phases.py <capture.jsonl> name:start:end ...
import json, sys, collections

events = []
for line in open(sys.argv[1]):
    try:
        j = json.loads(line)
    except Exception:
        continue
    if isinstance(j, dict):
        events.append(j)

phases = []
for spec in sys.argv[2:]:
    n, a, b = spec.split(':')
    phases.append((n, float(a), float(b)))

# Bytes per flow come from cumulative 60 s summaries; diff consecutive ones.
summaries = [e for e in events if e.get('k') == 'summary']
ipname = {}
for e in events:
    if e.get('k') == 'tls': ipname[e['rip']] = e['sni']
    if e.get('k') == 'dns' and not e.get('out'):
        for a in e.get('a', []):
            if not str(a[1]).startswith(('CNAME:', 'PTR:')):
                ipname.setdefault(a[1], a[0].lower())

def label(ip, dnsname, sni):
    return (sni or ipname.get(ip) or dnsname or ip).lower()

for n, a, b in phases:
    print('=== %s (t=%d..%d s)' % (n, a, b))
    sni = collections.Counter(e['sni'].lower() for e in events if e.get('k') == 'tls' and a <= e['t'] < b)
    print('  TLS hosts:', ', '.join('%s(%d)' % kv for kv in sorted(sni.items())))
    before = [s for s in summaries if s['t'] <= a]
    after = [s for s in summaries if s['t'] <= b]
    def tot(s):
        d = {}
        if not s: return d
        for r in s[-1]['flows']:
            if r[1].startswith('192.168.'): continue
            d[(r[0], r[1], r[2])] = (r[4], r[5], label(r[1], r[3], r[7]))
        return d
    t0, t1 = tot(before), tot(after)
    agg = collections.defaultdict(lambda: [0, 0])
    for k, (o, i, nm) in t1.items():
        po, pi = t0.get(k, (0, 0, ''))[:2]
        if o - po or i - pi:
            agg[nm][0] += o - po; agg[nm][1] += i - pi
    for nm, (o, i) in sorted(agg.items(), key=lambda kv: -kv[1][0]):
        print('   %-48s out=%-8d in=%d' % (nm[:48], o, i))
