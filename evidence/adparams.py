#!/usr/bin/env python3
# Read-only: find ad-request URLs in a process's memory and summarise their
# query parameters. Identifier values are masked; consent/tracking flags shown.
# Usage: adparams.py <pid> <host-substring> [host-substring...]
import sys, re, collections
from urllib.parse import urlsplit, parse_qsl
pid = sys.argv[1]; hosts = [h.encode() for h in sys.argv[2:]]
SHOW = re.compile(r'(gdpr|consent|lmt|limit|dnt|us_?privacy|gpp|coppa|is_lat|npa|tfua|tfcd|optout|opt_out|country|geo|zip|postal|lat$|lon$|ip$|ua$)', re.I)
MASK = re.compile(r'(ifa|idfa|adid|aaid|device_?id|did|uid|udid|rdid|ppid|cust_params|mac|serial|session)', re.I)
mem = open('/proc/%s/mem' % pid, 'rb', 0)
urls = set()
for m in open('/proc/%s/maps' % pid).read().splitlines():
    f = m.split()
    if 'rw' not in f[1] or (len(f) > 5 and f[5].startswith('/')): continue
    a, b = (int(x, 16) for x in f[0].split('-'))
    if b - a > 256 * 1024 * 1024: continue
    try: mem.seek(a); d = mem.read(b - a)
    except Exception: continue
    for h in hosts:
        for mt in re.finditer(rb'https?://[A-Za-z0-9.-]*' + re.escape(h) + rb'[\x21-\x7e]{0,4000}', d):
            urls.add(mt.group(0).decode('latin1'))
keys = collections.Counter(); vals = collections.defaultdict(collections.Counter); paths = collections.Counter()
for u in urls:
    try: s = urlsplit(u)
    except Exception: continue
    paths[s.netloc + s.path[:60]] += 1
    for k, v in parse_qsl(s.query, keep_blank_values=True):
        keys[k] += 1
        if MASK.search(k): vals[k]['<present:%d chars>' % len(v)] += 1
        elif SHOW.search(k): vals[k][v[:80]] += 1
print('urls:', len(urls))
for p, c in paths.most_common(12): print('  path', c, p)
print('param keys:', ', '.join('%s(%d)' % kv for kv in keys.most_common(80)))
for k, c in vals.items(): print('  %s -> %s' % (k, dict(c.most_common(4))))
