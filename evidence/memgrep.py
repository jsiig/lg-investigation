#!/usr/bin/env python3
# Read-only scan of a process's writable memory for byte patterns; prints
# printable context around each hit. Usage: memgrep.py <pid> <ctx> <pattern> [pattern...]
import sys, re
pid = sys.argv[1]; ctx = int(sys.argv[2]); pats = [p.encode() for p in sys.argv[3:]]
maps = open('/proc/%s/maps' % pid).read().splitlines()
mem = open('/proc/%s/mem' % pid, 'rb', 0)
seen = set(); hits = 0
for m in maps:
    f = m.split()
    if 'rw' not in f[1]: continue
    if len(f) > 5 and f[5].startswith('/') and not f[5].startswith('/dev/shm'): continue
    a, b = (int(x, 16) for x in f[0].split('-'))
    if b - a > 256 * 1024 * 1024: continue
    try:
        mem.seek(a); data = mem.read(b - a)
    except Exception:
        continue
    for p in pats:
        for mt in re.finditer(re.escape(p), data):
            s = max(0, mt.start() - ctx); e = min(len(data), mt.end() + ctx)
            chunk = data[s:e]
            txt = re.sub(rb'[^\x20-\x7e\n]', b'.', chunk).decode()
            key = txt[:200]
            if key in seen: continue
            seen.add(key); hits += 1
            print('=== %s @%x' % (p.decode(), a + mt.start())); print(txt)
            if hits > 40: sys.exit(0)
