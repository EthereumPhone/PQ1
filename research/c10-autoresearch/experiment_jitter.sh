#!/usr/bin/env bash
# experiment_jitter.sh — harness v3 at three code layouts (PAD = 0, 96, 224 bytes before the code), mean and spread.
# For changes expected under ~1%: 1-way ICACHE conflicts and fetch alignment move single-layout numbers by ~1-2%.
set -u
D="$(cd "$(dirname "$0")" && pwd)"; cd "$D"
for p in 0 96 224; do
  EXTRA_LDFLAGS="-Wl,--defsym=PAD=$p" EXP_CFLAGS="${EXP_CFLAGS:-}" ./experiment_flash.sh > out/jit-$p.json 2>&1 || { cat out/jit-$p.json; exit 1; }
done
python3 - <<'PY'
import json, statistics as st
rs=[json.load(open('out/jit-%d.json'%p)) for p in (0,96,224)]
if not all(r.get('ok') for r in rs): print(json.dumps({'ok':False,'why':[r.get('why') for r in rs]})); raise SystemExit(1)
o={'ok':True}
for k in ('cached_sign','keygen','total'):
    v=[r[k] for r in rs]; o[k]=int(st.mean(v)); o[k+'_spread']=max(v)-min(v); o[k+'_all']=v
print(json.dumps(o))
PY
