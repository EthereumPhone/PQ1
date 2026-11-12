#!/usr/bin/env bash
# log_result.sh <status> <description> — append out/exp.json as a results.tsv row for HEAD.
D="$(cd "$(dirname "$0")" && pwd)"; cd "$D"
python3 - "$(git rev-parse --short=9 HEAD)" "$1" "$2" <<'PY'
import json,sys
c,st,d=sys.argv[1:4]; r=json.load(open('out/exp.json'))
open('results.tsv','a').write('%s\t%d\t%d\t%d\t%s\t%s\n'%(c,r.get('cached_sign',0),r.get('keygen',0),r.get('total',0),st,d))
PY
tail -1 results.tsv
