from pathlib import Path
import json,os,shutil,subprocess,tempfile
ROOT=Path(__file__).resolve().parent
REPO=ROOT/'checks'
LOGS=ROOT/'logs'
rows=[{'label':'extracted-private-axiom','command':['make','-C','contracts/verification','verify-extracted'],'status':2,'expected_marker':'source inventory drift'}]
def run(label,cmd,cwd=REPO,env=None,needle=None):
    p=subprocess.run(cmd,cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=300)
    (LOGS/(label+'.log')).write_text(p.stdout)
    rows.append({'label':label,'command':cmd,'cwd':str(cwd),'status':p.returncode,'expected_marker':needle})
    print(label,p.returncode,flush=True)
    assert p.returncode!=0,(label,'unexpected green')
    if needle: assert needle in p.stdout,(label,p.stdout[-1500:])
def inject(project,root,source,label,cmd,needle):
    base=REPO/'contracts/verification'/project
    module=base/root/'CensusRegression.lean'; entry=base/(root+'.lean');orig=entry.read_bytes()
    assert not module.exists()
    try:
        module.write_text(source)
        entry.write_text('import '+root+'.CensusRegression\n'+orig.decode())
        run(label,cmd,needle=needle)
    finally:
        entry.write_bytes(orig);module.unlink()
inject('lean','SphincsCVerify','import SphincsCVerify.Crypto.Assumptions\nnamespace SphincsCVerify.CensusRegression\naxiom freeBreak : Crypto.BreaksHash\ntheorem vacuous (P : Prop) : P ∨ Crypto.BreaksHash := Or.inr freeBreak\nend SphincsCVerify.CensusRegression\n','flagship-break-token', ['make','-C','contracts/verification','verify-fv-lints'],'source inventory drift')
inject('lean','SphincsCVerify',Path('/tmp/pq-env-axiom-probe.lean').read_text(),'generated-environment-axiom', ['python3','contracts/verification/scripts/check_axiom_inventory.py','lean'],'elaborated inventory drift')
# Compile a real admit probe, then exercise the actual Make recipe over it.
probe=REPO/'contracts/verity/PQSigner/AdmitRegression.lean'
try:
    probe.write_text('theorem admitRegression : False := by admit\n')
    p=subprocess.run(['/home/nicola/.elan/bin/lake','env','lean',str(probe)],cwd=REPO/'contracts/verity',capture_output=True,text=True)
    (LOGS/'verity-admit-lean.log').write_text(p.stdout+p.stderr)
    assert p.returncode==0 and "uses 'sorry'" in p.stdout
    run('verity-admit-rejected',['make','-C','contracts/verity','ci'],needle='proof holes exceed baseline')
finally: probe.unlink()
# Real TLC output followed by an abnormal exit must be rejected by every wrapper.
with tempfile.TemporaryDirectory() as temp:
    path=Path(temp);java=path/'java';java.write_text('#!/bin/sh\n/usr/bin/java "$@"\nexit 42\n');java.chmod(0o755)
    env=dict(os.environ,PATH=str(path)+':'+os.environ['PATH'])
    for name in ['run.sh','run_combined.sh','run_pin.sh']:
        run('tlc-exit42-'+name,['bash','contracts/verification/tla/'+name],env=env,needle='process status 42')
# Reproduce duplicate+omission using actual config files and all wrapper entrypoints.
tla=REPO/'contracts/verification/tla';cfg=tla/'cb_onchain_cap.cfg';pins=tla/'cfg_pins.sha256';a,b=cfg.read_bytes(),pins.read_bytes()
try:
    cfg.write_text(a.decode().replace('INVARIANT INV_ONCHAIN_CAP',''))
    lines=b.decode().splitlines();dup=next(line for line in lines if line.endswith('cb_margin_noreset.cfg'))
    pins.write_text('\n'.join(dup if line.endswith('cb_onchain_cap.cfg') else line for line in lines)+'\n')
    for name in ['run.sh','run_combined.sh','run_pin.sh']:
        run('tlc-duplicate-'+name,['bash','contracts/verification/tla/'+name],needle='duplicate config pin')
finally: cfg.write_bytes(a);pins.write_bytes(b)
(ROOT/'negative-probes.json').write_text(json.dumps(rows,indent=2)+'\n')
