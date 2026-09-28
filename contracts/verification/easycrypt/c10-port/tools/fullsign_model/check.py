"""Cross-check the manual raw-oracle computation against actual Rust signatures.

Public deterministic fixtures only. Rust hooks count hardware-boundary calls;
shuffle.rs uses software SHA-256, so its separately counted calls are reported
explicitly, not attributed to those hooks. This is not an extraction proof.
"""
from pathlib import Path
import argparse, hashlib, json, shutil, subprocess, time
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[5]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--out', required=True, type=Path)
args = parser.parse_args()
OUT = args.out.resolve()
if OUT.is_relative_to(REPO):
    raise SystemExit('output must be outside the repository')
OUT.mkdir(parents=True, exist_ok=False)
CRATE = OUT / 'harness'
CRATE.mkdir()
(CRATE / 'src').mkdir()
for name in ['Cargo.lock', 'src/main.rs']:
    shutil.copy2(HERE / name, CRATE / name)
manifest = (HERE / 'Cargo.toml').read_text().replace('../../../../../../sphincs-c10', str(REPO / 'sphincs-c10'))
(CRATE / 'Cargo.toml').write_text(manifest)

def require(condition, detail):
    if not condition:
        raise AssertionError(detail)

def be(n, x):
    return (x % (1 << 8 * n)).to_bytes(n, 'big')

def pad(x):
    return x + bytes(16)

def addr(l, t, k, p, i, j, h):
    return be(4, l) + be(8, t) + be(4, k) + be(4, p) + be(4, i) + be(4, j) + be(4, h)

class Model:

    def __init__(self, case):
        self.sk = bytes((0 if case == 0 else 255 if case == 1 else (i * 37 + case * 19) % 256 for i in range(32)))
        self.seed = pad(bytes((0 if case == 0 else 255 if case == 1 else (i * 13 + case * 23) % 256 for i in range(16))))
        self.reset()

    def reset(self):
        self.calls = self.software = self.r_calls = self.hmsg_calls = 0

    def h(self, x, software=False):
        self.calls += 1
        self.software += software
        return hashlib.sha256(x).digest()

    def node(self, x):
        return self.h(x)[:16]

    def wsecret(self, l, t, p, i):
        return self.node(self.sk + b'wots' + be(4, l) + be(32, t) + be(4, p) + be(4, i))

    def fsecret(self, ht, t, j):
        return self.node(self.sk + b'fors' + be(4, ht) + be(4, t) + be(4, j))

    def chain(self, l, t, p, i, x, start, stop):
        for j in range(start, stop):
            x = self.node(self.seed + addr(l, t, 0, p, i, j, 0) + pad(x))
        return x

    def leaf(self, l, t, p):
        elements = [self.chain(l, t, p, i, self.wsecret(l, t, p, i), 0, 7) for i in range(43)]
        return self.node(self.seed + addr(l, t, 1, p, 0, 0, 0) + b''.join(map(pad, elements)))

    def merkle(self, l, t, target):
        stack = []
        keep = [bytes(16)] * 9
        kept = [False] * 9
        for kp in range(512):
            cur = self.leaf(l, t, kp)
            height = 0
            while stack and stack[0][1] == height:
                left, _ = stack.pop(0)
                if not kept[height]:
                    sibling = target >> height ^ 1
                    start = kp >> height + 1 << height + 1
                    left_idx = start >> height
                    if left_idx == sibling:
                        keep[height] = left
                        kept[height] = True
                    elif left_idx + 1 == sibling:
                        keep[height] = cur
                        kept[height] = True
                parent = kp >> height + 1
                cur = self.node(self.seed + addr(l, t, 2, 0, 0, height + 1, parent) + pad(left) + pad(cur))
                height += 1
            stack.insert(0, (cur, height))
        require(len(stack) == 1 and stack[0][1] == 9 and all(kept), 'full signer model check failed')
        return (keep, stack[0][0])

    def walk(self, l, t, k, p, cur, idx, auth):
        for h, sib in enumerate(auth):
            left, right = (cur, sib) if idx % 2 == 0 else (sib, cur)
            idx //= 2
            cur = self.node(self.seed + addr(l, t, k, p, 0, h + 1, idx) + pad(left) + pad(right))
        return cur

    def ftree(self, ht, t, target):
        stack = []
        auth = [bytes(16)] * 11
        for j in range(2048):
            cur = self.node(self.seed + addr(0, ht, 3, t, 0, 0, j) + pad(self.fsecret(ht, t, j)))
            height = 0
            while stack and stack[0][1] == height:
                sib, _ = stack.pop(0)
                parent = j >> height + 1
                sibling_idx = target >> height ^ 1
                left_start = parent << height + 1
                right_start = left_start + (1 << height)
                if sibling_idx % 2 == 0:
                    if sibling_idx << height == left_start:
                        auth[height] = sib
                elif sibling_idx << height == right_start:
                    auth[height] = cur
                cur = self.node(self.seed + addr(0, ht, 3, t, 0, height + 1, parent) + pad(sib) + pad(cur))
                height += 1
            stack.insert(0, (cur, height))
        require(len(stack) == 1 and stack[0][1] == 11, 'full signer model check failed')
        return (stack[0][0], auth)

    def frecover(self, ht, t, idx, secret, auth):
        cur = self.node(self.seed + addr(0, ht, 3, t, 0, 0, idx) + pad(secret))
        return self.walk(0, ht, 3, t, cur, idx, auth)

    def derive_shuffle(self, seed, label):
        return bytes(32) if seed == bytes(32) else self.h(b'sphincs-c10-shuffle-v1' + seed + label, True)

    def permutation(self, seed, n):
        order = list(range(n))
        if seed == bytes(32) or n <= 1:
            return order
        stream = b''.join((self.h(b'sphincs-c10-fisher-yates-v1' + seed + be(4, k), True) for k in range(4)))
        pos = 0
        for i in range(n - 1, 0, -1):
            r = int.from_bytes(stream[pos:pos + 2], 'little')
            pos += 2
            j = r * (i + 1) >> 16
            order[i], order[j] = (order[j], order[i])
        return order

    def forest(self, ht, d, shuffle):
        indices = [d >> 11 * t & 2047 for t in range(13)]
        require(indices[12] == 0, 'full signer model check failed')
        secrets = [bytes(16)] * 13
        auths = [None] * 12
        roots = [bytes(16)] * 13
        order = self.permutation(self.derive_shuffle(shuffle, b'fors'), 12)
        for t in order:
            secret = self.fsecret(ht, t, indices[t])
            _, auth = self.ftree(ht, t, indices[t])
            secrets[t] = secret
            auths[t] = auth
            roots[t] = self.frecover(ht, t, indices[t], secret, auth)
        last, _ = self.ftree(ht, 12, 0)
        secrets[12] = last
        roots[12] = self.node(self.seed + addr(0, ht, 3, 12, 0, 0, 0) + pad(last))
        pk = self.node(self.seed + addr(0, ht, 4, 0, 0, 0, 0) + b''.join(map(pad, roots)))
        return (secrets, auths, pk)

    def wdigest(self, l, t, p, m, count):
        d = int.from_bytes(self.h(self.seed + addr(l, t, 0, p, 0, 0, 0) + pad(m) + be(32, count)), 'big')
        return [d >> 3 * i & 7 for i in range(43)]

    def wsign(self, l, t, p, m, shuffle):
        for count in range(10000000):
            digits = self.wdigest(l, t, p, m, count)
            if sum(digits) == 205:
                break
        else:
            raise AssertionError('WOTS exhausted')
        order = self.permutation(shuffle, 43)
        sigma = [bytes(16)] * 43
        for i in order:
            sigma[i] = self.chain(l, t, p, i, self.wsecret(l, t, p, i), 0, digits[i])
        return (sigma, count)

    def wrecover(self, l, t, p, m, sigma, count):
        digits = self.wdigest(l, t, p, m, count)
        if sum(digits) != 205:
            return bytes(16)
        nodes = [self.chain(l, t, p, i, sigma[i], digits[i], 7) for i in range(43)]
        return self.node(self.seed + addr(l, t, 1, p, 0, 0, 0) + b''.join(map(pad, nodes)))

    def sign(self, root, m, random, shuffle):
        for nonce in range(10000000):
            self.r_calls += 1
            r = self.node(self.sk + b'R_grind' + random + m + be(32, nonce))
            self.hmsg_calls += 1
            d = int.from_bytes(self.h(self.seed + pad(root) + pad(r) + m + bytes([255]) * 32), 'big')
            if d >> 132 & 2047 == 0:
                break
        else:
            raise AssertionError('R exhausted')
        ht = d >> 143 & (1 << 18) - 1
        secrets, auths, cur = self.forest(ht, d, shuffle)
        encoded = r + b''.join(secrets) + b''.join((b''.join(a) for a in auths))
        tree = ht
        for layer in range(2):
            leaf = tree % 512
            tree //= 512
            auth, _ = self.merkle(layer, tree, leaf)
            sub = self.derive_shuffle(shuffle, b'wots-0\x00' if layer == 0 else b'wots-1\x00')
            sigma, count = self.wsign(layer, tree, leaf, cur, sub)
            encoded += b''.join(sigma) + be(4, count) + b''.join(auth)
            pk = self.wrecover(layer, tree, leaf, cur, sigma, count)
            cur = self.walk(layer, tree, 2, 0, pk, leaf, auth)
        require(cur == root and len(encoded) == 4008, 'full signer model check failed')
        return encoded

    def verify(self, root, m, sig):
        d = int.from_bytes(self.h(self.seed + pad(root) + pad(sig[:16]) + m + bytes([255]) * 32), 'big')
        if d >> 132 & 2047:
            return False
        ht = d >> 143 & (1 << 18) - 1
        secrets = [sig[16 + 16 * t:32 + 16 * t] for t in range(13)]
        auths = [[sig[224 + 176 * t + 16 * h:240 + 176 * t + 16 * h] for h in range(11)] for t in range(12)]
        roots = [self.frecover(ht, t, d >> 11 * t & 2047, secrets[t], auths[t]) for t in range(12)]
        roots.append(self.node(self.seed + addr(0, ht, 3, 12, 0, 0, 0) + pad(secrets[12])))
        cur = self.node(self.seed + addr(0, ht, 4, 0, 0, 0, 0) + b''.join(map(pad, roots)))
        tree = ht
        for layer in range(2):
            off = 2336 + 836 * layer
            sigma = [sig[off + 16 * i:off + 16 * i + 16] for i in range(43)]
            count = int.from_bytes(sig[off + 688:off + 692], 'big')
            auth = [sig[off + 692 + 16 * h:off + 708 + 16 * h] for h in range(9)]
            leaf = tree % 512
            tree //= 512
            pk = self.wrecover(layer, tree, leaf, cur, sigma, count)
            cur = self.walk(layer, tree, 2, 0, pk, leaf, auth)
        return cur == root
started = time.time()
cmd = ['cargo', 'run', '--locked', '--release', '--quiet', '--target', 'x86_64-unknown-linux-gnu', '--manifest-path', str(CRATE / 'Cargo.toml'), '--target-dir', str(OUT / 'target')]
cp = subprocess.run(cmd, cwd=REPO, text=True, capture_output=True, timeout=300)
(OUT / 'rust.log').write_text(cp.stdout + cp.stderr)
require(cp.returncode == 0, cp.stderr)
rows = []
negatives = []
models = {}
roots = {}
same = {}
signatures = {}
for line in cp.stdout.splitlines():
    w = line.split()
    case = int(w[1])
    if w[0] == 'K':
        model = Model(case)
        _, root = model.merkle(1, 0, 0)
        require(root.hex() == w[2] and model.calls == int(w[3]) == 177151, 'full signer model check failed')
        models[case] = model
        roots[case] = root
    elif w[0] == 'S':
        _, _, run, shex, calls, rc, hc, vc = w
        run = int(run)
        model = models[case]
        model.reset()
        msg = bytes([(case * 29 + 7) % 256]) * 32
        random = bytes([(case * 17 + 11) % 256]) * 16 if run % 2 else b''
        shuffle = bytes(32) if run < 2 else bytes([case + 1]) * 32
        sig = model.sign(roots[case], msg, random, shuffle)
        require(sig.hex() == shex, (case, run, 'signature mismatch'))
        signatures[case, run] = sig
        require((model.calls - model.software, model.r_calls, model.hmsg_calls) == (int(calls), int(rc), int(hc)), (case, run, 'counter mismatch'))
        require(model.calls <= 40435646, 'full signer model check failed')
        physical = model.calls
        software = model.software
        model.reset()
        require(model.verify(roots[case], msg, sig), 'full signer model check failed')
        require(model.calls == int(vc) <= 771, 'full signer model check failed')
        digest = hashlib.sha256(sig).hexdigest()
        if run < 2:
            same[case, run] = digest
        else:
            require(same[case, run % 2] == digest, 'full signer model check failed')
        rows.append(dict(case=case, run=run, signature_sha256=digest, hook_calls=int(calls), software_shuffle_calls=software, total_calls=physical, r_calls=int(rc), hmsg_calls=int(hc), verify_calls=int(vc)))
    elif w[0] == 'N':
        _, _, run, position, accepted, calls = w
        run = int(run)
        position = int(position)
        model = models[case]
        model.reset()
        sig = bytearray(signatures[case, run])
        msg = bytearray(bytes([(case * 29 + 7) % 256]) * 32)
        if position < 0:
            msg[0] ^= 1
        else:
            sig[position] ^= 1
        result = model.verify(roots[case], bytes(msg), bytes(sig))
        require(result == bool(int(accepted)) == False, (case, run, position, 'negative mismatch'))
        require(model.calls == int(calls) <= 771, (case, run, position, 'negative cost mismatch'))
        negatives.append(dict(case=case, run=run, position=position, accepted=False, verify_calls=int(calls)))
    else:
        raise AssertionError('unknown Rust record')
require(len(models) == 5 and len(rows) == 20 and (len(negatives) == 160), 'full signer model check failed')
files = ['RawKeygen', 'RawFors', 'RawShuffle', 'RawWots', 'RawForest', 'RawMerkle', 'RawLayer', 'RawSigner', 'RawSignerCost', 'RawSignature', 'RawDecode', 'ByteSession']
receipt = dict(exit_code=0, seconds=round(time.time() - started, 2), rust_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip(), rust_sources={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((REPO / 'sphincs-c10/src').glob('*.rs'))}, model_sources={n + '.ec': hashlib.sha256((HERE.parents[1] / 'cdrafts-split' / f'{n}.ec').read_bytes()).hexdigest() for n in files}, harness_sources={str(p.relative_to(HERE)): hashlib.sha256(p.read_bytes()).hexdigest() for p in [HERE / 'src/main.rs', HERE / 'check.py', HERE / 'Cargo.toml', HERE / 'Cargo.lock']}, keygen_cases=5, signatures=rows, negative_verifications=negatives, scope='Manual byte/call correspondence for public fixtures; software shuffle SHA calls counted separately from Rust hooks. No extraction or probability/security theorem.')
(OUT / 'result.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps({'exit_code': 0, 'seconds': receipt['seconds'], 'keygen_cases': 5, 'signature_cases': 20, 'negative_cases': 160, 'receipt': str(OUT / 'result.json')}))
