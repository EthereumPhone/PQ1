#!/usr/bin/env python3
"""Executable controls for imported bad proofs and unfinished proof EOFs."""
from pathlib import Path
import subprocess
import tempfile


def require(condition, message):
    if not condition:
        raise SystemExit('FAIL proof controls: ' + message)


def compile_file(path, include):
    return subprocess.run(['easycrypt', 'compile', '-no-eco', '-timeout', '60',
                           '-I', str(include), str(path)], text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)


def main():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        original = Path('base-c10-split/BinaryTrees.ec').read_text()
        needle = 'proof. by elim: bt => /#. qed.'
        require(original.count(needle) == 1, 'dependency control anchor drift')
        source = root / 'BinaryTrees.ec'
        source.write_text(original)
        cp = compile_file(source, root)
        require(cp.returncode == 0, 'dependency control baseline failed: ' + cp.stdout[-1500:])
        source.write_text(original.replace(needle, 'proof. by trivial. qed.'))
        cp = compile_file(source, root)
        require(cp.returncode == 1 and 'cannot close goals' in cp.stdout.lower(),
            'broken dependency must fail its own proof: ' + cp.stdout[-1500:])
        consumer = root / 'Consumer.ec'
        consumer.write_text('require import BinaryTrees.\n')
        cp = compile_file(consumer, root)
        require(cp.returncode == 0, 'dependency import semantics changed: ' + cp.stdout[-1500:])
        unfinished = root / 'Unfinished.ec'
        unfinished.write_text('require import AllCore.\nlemma unfinished : true.\nproof.\n')
        # Requiring the file must reject the open proof even if compile accepts EOF.
        consumer.write_text('require Unfinished.\n')
        cp = compile_file(consumer, root)
        require(cp.returncode == 1 and 'proof' in cp.stdout.lower(),
            'open proof must fail require: ' + cp.stdout[-1500:])
        abstract = root / 'Abstract.eca'
        abstract.write_text('require import AllCore.\nlemma checked : true.\nproof. trivial. qed.\n')
        cp = compile_file(abstract, root)
        require(cp.returncode == 0, 'abstract theory must compile directly: ' + cp.stdout[-1500:])
        consumer.write_text('require Abstract.\n')
        cp = compile_file(consumer, root)
        require(cp.returncode == 0, 'abstract theory must be requirable: ' + cp.stdout[-1500:])
        consumer.write_text('require import Abstract.\n')
        cp = compile_file(consumer, root)
        require(cp.returncode == 1 and 'cannot import an abstract theory' in cp.stdout,
            'abstract import control changed: ' + cp.stdout[-1500:])
        abstract.write_text('require import AllCore.\nlemma checked : true.\nproof.\n')
        consumer.write_text('require Abstract.\n')
        cp = compile_file(consumer, root)
        require(cp.returncode == 1 and 'proof' in cp.stdout.lower(),
            'abstract open proof must fail plain require: ' + cp.stdout[-1500:])
    print('OK proof controls: direct dependency failure / import acceptance / '
          'open-proof rejection / abstract require and EOF')


if __name__ == '__main__':
    main()
