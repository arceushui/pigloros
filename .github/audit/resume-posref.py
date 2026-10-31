"""Temporary frozen-source audit resumption; never used by the shipping gate."""
import json
import re
import subprocess
import sys
from pathlib import Path

names = json.loads(Path('.github/audit/resume-names.json').read_text())
assert len(names) == len(set(names)) == 1704
command = ['cargo', 'mutants', '--package', 'pos-reference', '--all-features', '--no-shuffle']
for name in names:
    command.extend(['--re', '^' + re.escape(name) + '$'])

if sys.argv[1:] == ['inventory']:
    with Path('resume-inventory.json').open('wb') as output:
        subprocess.run([*command, '--list', '--json'], stdout=output, check=True)
    actual = json.loads(Path('resume-inventory.json').read_text())
    assert len(actual) == len(names) and {row['name'] for row in actual} == set(names)
    print(f'Exactly {len(actual)} previously unexecuted catalog entries selected')
else:
    assert len(sys.argv) == 2
    shard = int(sys.argv[1])
    assert 0 <= shard < 32
    command.extend(['--shard', f'{shard}/32', '--baseline', 'run', '--jobs', '1',
                    '--timeout', '120', '--build-timeout', '600', '--cap-lints', 'true',
                    '--cargo-arg=--locked', '--', '--', '-Zunstable-options', '--fail-fast',
                    '--include-ignored', '--test-threads=4'])
    result = subprocess.run(['timeout', '--foreground', '60m', *command], check=False)
    Path('resume-exit-status.txt').write_text(str(result.returncode) + '\n')
    if result.returncode == 124:
        print('Mutation shard watchdog timed out after 60 minutes.', flush=True)
        logs = list(Path('mutants.out').rglob('*.log'))
        if logs:
            latest = max(logs, key=lambda path: path.stat().st_mtime_ns)
            print(f'Most recent mutant log: {latest}', flush=True)
            with latest.open('rb') as log:
                log.seek(max(0, latest.stat().st_size - 12000))
                print(log.read(12000).decode(errors='replace'), flush=True)
    raise SystemExit(result.returncode)
