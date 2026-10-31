"""Hosted-only native resolver probe; run inside fresh mount/network namespaces."""
import argparse
import json
import os
from pathlib import Path
import pwd
import re
import select
import signal
import socket
import struct
import subprocess
import time


def question(packet):
    assert len(packet) <= 512 and len(packet) >= 17
    ident, flags, queries, *_ = struct.unpack('!HHHHHH', packet[:12])
    assert not flags & 0x8000 and queries == 1
    cursor, labels = 12, []
    while packet[cursor]:
        size = packet[cursor]
        assert 0 < size <= 63 and cursor + size < len(packet)
        labels.append(packet[cursor + 1:cursor + size + 1].decode('ascii'))
        cursor += size + 1
    end = cursor + 5
    assert end <= len(packet)
    kind, family = struct.unpack('!HH', packet[cursor + 1:end])
    assert family == 1 and kind in (1, 28)
    return ident, '.'.join(labels).lower(), kind, packet[12:end]


def response(packet, address):
    ident, host, kind, query = question(packet)
    tail = 0
    if host.startswith('ready.'):
        tail = 13
    elif host.startswith('wedged.'):
        tail = 11
    elif host.startswith('next.'):
        tail = 12
    answers = int(kind == 1 and bool(tail))
    flags = 0x8180 if tail else 0x8183
    result = struct.pack('!HHHHHH', ident, flags, 1, answers, 0, 0) + query
    if answers:
        result += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + bytes([127, 0, 0, tail])
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--user', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0
    args.output.mkdir(parents=True, exist_ok=True)
    original = Path('/etc/nsswitch.conf').read_text()
    nss, changes = re.subn(r'(?m)^hosts:.*$', 'hosts: dns', original)
    assert changes == 1
    nss_path = args.output / 'nsswitch.conf'
    nss_path.write_text(nss)
    resolv_path = args.output / 'resolv.conf'
    resolv_path.write_text('nameserver 127.0.0.1\noptions timeout:30 attempts:5\n')
    subprocess.run(['mount', '--bind', str(nss_path), '/etc/nsswitch.conf'], check=True)
    subprocess.run(['mount', '--bind', str(resolv_path), '/etc/resolv.conf'], check=True)
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('127.0.0.1', 53))
    control_path = args.output / 'control.sock'
    control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    control.bind(str(control_path))
    os.chmod(control_path, 0o666)
    control.listen(4)
    seen, held, replies = [], [], []
    released = False
    user = pwd.getpwnam(args.user)
    assert user.pw_uid != 0
    log_path = args.output / 'native-test.log'
    with log_path.open('wb') as log:
        command = ['runuser', '-u', args.user, '--', 'env',
                   'REMOTE_PROBE_CONTROL=' + str(control_path),
                   'REMOTE_PROBE_UID=' + str(user.pw_uid), str(args.executable),
                   '--exact', 'remote::resolver::tests::native_system_resolver_resource_probe',
                   '--nocapture', '--include-ignored', '--test-threads=1']
        child = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 45
        try:
            while child.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('native probe exceeded 45-second driver bound')
                readable, _, _ = select.select([udp, control], [], [], min(remaining, 1))
                for endpoint in readable:
                    if endpoint is udp:
                        packet, address = udp.recvfrom(513)
                        _, host, kind, _ = question(packet)
                        assert len(seen) < 128
                        seen.append({'host': host, 'type': kind})
                        if host == 'wedged.remote-probe.invalid' and not released:
                            assert len(held) < 8
                            held.append((packet, address))
                        else:
                            udp.sendto(response(packet, address), address)
                            replies.append(host)
                    else:
                        peer, _ = control.accept()
                        with peer:
                            peer.settimeout(2)
                            request = bytearray()
                            while True:
                                part = peer.recv(257 - len(request))
                                if not part:
                                    break
                                request.extend(part)
                                assert len(request) <= 256
                            request = request.decode('ascii')
                            assert request in ('state', 'release')
                            if request == 'release':
                                assert held and not released
                                released = True
                                for packet, address in held:
                                    udp.sendto(response(packet, address), address)
                                    replies.append(question(packet)[1])
                                held.clear()
                            state = {'hosts': sorted({row['host'] for row in seen}),
                                     'queries': len(seen), 'replied_hosts': sorted(set(replies)),
                                     'released': released, 'held': len(held)}
                            peer.sendall(json.dumps(state).encode())
            code = child.wait(timeout=1)
            assert code == 0, f'native probe test exited {code}'
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=3)
            control.close()
            udp.close()
            control_path.unlink(missing_ok=True)
    text = log_path.read_text()
    assert 'test result: ok. 1 passed; 0 failed' in text
    marker = 'NATIVE_RESOLVER_PROBE='
    matches = [line.split(marker, 1)[1] for line in text.splitlines() if marker in line]
    assert len(matches) == 1
    result = json.loads(matches[0])
    assert result['busy_callers'] == 100 and result['dns']['released']
    result['native_dns_queries'] = seen
    result['namespace'] = {name: os.readlink('/proc/self/ns/' + name) for name in ('mnt', 'net')}
    result['driver_uid'] = os.geteuid()
    result['process_exit'] = code
    (args.output / 'native-verdict.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
