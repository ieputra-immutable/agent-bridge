#!/usr/bin/env python3
"""Package immutable source and original locked dependency licenses for release."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

ASSETS = ('agent-bridge-linux-x86_64', 'agent-bridge-linux-aarch64',
          'agent-bridge-macos-x86_64', 'agent-bridge-macos-aarch64')


def license_files(package):
    root = Path(package['manifest_path']).parent
    found = set()
    explicit = package.get('license_file')
    if explicit:
        found.add(root / explicit)
    for path in root.rglob('*'):
        relative = path.relative_to(root)
        if relative.parts[0] in ('vendor-dependencies', 'target', '.git'):
            continue
        if path.is_file() and path.name.upper().startswith(
                ('LICENSE', 'LICENCE', 'COPYING', 'NOTICE', 'COPYRIGHT', 'UNLICENSE')):
            found.add(path)
    return [(path.relative_to(root).as_posix(), path.read_text(errors='replace'))
            for path in sorted(found)
            if path.is_file() and path.resolve().is_relative_to(root.resolve())]


def normalized_entry(info, timestamp):
    if any(part in ('target', '.git') for part in Path(info.name).parts):
        return None
    info.uid = info.gid = 0
    info.uname = info.gname = ''
    info.mtime = timestamp
    info.pax_headers = {}
    return info


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dist', required=True, type=Path)
    parser.add_argument('--commit', required=True)
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}', args.commit):
        parser.error('Expected an immutable full commit SHA')
    dist = args.dist.resolve()
    unexpected = [path.name for path in dist.iterdir() if path.name not in ASSETS]
    if unexpected:
        parser.error("Distribution directory must contain only the four platform binaries")
    for name in ASSETS:
        if not (dist / name).is_file():
            parser.error(f'Missing platform executable: {name}')
    actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    if actual != args.commit:
        parser.error('Checkout does not match requested source commit')
    timestamp = int(subprocess.check_output(['git', 'show', '-s', '--format=%ct', args.commit], text=True))
    with tempfile.TemporaryDirectory(prefix='agent-bridge-source-') as temporary:
        source = Path(temporary) / 'agent-bridge'
        source.mkdir()
        archive = Path(temporary) / 'source.tar'
        with archive.open('wb') as output:
            subprocess.run(['git', 'archive', '--format=tar', args.commit], stdout=output, check=True)
        subprocess.run(['tar', '-xf', str(archive), '-C', str(source)], check=True)
        config = source / '.cargo/config.toml'
        config.parent.mkdir(exist_ok=True)
        with config.open('w') as output:
            subprocess.run(['cargo', 'vendor', '--locked', '--versioned-dirs', 'vendor-dependencies'],
                           cwd=source, stdout=output, check=True)
        metadata = json.loads(subprocess.check_output(
            ['cargo', 'metadata', '--locked', '--offline', '--format-version', '1'], cwd=source))
        lines = ['Agent Bridge dependency copyright and license notices',
                 f'Corresponding source commit: {args.commit}',
                 'The original project is GPL-3.0-or-later; dependencies retain their own licenses.', '']
        for package in sorted(metadata['packages'], key=lambda p: (p['name'], p['version'])):
            lines.extend([f"=== {package['name']} {package['version']} ===",
                          'Declared license: ' + (package.get('license') or 'see source license files'),
                          'Repository: ' + (package.get('repository') or '(see corresponding source)'), ''])
            for name, content in license_files(package):
                lines.extend([f'--- {name} ---', content, ''])
        (dist / 'THIRD_PARTY_LICENSES.txt').write_text('\n'.join(lines))
        shutil.copy2(source / 'LICENSE', dist / 'LICENSE')
        (dist / 'SOURCE_COMMIT').write_text(args.commit + '\n')
        (source / 'SOURCE_COMMIT').write_text(args.commit + '\n')
        (source / 'BUILDING-OFFLINE.md').write_text('Build with Rust 1.98.0 and the platform C toolchain.\n\nAGENT_BRIDGE_BUILD_COMMIT=$(cat SOURCE_COMMIT) cargo build --release --locked --offline\n')
        source_archive = dist / f'agent-bridge-source-{args.commit[:12]}.tar.gz'
        with tarfile.open(source_archive, 'w:gz') as output:
            output.add(source, arcname='agent-bridge',
                       filter=lambda info: normalized_entry(info, timestamp))
    (dist / 'RELEASE_NOTES.md').write_text(
        '# Agent Bridge\n\n'
        'Peer-to-peer agent messaging, MCP tools and a live shared Markdown board.\n\n'
        f'Source commit: `{args.commit}`\n\n'
        f'Build: `{args.commit[:12]}`. Install a specific release tag to pin this build.\n\n'
        'Linux: x86_64/aarch64, glibc 2.35 or newer. macOS: Intel/Apple Silicon, macOS 13 or newer.\n'
        'macOS binaries are ad-hoc signed, not Apple notarized.\n\n'
        'SHA256SUMS protects download integrity; it is not an independent publisher signature.\n'
        'LICENSE and THIRD_PARTY_LICENSES.txt accompany the binaries. The source archive includes\n'
        'all locked registry dependencies plus an offline Cargo source configuration.\n'
        'Back up state before upgrading; older binaries must not open a migrated database.\n')
    files = sorted(path for path in dist.iterdir() if path.is_file() and path.name != 'SHA256SUMS')
    with (dist / 'SHA256SUMS').open('w') as output:
        for path in files:
            with path.open('rb') as stream:
                hasher = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    hasher.update(chunk)
                digest = hasher.hexdigest()
            output.write(f'{digest}  {path.name}\n')


if __name__ == '__main__':
    main()
