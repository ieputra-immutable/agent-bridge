#!/usr/bin/env python3
"""Resolve a strict release tag without making the package manifest its source of truth."""
import argparse
import os
from pathlib import Path
import re
import subprocess

MAX_COMPONENT = 2**64 - 1
VERSION = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', re.ASCII)


def parse_version(value):
    match = VERSION.fullmatch(value)
    if not match or len(value) > 62:
        raise ValueError('Expected MAJOR.MINOR.PATCH without leading zeroes or prerelease suffixes')
    parts = tuple(int(part) for part in match.groups())
    if any(part > MAX_COMPONENT for part in parts):
        raise ValueError('Version components must fit an unsigned 64-bit integer')
    return value


def version_key(value):
    return tuple(int(part) for part in parse_version(value).split('.'))


def tag_version(tag):
    if not tag.startswith('v'):
        raise ValueError('Release tags must use vMAJOR.MINOR.PATCH')
    version = tag[1:]
    parse_version(version)
    return version


def git(*arguments):
    return subprocess.check_output(['git', *arguments], text=True).strip()


def manifest_version(manifest):
    # CI's Ubuntu 22.04 Python predates tomllib. Only the repository's literal
    # [package].version is needed here; Cargo still validates the full manifest.
    section = re.search(r'^\[package\]\s*\n(.*?)(?=^\[|\Z)',
                        manifest.read_text(), re.MULTILINE | re.DOTALL)
    match = re.search(r'^version\s*=\s*"([^"\n]+)"\s*$', section[1], re.MULTILINE) if section else None
    if not match:
        raise ValueError('Cargo.toml must contain a literal package version')
    return parse_version(match[1])


def metadata(ref, manifest=Path('Cargo.toml')):
    commit = git('rev-parse', 'HEAD')
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('Checkout must resolve to an immutable full commit SHA')
    release = ref.startswith('refs/tags/')
    if release:
        tag = ref.removeprefix('refs/tags/')
        version = tag_version(tag)
        if git('rev-parse', '--verify', f'refs/tags/{tag}^{{commit}}') != commit:
            raise ValueError('Tag and checked-out commit differ')
        # Checkout fetches complete history and branch refs. Annotated and
        # lightweight tags both resolve to the commit actually being built.
        subprocess.run(['git', 'merge-base', '--is-ancestor', commit,
                        'refs/remotes/origin/main'], check=True)
    else:
        version = manifest_version(manifest)
    return {'version': version, 'commit': commit, 'release': str(release).lower()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--github-output', type=Path)
    args = parser.parse_args()
    try:
        values = metadata(os.environ.get('GITHUB_REF', ''))
    except (ValueError, subprocess.CalledProcessError) as error:
        parser.error(str(error))
    content = ''.join(f'{key}={value}\n' for key, value in values.items())
    if args.github_output:
        with args.github_output.open('a') as output:
            output.write(content)
    print(content, end='')


if __name__ == '__main__':
    main()
