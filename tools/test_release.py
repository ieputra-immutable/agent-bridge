#!/usr/bin/env python3
"""Check version selection and immutable publication without contacting GitHub."""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import release_publish
from release_publish import PLATFORMS, highest_version, publish, verify_assets
from release_version import MAX_COMPONENT, manifest_version, metadata, parse_version, tag_version

COMMIT = '0123456789abcdef0123456789abcdef01234567'


def assets(directory, version='0.2.0', commit=COMMIT):
    directory.mkdir(exist_ok=True)
    for name in PLATFORMS | {'LICENSE', 'THIRD_PARTY_LICENSES.txt', 'RELEASE_NOTES.md',
                             f'agent-bridge-source-v{version}.tar.gz'}:
        (directory / name).write_bytes(('fixture ' + name).encode())
    (directory / 'SOURCE_COMMIT').write_text(commit + '\n')
    (directory / 'SOURCE_VERSION').write_text(version + '\n')
    (directory / 'SHA256SUMS').write_text(''.join(
        f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n'
        for path in sorted(directory.iterdir()) if path.name != 'SHA256SUMS'))


@contextmanager
def working_directory(path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


class VersionTests(unittest.TestCase):
    def test_strict_semver_and_numeric_latest_ordering(self):
        self.assertEqual(parse_version('0.2.0'), '0.2.0')
        self.assertEqual(tag_version('v0.2.0'), '0.2.0')
        self.assertEqual(parse_version(f'{MAX_COMPONENT}.0.0'), f'{MAX_COMPONENT}.0.0')
        for value in ['', 'v0.2.0', '0.02.0', '00.2.0', '0.2', '0.2.0-beta',
                      '0.2.0+build', '0.2.0\n', '１.2.3', '-1.0.0',
                      f'{MAX_COMPONENT + 1}.0.0', '0.2.0;echo']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_version(value)
        releases = [
            {'tag_name': 'v0.9.9'}, {'tag_name': 'v0.10.0'}, {'tag_name': 'v0.2.0'},
            {'tag_name': 'v9.0.0', 'draft': True},
            {'tag_name': 'v8.0.0', 'prerelease': True},
            {'tag_name': 'v0.100.0-beta'}, {'tag_name': 'historical-build'},
        ]
        self.assertEqual(highest_version(releases), 'v0.10.0')

    def test_manifest_fallback_uses_only_literal_package_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest = Path(temporary) / 'Cargo.toml'
            manifest.write_text('[package]\nname = "test"\nversion = "0.2.0"\n\n[dependencies]\nversion = "9.9.9"\n')
            self.assertEqual(manifest_version(manifest), '0.2.0')
            manifest.write_text('[dependencies]\nversion = "9.9.9"\n')
            with self.assertRaises(ValueError):
                manifest_version(manifest)

    def test_tag_metadata_peels_annotations_and_rejects_unmerged_commits(self):
        with tempfile.TemporaryDirectory() as temporary, working_directory(temporary):
            def git(*arguments):
                return subprocess.check_output(['git', '-c', 'user.name=Release tests',
                                               '-c', 'user.email=release-tests@example.invalid',
                                               '-c', 'commit.gpgsign=false',
                                               '-c', 'tag.gpgsign=false',
                                               '-c', 'core.hooksPath=/dev/null',
                                               *arguments], text=True, stderr=subprocess.DEVNULL).strip()
            git('init', '-b', 'main')
            Path('Cargo.toml').write_text('[package]\nversion = "0.1.3"\n')
            git('add', 'Cargo.toml')
            git('commit', '-m', 'fixture')
            commit = git('rev-parse', 'HEAD')
            git('update-ref', 'refs/remotes/origin/main', commit)
            git('tag', '-a', 'v0.2.0', '-m', 'fixture release')
            self.assertEqual(metadata('refs/tags/v0.2.0'),
                             {'version': '0.2.0', 'commit': commit, 'release': 'true'})
            self.assertEqual(metadata('refs/heads/main')['release'], 'false')
            self.assertEqual(metadata('refs/pull/1/merge')['version'], '0.1.3')
            git('tag', 'v0.02.0')
            with self.assertRaises(ValueError):
                metadata('refs/tags/v0.02.0')
            git('checkout', '-b', 'unmerged')
            git('commit', '--allow-empty', '-m', 'not on main')
            git('tag', 'v0.3.0')
            with self.assertRaises(subprocess.CalledProcessError):
                metadata('refs/tags/v0.3.0')


class AssetTests(unittest.TestCase):
    def test_checksums_and_release_identity_are_exact(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            assets(directory)
            verify_assets(directory, COMMIT, '0.2.0')
            for commit, version in [('f' * 40, '0.2.0'), (COMMIT, '0.3.0')]:
                with self.assertRaises(ValueError):
                    verify_assets(directory, commit, version)
            (directory / 'LICENSE').write_text('tampered')
            with self.assertRaises(ValueError):
                verify_assets(directory, COMMIT, '0.2.0')

    def test_unexpected_assets_duplicate_manifest_and_symlinks_fail_closed(self):
        for mode in ['unexpected', 'duplicate', 'symlink']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                assets(directory)
                if mode == 'unexpected':
                    (directory / 'stale-asset').write_text('stale')
                elif mode == 'duplicate':
                    manifest = directory / 'SHA256SUMS'
                    manifest.write_text(manifest.read_text() * 2)
                else:
                    (directory / 'LICENSE').unlink()
                    (directory / 'LICENSE').symlink_to(directory / 'RELEASE_NOTES.md')
                with self.assertRaises(ValueError):
                    verify_assets(directory, COMMIT, '0.2.0')


class PublicationTests(unittest.TestCase):
    def exercise(self, directory, existing=None, stale=False, tag_changed=False):
        calls = []
        lookups = 0

        def gh(*arguments, json_output=False):
            nonlocal lookups
            calls.append(arguments)
            if arguments[:2] == ('api', 'repos/owner/repo/commits/v0.2.0'):
                lookups += 1
                return 'f' * 40 if tag_changed and lookups > 1 else COMMIT
            if arguments[:2] == ('release', 'download'):
                target = Path(arguments[arguments.index('--dir') + 1])
                for path in directory.iterdir():
                    shutil.copyfile(path, target / path.name)
                if stale:
                    (target / 'unexpected-stale-asset').write_text('stale')
            if json_output:
                return [[{'tag_name': 'v0.2.0'}, {'tag_name': 'v0.10.0'}]]
            return ''

        with patch.object(release_publish, 'gh', side_effect=gh), \
                patch.object(release_publish, 'find_release', return_value=existing):
            try:
                publish('owner/repo', 'v0.2.0', COMMIT, directory)
            except ValueError:
                return calls, True
        return calls, False

    def test_new_release_verifies_uploads_before_publication_and_keeps_latest_numeric(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            assets(directory)
            calls, failed = self.exercise(directory)
            self.assertFalse(failed)
            create = next(call for call in calls if call[:2] == ('release', 'create'))
            self.assertIn('--verify-tag', create)
            self.assertIn('--draft', create)
            download = next(i for i, call in enumerate(calls) if call[:2] == ('release', 'download'))
            publish_index = next(i for i, call in enumerate(calls) if '--draft=false' in call)
            self.assertLess(download, publish_index)
            self.assertEqual(calls[-1], ('release', 'edit', 'v0.10.0', '--repo', 'owner/repo', '--latest'))

    def test_published_rerun_checks_original_assets_without_replacing_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            assets(directory)
            calls, failed = self.exercise(directory, existing={'draft': False})
            self.assertFalse(failed)
            self.assertFalse(any(call[:2] in [('release', 'create'), ('release', 'upload')] for call in calls))
            self.assertFalse(any('--draft=false' in call for call in calls))

    def test_draft_repairs_never_publish_stale_assets_or_a_changed_tag(self):
        for stale, changed in [(True, False), (False, True)]:
            with self.subTest(stale=stale, changed=changed), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                assets(directory)
                calls, failed = self.exercise(directory, existing={'draft': True}, stale=stale,
                                              tag_changed=changed)
                self.assertTrue(failed)
                self.assertTrue(any(call[:2] == ('release', 'upload') for call in calls))
                self.assertFalse(any('--draft=false' in call for call in calls))
                self.assertFalse(any('--latest' in call for call in calls))


if __name__ == '__main__':
    unittest.main()
