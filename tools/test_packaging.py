#!/usr/bin/env python3
"""Check public source archive metadata and original-notice isolation."""
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from package_dogfood import license_files, normalized_entry


class PackagingTests(unittest.TestCase):
    def test_archive_metadata_never_contains_build_machine_identity(self):
        info = tarfile.TarInfo('agent-bridge/source.rs')
        info.uid, info.gid = 1234, 4321
        info.uname, info.gname = 'private-build-user', 'private-build-group'
        info.mtime, info.size = 100.5, 3
        info.pax_headers = {'atime': '100.5', 'ctime': '99.1'}
        result = normalized_entry(info, 123)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as archive:
            archive.addfile(result, io.BytesIO(b'abc'))
        buffer.seek(0)
        with tarfile.open(fileobj=buffer, mode='r') as archive:
            saved = archive.getmembers()[0]
        self.assertEqual((saved.uid, saved.gid, saved.uname, saved.gname, saved.mtime),
                         (0, 0, '', '', 123))
        self.assertNotIn(b'private-build', buffer.getvalue())
        self.assertEqual(saved.pax_headers, {})

    def test_build_outputs_and_git_metadata_are_not_corresponding_source(self):
        for name in ('agent-bridge/target/debug/app', 'agent-bridge/.git/config'):
            self.assertIsNone(normalized_entry(tarfile.TarInfo(name), 123))

    def test_license_symlinks_cannot_read_outside_package(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / 'package'
            package.mkdir()
            (package / 'Cargo.toml').write_text('[package]\n')
            (package / 'LICENSE').write_text('original copyright notice')
            (root / 'private').write_text('outside-package-sensitive-value')
            (package / 'NOTICE').symlink_to(root / 'private')
            found = license_files({'manifest_path': str(package / 'Cargo.toml')})
            self.assertEqual(found, [('LICENSE', 'original copyright notice')])


if __name__ == '__main__':
    unittest.main()
