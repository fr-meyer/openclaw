"""Bounded, metadata-only fit check for the fixed retained report and OCI tree.

This does not read a private file body, accept an OCI graph, or issue copy or
qualification authority. The subsequent descriptor copier independently checks
all source bytes, digests, identities, file counts, and aggregate byte limits.
"""
from __future__ import annotations

import os
import re
import stat

import copier
import protocol as p

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_SHA256_NAME = re.compile(r'[0-9a-f]{64}\Z')
JSON_METADATA_MAX = 32 * 1024 * 1024


def _directory_identity(info):
    return tuple(getattr(info, key) for key in
                 ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                  'st_nlink', 'st_mtime_ns', 'st_ctime_ns'))


def _file_identity(info):
    return tuple(getattr(info, key) for key in
                 ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                  'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def _open_child(parent_fd, name, device, tracked):
    fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    try:
        before = os.fstat(fd)
        p.require(stat.S_ISDIR(before.st_mode) and before.st_dev == device and
                  _directory_identity(before) == _directory_identity(
                      os.stat(name, dir_fd=parent_fd, follow_symlinks=False)),
                  'copy_metadata.directory_identity')
        tracked.append((fd, before, parent_fd, name))
        return fd
    except BaseException:
        os.close(fd)
        raise


def _chain(root_fd, parts, device, tracked):
    current = root_fd
    for name in parts:
        current = _open_child(current, name, device, tracked)
    return current


def _names(fd, maximum, role):
    names = []
    with os.scandir(fd) as entries:
        for entry in entries:
            p.require(len(names) < maximum, 'copy_metadata.entry_cap',
                      {'role': role, 'maximum': maximum})
            names.append(entry.name)
    return sorted(names)


def _file(fd, name, relative, device, maximum, tracked):
    before = os.stat(name, dir_fd=fd, follow_symlinks=False)
    p.require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
              before.st_dev == device and 0 <= before.st_size <= maximum,
              'copy_metadata.file_identity')
    tracked.append((fd, name, before))
    return {'path': relative, 'bytes': before.st_size,
            'identitySha256': p.sha(p.canonical(_file_identity(before)))}


def admittance(source_root_fd, report_relative, oci_relative,
               report_bytes, max_files, max_bytes):
    """Return only a bounded size/count receipt from already authorized TEST.

    `source_root_fd` must be the caller's held, source-verified read-only TEST
    directory. The check opens directories only; it never opens report, OCI
    metadata, or blob file contents. It does not create a destination.
    """
    p.require(type(source_root_fd) is int and source_root_fd >= 0 and
              type(report_bytes) is int and 0 < report_bytes <= p.PRIVATE_MAX and
              type(max_files) is int and 3 <= max_files <= p.MAX_FILES and
              type(max_bytes) is int and report_bytes <= max_bytes <= p.PRIVATE_MAX,
              'copy_metadata.bounds')
    report = copier.relative_parts(report_relative)
    oci = copier.relative_parts(oci_relative)
    p.require(report and oci and report != oci and
              not (len(report) > len(oci) and report[:len(oci)] == oci) and
              not (len(oci) > len(report) and oci[:len(report)] == report),
              'copy_metadata.paths')
    root_fd = os.dup(source_root_fd)
    directories = []
    files = []
    try:
        root_before = os.fstat(root_fd)
        p.require(stat.S_ISDIR(root_before.st_mode), 'copy_metadata.source_root')
        device = root_before.st_dev
        report_parent = _chain(root_fd, report[:-1], device, directories)
        rows = [_file(report_parent, report[-1], 'privacy.json',
                      device, report_bytes, files)]
        p.require(rows[0]['bytes'] == report_bytes, 'copy_metadata.report_size')
        oci_fd = _chain(root_fd, oci, device, directories)
        root_names = _names(oci_fd, 4, 'oci_root')
        p.require(set(root_names) in ({'oci-layout', 'index.json', 'blobs'},
                                    {'oci-layout', 'index.json', 'blobs', 'ingest'}),
                  'copy_metadata.oci_root_roster')
        for name in ('oci-layout', 'index.json'):
            rows.append(_file(oci_fd, name, 'oci/' + name,
                              device, min(JSON_METADATA_MAX,
                                  max_bytes - sum(row['bytes'] for row in rows)), files))
        blobs_fd = _open_child(oci_fd, 'blobs', device, directories)
        p.require(_names(blobs_fd, 1, 'blob_algorithm') == ['sha256'],
                  'copy_metadata.blob_algorithm')
        algorithm_fd = _open_child(blobs_fd, 'sha256', device, directories)
        blob_names = _names(algorithm_fd, max_files - 3, 'oci_blobs')
        p.require(blob_names, 'copy_metadata.empty_blobs')
        for name in blob_names:
            p.require(_SHA256_NAME.fullmatch(name) is not None,
                      'copy_metadata.blob_name')
            rows.append(_file(algorithm_fd, name, 'oci/blobs/sha256/' + name,
                              device, max_bytes - sum(row['bytes'] for row in rows), files))
        if 'ingest' in root_names:
            ingest_fd = _open_child(oci_fd, 'ingest', device, directories)
            p.require(_names(ingest_fd, 0, 'ingest') == [],
                      'copy_metadata.ingest_nonempty')
        p.require(_names(oci_fd, 4, 'oci_root_recheck') == root_names and
                  _names(blobs_fd, 1, 'blob_algorithm_recheck') == ['sha256'] and
                  _names(algorithm_fd, max_files - 3, 'oci_blobs_recheck') == blob_names,
                  'copy_metadata.roster_changed')
        for fd, name, before in files:
            p.require(_file_identity(before) == _file_identity(
                os.stat(name, dir_fd=fd, follow_symlinks=False)),
                'copy_metadata.file_changed')
        for fd, before, parent_fd, name in reversed(directories):
            p.require(_directory_identity(before) == _directory_identity(os.fstat(fd)) ==
                      _directory_identity(os.stat(name, dir_fd=parent_fd,
                                                  follow_symlinks=False)),
                      'copy_metadata.directory_changed')
        p.require(_directory_identity(root_before) == _directory_identity(os.fstat(root_fd)),
                  'copy_metadata.source_root_changed')
        total = sum(row['bytes'] for row in rows)
        p.require(len(rows) <= max_files and total <= max_bytes,
                  'copy_metadata.aggregate')
        return {'schema': 'openclaw.private-copy-metadata-admission.v1',
                'files': len(rows), 'blobFiles': len(blob_names), 'bytes': total,
                'rosterSha256': p.sha(p.canonical(rows)), 'contentVerified': False,
                'privacyVerdict': False, 'qualificationAuthority': False}
    finally:
        for fd, *_ in reversed(directories):
            os.close(fd)
        os.close(root_fd)


if __name__ == '__main__':
    raise SystemExit('copy_metadata_admission_no_cli')
