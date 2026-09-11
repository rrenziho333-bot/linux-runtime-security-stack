#!/usr/bin/env python3
"""Validate and install the repository's reproducible Falco rule bundle."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

import yaml


OFFICIAL = ('falco_rules.yaml', 'falco-sandbox_rules.yaml', 'falco-incubating_rules.yaml')
LEGACY_CUSTOM = {'90-local-file-monitoring.yaml', '95-security-stack-exceptions.yaml'}


def content(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Expected a regular, non-symlink rule file: ' + str(path))
    return path.read_text(encoding='utf-8').replace('\r\n', '\n').encode('utf-8')


def rule_count(data):
    entries = yaml.safe_load(data)
    if not isinstance(entries, list):
        raise ValueError('A rule file must contain a YAML list')
    return sum(isinstance(entry, dict) and 'rule' in entry for entry in entries)


def lock_rules(source):
    files = {}
    for name in OFFICIAL:
        data = content(source / 'official-rules' / name)
        files[name] = {'sha256': hashlib.sha256(data).hexdigest(), 'rules': rule_count(data)}
    lock = {'version': 1, 'normalization': 'UTF-8 with LF newlines', 'files': files}
    (source / 'rules.lock.json').write_text(json.dumps(lock, indent=2) + '\n', encoding='utf-8')


def load_bundle(source):
    lock = json.loads((source / 'rules.lock.json').read_text(encoding='utf-8'))
    if lock.get('version') != 1 or set(lock.get('files', {})) != set(OFFICIAL):
        raise ValueError('Invalid rules.lock.json; expected all three official rule files')
    bundle = {}
    for name in OFFICIAL:
        data = content(source / 'official-rules' / name)
        expected = lock['files'][name]
        if hashlib.sha256(data).hexdigest() != expected['sha256'] or rule_count(data) != expected['rules']:
            raise ValueError('Official rules differ from rules.lock.json: ' + name)
        bundle['official/' + name] = data
    custom = source / 'rules.d'
    if not custom.is_dir() or custom.is_symlink():
        raise ValueError('Missing regular custom rules directory: ' + str(custom))
    for path in sorted(custom.glob('*.yaml')):
        data = content(path)
        rule_count(data)
        bundle['custom/' + path.name] = data
    return bundle


def bundle_id(bundle):
    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in sorted(bundle.items())}
    return hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()


def config_overrides(config, parent):
    for item in config.get('config_files', []):
        name = item.get('path') if isinstance(item, dict) else item
        if not isinstance(name, str) or not Path(name).is_absolute():
            raise ValueError('config_files paths must be absolute; inspect ' + str(parent))
        path = Path(name)
        files = sorted(path.iterdir()) if path.is_dir() else [path]
        for file in files:
            if not file.is_file() or (path.is_dir() and file.suffix not in ('.yaml', '.yml')):
                continue
            data = yaml.safe_load(file.read_text(encoding='utf-8')) or {}
            if isinstance(data, dict) and 'rules_files' in data:
                raise ValueError('Conflicting rules_files override: ' + str(file)
                                 + '; consolidate it into the main config first')


def host_rule_paths(config, parent, target, bundle):
    custom_names = LEGACY_CUSTOM | {Path(name).name for name in bundle if name.startswith('custom/')}
    result = []
    for name in config.get('rules_files', []):
        path = Path(name)
        if not path.is_absolute():
            path = parent / path
        path = path.absolute()
        if path == target or target in path.parents:
            continue
        if path.parent == parent and path.name in OFFICIAL:
            continue
        if path.parent == parent / 'rules.d' and path.name in custom_names:
            continue
        if path == parent / 'rules.d':
            candidates = sorted(path.iterdir()) if path.is_dir() else []
            paths = [p for p in candidates if p.suffix in ('.yaml', '.yml') and p.name not in custom_names]
        elif path == parent / 'falco_rules.local.yaml' and not path.exists():
            paths = []
        else:
            paths = [path]
        for file in paths:
            if not file.exists():
                raise ValueError('Configured host rule path does not exist: ' + str(file))
            if str(file) not in result:
                result.append(str(file))
    return result


def rule_paths(directory, bundle, extras):
    paths = [str(directory / 'official' / name) for name in OFFICIAL]
    paths += [str(directory / name) for name in sorted(bundle) if name.startswith('custom/')]
    return paths + extras


def write_bundle(directory, bundle):
    for name, data in bundle.items():
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.parent.chmod(0o755)
        path.write_bytes(data)
        path.chmod(0o644)
    manifest = {'bundle_sha256': bundle_id(bundle), 'files': {
        name: {'sha256': hashlib.sha256(data).hexdigest(), 'rule_definitions': rule_count(data)}
        for name, data in bundle.items()}}
    (directory / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    (directory / 'manifest.json').chmod(0o644)


def install_rules(source, config_path, target, falco='falco', check=False):
    if config_path.is_symlink():
        raise ValueError('The managed Falco config must not be a symlink')
    bundle = load_bundle(source)
    original = config_path.read_bytes()
    config = yaml.safe_load(original)
    if not isinstance(config, dict) or not isinstance(config.get('rules_files'), list):
        raise ValueError('The Falco config must contain a rules_files list')
    config_overrides(config, config_path.parent)
    extras = host_rule_paths(config, config_path.parent, target, bundle)
    release = target / bundle_id(bundle)
    # Validate an isolated candidate before changing any installed rules or config.
    with tempfile.TemporaryDirectory(prefix='lrss-rules-') as temporary:
        stage = Path(temporary)
        write_bundle(stage, bundle)
        candidate = dict(config, rules_files=rule_paths(stage, bundle, extras))
        candidate_path = stage / 'falco.yaml'
        candidate_path.write_text(yaml.safe_dump(candidate, sort_keys=False), encoding='utf-8')
        subprocess.run([falco, '-c', str(candidate_path), '-L', '-o', 'json_output=false'],
                       check=True, stdout=subprocess.DEVNULL, timeout=90)
        if not check:
            target.mkdir(parents=True, exist_ok=True)
            if target.is_symlink():
                raise ValueError('Managed rules directory must not be a symlink')
            if release.exists():
                if release.is_symlink() or any(content(release / name) != data for name, data in bundle.items()):
                    raise ValueError('Existing managed bundle was modified: ' + str(release))
            else:
                with tempfile.TemporaryDirectory(prefix='.install-', dir=target) as install_temp:
                    prepared = Path(install_temp) / 'bundle'
                    prepared.mkdir(mode=0o755)
                    write_bundle(prepared, bundle)
                    os.replace(prepared, release)
            final = dict(config, rules_files=rule_paths(release, bundle, extras))
            if final != config:
                if config_path.read_bytes() != original:
                    raise ValueError('Falco config changed during validation; retry without concurrent edits')
                backup = config_path.with_name(config_path.name + '.bak-rules-' + str(time.time_ns()))
                shutil.copy2(config_path, backup)
                fd, temporary_config = tempfile.mkstemp(prefix='.rules-config-', dir=config_path.parent)
                try:
                    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                        yaml.safe_dump(final, stream, sort_keys=False)
                    shutil.copymode(config_path, temporary_config)
                    if hasattr(os, 'chown'):
                        metadata = config_path.stat()
                        os.chown(temporary_config, metadata.st_uid, metadata.st_gid)
                    os.replace(temporary_config, config_path)
                finally:
                    if os.path.exists(temporary_config):
                        os.unlink(temporary_config)
                print('Original configuration backup:', backup)
    print('Rule bundle:', bundle_id(bundle))
    print('Official rule definitions:', sum(rule_count(v) for k, v in bundle.items() if k.startswith('official/')))
    print('Custom rule definitions:', sum(rule_count(v) for k, v in bundle.items() if k.startswith('custom/')))
    print('Definitions are not an enabled-rule count; enabled flags and Falco filters still apply.')
    print('Managed rules location:', release)
    print('Preserved host rule paths:', json.dumps(extras))
    print('Check passed; no installed files changed.' if check else 'Rules installed; restart Falco to activate.')
    return release


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'install', 'lock'))
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--config', type=Path, default=Path('/etc/falco/falco.yaml'))
    parser.add_argument('--target', type=Path, default=Path('/etc/falco/security-stack/rules'))
    args = parser.parse_args()
    try:
        if args.action == 'lock':
            lock_rules(args.source)
        else:
            if args.action == 'install' and os.geteuid() != 0:
                raise ValueError('Installation requires sudo')
            if args.action == 'install':
                import fcntl
                with (args.config.parent / '.security-stack-rules.lock').open('a') as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX)
                    install_rules(args.source.resolve(), args.config.absolute(), args.target.absolute())
            else:
                install_rules(args.source.resolve(), args.config.absolute(), args.target.absolute(), check=True)
    except (OSError, ValueError, KeyError, yaml.YAMLError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Rule deployment failed: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
