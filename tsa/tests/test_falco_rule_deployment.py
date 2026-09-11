import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml


SCRIPT = Path(__file__).resolve().parents[2] / 'falco' / 'manage_rules.py'
SPEC = importlib.util.spec_from_file_location('manage_rules', SCRIPT)
rules = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rules)


class RuleDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'repository'
        self.etc = self.root / 'etc' / 'falco'
        self.target = self.etc / 'security-stack' / 'rules'
        self.config = self.etc / 'falco.yaml'
        (self.source / 'official-rules').mkdir(parents=True)
        (self.source / 'rules.d').mkdir()
        (self.etc / 'rules.d').mkdir(parents=True)
        (self.etc / 'config.d').mkdir()
        for name in rules.OFFICIAL:
            (self.source / 'official-rules' / name).write_text('- rule: ' + name + '\n')
        (self.source / 'rules.d' / '90-local-file-monitoring.yaml').write_text('- rule: project\n')
        rules.lock_rules(self.source)
        self.original = {
            'rules_files': [str(self.etc / n) for n in rules.OFFICIAL] + [
                str(self.etc / 'rules.d'), str(self.etc / 'falco_rules.local.yaml')],
            'config_files': [str(self.etc / 'config.d')],
            'rule_matching': 'first', 'priority': 'debug',
        }
        self.config.write_text(yaml.safe_dump(self.original))
        self.validation = patch.object(rules.subprocess, 'run').start()
        self.addCleanup(patch.stopall)

    def install(self, check=False):
        return rules.install_rules(self.source, self.config, self.target, check=check)

    def loaded(self):
        return yaml.safe_load(self.config.read_text())['rules_files']

    def test_fresh_machine_does_not_need_package_rule_files(self):
        release = self.install()
        self.assertEqual(len(self.loaded()), 4)
        self.assertTrue(all(str(release) in p for p in self.loaded()))
        self.assertEqual(json.loads((release / 'manifest.json').read_text())['bundle_sha256'], release.name)
        self.validation.assert_called_once()

    def test_check_does_not_install_or_change_config(self):
        before = self.config.read_bytes()
        self.install(check=True)
        self.assertEqual(self.config.read_bytes(), before)
        self.assertFalse(self.target.exists())

    def test_invalid_rules_leave_existing_config_and_files_untouched(self):
        before = self.config.read_bytes()
        self.validation.side_effect = subprocess.CalledProcessError(1, 'falco')
        with self.assertRaises(subprocess.CalledProcessError):
            self.install()
        self.assertEqual(self.config.read_bytes(), before)
        self.assertFalse(self.target.exists())

    def test_missing_bundled_rule_fails_without_system_fallback(self):
        (self.source / 'official-rules' / rules.OFFICIAL[0]).unlink()
        (self.etc / rules.OFFICIAL[0]).write_text('- rule: installed\n')
        with self.assertRaises(ValueError):
            self.install()
        self.validation.assert_not_called()

    def test_checksum_mismatch_rejected(self):
        (self.source / 'official-rules' / rules.OFFICIAL[0]).write_text('- rule: changed\n')
        with self.assertRaisesRegex(ValueError, 'differ'):
            self.install()

    def test_package_and_host_rules_preserved_without_legacy_duplicates(self):
        package = self.etc / rules.OFFICIAL[0]
        package.write_text('- rule: package\n')
        host = self.etc / 'rules.d' / 'my-rule.yaml'
        host.write_text('- rule: host\n')
        legacy = self.etc / 'rules.d' / '90-local-file-monitoring.yaml'
        legacy.write_text('- rule: old project copy\n')
        local = self.etc / 'falco_rules.local.yaml'
        local.write_text('[]\n')
        self.install()
        self.assertIn(str(host), self.loaded())
        self.assertIn(str(local), self.loaded())
        self.assertNotIn(str(package), self.loaded())
        self.assertNotIn(str(legacy), self.loaded())
        self.assertEqual(package.read_text(), '- rule: package\n')
        self.assertEqual(legacy.read_text(), '- rule: old project copy\n')

    def test_redeployment_is_idempotent_and_keeps_other_config(self):
        first = self.install()
        before = self.config.read_bytes()
        self.assertEqual(self.install(), first)
        self.assertEqual(self.config.read_bytes(), before)
        self.assertEqual(len(list(self.etc.glob('falco.yaml.bak-rules-*'))), 1)
        self.assertEqual(yaml.safe_load(before)['priority'], 'debug')

    def test_custom_rule_add_and_remove_selects_new_bundle(self):
        original = self.install()
        extra = self.source / 'rules.d' / '91-extra.yaml'
        extra.write_text('- rule: extra\n')
        added = self.install()
        self.assertNotEqual(added, original)
        self.assertIn(str(added / 'custom' / extra.name), self.loaded())
        extra.unlink()
        self.assertEqual(self.install(), original)
        self.assertFalse(any('91-extra.yaml' in p for p in self.loaded()))
        self.assertTrue((added / 'custom' / extra.name).is_file())

    def test_existing_managed_file_tampering_rejected(self):
        release = self.install()
        (release / 'official' / rules.OFFICIAL[0]).write_text('- rule: altered\n')
        with self.assertRaisesRegex(ValueError, 'modified'):
            self.install()

    def test_config_override_conflict_fails_explicitly(self):
        (self.etc / 'config.d' / 'extra.yaml').write_text('rules_files: []\n')
        with self.assertRaisesRegex(ValueError, 'Conflicting'):
            self.install()
        self.validation.assert_not_called()

    def test_missing_extra_host_rule_not_silently_dropped(self):
        self.original['rules_files'].append(str(self.etc / 'missing.yaml'))
        self.config.write_text(yaml.safe_dump(self.original))
        with self.assertRaisesRegex(ValueError, 'does not exist'):
            self.install()

    def test_host_rule_moved_into_repository_not_loaded_twice(self):
        host = self.etc / 'rules.d' / 'my-rule.yaml'
        host.write_text('- rule: host\n')
        self.install()
        (self.source / 'rules.d' / host.name).write_text('- rule: project-managed\n')
        release = self.install()
        self.assertNotIn(str(host), self.loaded())
        self.assertIn(str(release / 'custom' / host.name), self.loaded())
        self.assertEqual(host.read_text(), '- rule: host\n')

    def test_config_changed_during_validation_not_overwritten(self):
        changed = 'rules_files: []\npriority: warning\n'
        self.validation.side_effect = lambda *a, **kw: self.config.write_text(changed)
        with self.assertRaisesRegex(ValueError, 'changed during'):
            self.install()
        self.assertEqual(self.config.read_text(), changed)

    def test_custom_yaml_must_be_a_list(self):
        (self.source / 'rules.d' / 'invalid.yaml').write_text('rule: not-a-list\n')
        with self.assertRaisesRegex(ValueError, 'YAML list'):
            self.install()

    def test_actual_repository_lock_and_definition_count(self):
        bundle = rules.load_bundle(SCRIPT.parent)
        lock = json.loads((SCRIPT.parent / 'rules.lock.json').read_text())
        self.assertEqual(sum(rules.rule_count(v) for k, v in bundle.items() if k.startswith('official/')),
                         sum(entry['rules'] for entry in lock['files'].values()))


if __name__ == '__main__':
    unittest.main()
