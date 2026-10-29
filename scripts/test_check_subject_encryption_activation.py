#!/usr/bin/env python3
"""Adversarial E15 fixtures, with no Cargo execution."""

import tempfile
import unittest
from pathlib import Path

from check_subject_encryption_activation import check_source, violations

GATE = '#![cfg(any(test, feature = "test-support"))]\n'
LOCK = "pub struct SubjectEncryptorLock; impl SubjectEncryptorLock { fn acquire() {} }"
OWNER = "impl EnrollmentPort for RealOwner {} impl UnlockPort for RealOwner {}"


class ActivationPolicyTests(unittest.TestCase):
    def test_activation_definitions_require_a_real_leading_gate(self):
        for surface in [LOCK, OWNER, "fn build() -> Result<SubjectEncryptorLock, Error> {}"]:
            self.assertEqual(check_source("crates/x/src/fixture.rs", GATE + surface), [])
            for prefix in ["", "// " + GATE, 'const DOC: &str = r#"' + GATE + '"#;\n', "fn prior() {}\n" + GATE, '#[cfg(any(test, feature = "test-support"))]\n']:
                self.assertTrue(check_source("crates/x/src/fixture.rs", prefix + surface))

    def test_aliases_and_raw_names_do_not_hide_the_surface(self):
        for name in ["SubjectEncryptorLock", "EnrollmentPort", "UnlockPort"]:
            for source in [f"use owner::{name} as Hidden;", f"use owner::{{{name} as Hidden}};", f"use owner::r#{name};", f"type Hidden = owner::{name};"]:
                self.assertTrue(check_source("crates/x/src/lib.rs", GATE + source))

    def test_apps_allow_only_explicit_test_items(self):
        call = "fn exercise() { SubjectEncryptorLock::acquire(); }"
        for source in [call, GATE + call, "#[cfg(test)] mod tests {}\n" + call]:
            self.assertTrue(check_source("apps/x/src/main.rs", source))
        for source in ["#[cfg(test)] " + call, "#[cfg(test)] mod tests { " + call + " }", "#![cfg(test)]\n" + GATE + call]:
            # The constructor call itself also belongs in a gated fixture file.
            self.assertEqual(check_source("apps/x/src/test.rs", GATE + source), [])
        self.assertEqual(check_source("apps/x/src/main.rs", "#[cfg(test)] use owner::SubjectEncryptorLock;"), [])

    def test_comments_literals_and_real_protocol_fakes(self):
        for text in ["// " + LOCK, "/* outer /* nested */ " + OWNER + " */", 'const TEXT: &str = r#"' + LOCK + '"#;', "fn validation(_: TargetOs) {}"]:
            self.assertEqual(check_source("apps/x/src/main.rs", text), [])
        path = "crates/pos-owner-bridge/tests/protocol/main.rs"
        self.assertEqual(check_source(path, "impl EnrollmentPort for FakeEnrollment {} impl UnlockPort for FakeUnlock {}"), [])
        self.assertTrue(check_source("crates/x/src/fake.rs", "impl EnrollmentPort for FakeEnrollment {}"))
        self.assertTrue(check_source(path, "impl EnrollmentPort for PretendFake {}"))

    def test_filesystem_scan_keeps_nested_target_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ["target/generated.rs", "crates/x/src/target/hidden.rs"]:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(LOCK)
            found = violations(root)
            self.assertEqual(len(found), 1)
            self.assertIn("crates/x/src/target/hidden.rs", found[0])


if __name__ == "__main__":
    unittest.main()
