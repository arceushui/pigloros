#!/usr/bin/env python3
"""Adversarial fixtures for the E16 dependency pin, without invoking Cargo."""

import copy
import unittest

from check_owner_bridge_lock import (
    CHECKSUM, SOURCE, TARGET, WINDOWS_PINS, WEBVIEW_PINS, WINDOWS_TARGET, COMPANIONS, check, check_windows,
)


class OwnerBridgeLockTests(unittest.TestCase):
    def setUp(self):
        self.lock = {
            "package": [
                {"name": "rustix", "version": "0.38.44"},
                {"name": "rustix", "version": "1.1.6", "source": SOURCE, "checksum": CHECKSUM},
                {"name": "pos-owner-bridge", "dependencies": ["rustix 1.1.6"]},
            ]
        }
        self.owner = {"target": {TARGET: {"dependencies": {
            "rustix": {"workspace": True, "features": ["process"]}
        }}}}
        self.workspace = {"workspace": {"dependencies": {"rustix": {
            "version": "1.1.4", "default-features": False, "features": ["fs", "std"]
        }}}}

    def test_selected_graph(self):
        self.assertEqual(check(self.lock, self.owner, self.workspace), [])

    def test_package_pin_and_owner_resolution(self):
        for field in ["version", "source", "checksum"]:
            lock = copy.deepcopy(self.lock)
            lock["package"][1][field] = "unapproved"
            self.assertTrue(check(lock, self.owner, self.workspace), field)
        for index in [1, 2]:
            for duplicate in [False, True]:
                lock = copy.deepcopy(self.lock)
                if duplicate:
                    lock["package"].append(copy.deepcopy(lock["package"][index]))
                else:
                    lock["package"].pop(index)
                self.assertTrue(check(lock, self.owner, self.workspace))
        for dependencies in [["rustix 0.38.44"], ["rustix 1.1.6", "rustix 0.38.44"]]:
            self.lock["package"][2]["dependencies"] = dependencies
            self.assertTrue(check(self.lock, self.owner, self.workspace))

    def test_target_and_feature_confinement(self):
        for field, value in [("workspace", False), ("features", []), ("features", ["process", "net"])]:
            owner = copy.deepcopy(self.owner)
            owner["target"][TARGET]["dependencies"]["rustix"][field] = value
            self.assertTrue(check(self.lock, owner, self.workspace))
        for destination in ["dependencies", 'cfg(windows)']:
            owner = copy.deepcopy(self.owner)
            if destination == "dependencies":
                owner[destination] = {"rustix": {"workspace": True}}
            else:
                owner["target"][destination] = {"dependencies": {"rustix": {"workspace": True}}}
            self.assertTrue(check(self.lock, owner, self.workspace))
        self.assertTrue(check(self.lock, {}, self.workspace))
        for target in [None, TARGET, 'cfg(windows)']:
            for kind in ["dependencies", "dev-dependencies", "build-dependencies"]:
                for name in ["rustix", "renamed"]:
                    if (target, kind, name) == (TARGET, "dependencies", "rustix"):
                        continue
                    owner = copy.deepcopy(self.owner)
                    table = owner if target is None else owner["target"].setdefault(target, {})
                    table.setdefault(kind, {})[name] = {"package": "rustix", "version": "1.1.6"}
                    self.assertTrue(check(self.lock, owner, self.workspace), (target, kind, name))

    def test_workspace_features_stay_unchanged(self):
        for field, value in [("version", "1.1.6"), ("default-features", True), ("features", ["fs", "std", "process"])]:
            workspace = copy.deepcopy(self.workspace)
            workspace["workspace"]["dependencies"]["rustix"][field] = value
            self.assertTrue(check(self.lock, self.owner, workspace))


class WindowsFamilyLockTests(unittest.TestCase):
    def setUp(self):
        self.lock = {"package": [
            {"name": name, "version": version, "source": SOURCE, "checksum": checksum}
            for name, (version, checksum) in WINDOWS_PINS.items()
        ] + [{"name": "pos-owner-bridge-windows", "dependencies": ["windows"]}]}
        self.shim = {"target": {WINDOWS_TARGET: {"dependencies": {
            "windows": {"workspace": True, "features": ["Win32_Foundation"]}
        }}}}
        self.workspace = {"workspace": {"dependencies": {"windows": {
            "version": "=0.62.2", "default-features": False, "features": ["std"]
        }}}}

    def enable_webview(self):
        self.workspace["workspace"]["dependencies"]["webview2-com"] = "=0.39.1"
        self.shim["target"][WINDOWS_TARGET]["dependencies"]["webview2-com"] = {"workspace": True}
        self.lock["package"][-1]["dependencies"].append("webview2-com")
        self.lock["package"].extend(
            {"name": name, "version": version, "source": SOURCE, "checksum": checksum}
            for name, (version, checksum) in WEBVIEW_PINS.items()
        )

    def test_current_and_full_consumed_graphs(self):
        self.assertEqual(check_windows(self.lock, self.shim, self.workspace), [])
        self.enable_webview()
        self.assertEqual(check_windows(self.lock, self.shim, self.workspace), [])

    def test_every_selected_version_source_checksum_and_single_version_rule(self):
        self.enable_webview()
        for name in WINDOWS_PINS | WEBVIEW_PINS:
            index = next(i for i, package in enumerate(self.lock["package"]) if package["name"] == name)
            for field in ["version", "source", "checksum"]:
                lock = copy.deepcopy(self.lock)
                lock["package"][index][field] = "unapproved"
                self.assertTrue(check_windows(lock, self.shim, self.workspace), (name, field))
            for duplicate in [False, True]:
                lock = copy.deepcopy(self.lock)
                if duplicate:
                    lock["package"].append(copy.deepcopy(lock["package"][index]))
                else:
                    lock["package"].pop(index)
                self.assertTrue(check_windows(lock, self.shim, self.workspace), (name, duplicate))

    def test_pins_are_added_only_when_consumed(self):
        for name, (version, checksum) in WEBVIEW_PINS.items():
            lock = copy.deepcopy(self.lock)
            lock["package"].append({"name": name, "version": version, "source": SOURCE, "checksum": checksum})
            self.assertTrue(check_windows(lock, self.shim, self.workspace), name)
        self.workspace["workspace"]["dependencies"]["webview2-com"] = "=0.39.1"
        self.assertTrue(check_windows(self.lock, self.shim, self.workspace))
        self.enable_webview()
        for dependency in ["0.39.1", {"workspace": True, "features": []}, {"workspace": False}]:
            shim = copy.deepcopy(self.shim)
            shim["target"][WINDOWS_TARGET]["dependencies"]["webview2-com"] = dependency
            self.assertTrue(check_windows(self.lock, shim, self.workspace), dependency)
        self.workspace["workspace"]["dependencies"]["webview2-com"] = "0.39.1"
        self.assertTrue(check_windows(self.lock, self.shim, self.workspace))

    def test_windows_workspace_pin_and_shim_scope_are_exact(self):
        for field, value in [("version", "0.62.2"), ("default-features", True), ("features", [])]:
            workspace = copy.deepcopy(self.workspace)
            workspace["workspace"]["dependencies"]["windows"][field] = value
            self.assertTrue(check_windows(self.lock, self.shim, workspace), field)
        self.enable_webview()
        for name in ["windows", "webview2-com"]:
            for target in [None, WINDOWS_TARGET, TARGET]:
                for kind in ["dependencies", "dev-dependencies", "build-dependencies"]:
                    for alias in [name, "renamed"]:
                        if (target, kind, alias) == (WINDOWS_TARGET, "dependencies", name):
                            continue
                        shim = copy.deepcopy(self.shim)
                        table = shim if target is None else shim["target"].setdefault(target, {})
                        table.setdefault(kind, {})[alias] = {"package": name, "workspace": True}
                        self.assertTrue(check_windows(self.lock, shim, self.workspace), (name, target, kind, alias))
        self.assertTrue(check_windows(self.lock, {}, self.workspace))

    def test_companions_remain_transitive_and_lock_edges_match(self):
        self.enable_webview()
        for name in COMPANIONS:
            for alias in [name, "renamed"]:
                workspace = copy.deepcopy(self.workspace)
                workspace["workspace"]["dependencies"][alias] = {"package": name, "version": "=0.1.0"}
                self.assertTrue(check_windows(self.lock, self.shim, workspace), (name, alias))
                shim = copy.deepcopy(self.shim)
                shim["target"][WINDOWS_TARGET]["dependencies"][alias] = {"package": name, "version": "=0.1.0"}
                self.assertTrue(check_windows(self.lock, shim, self.workspace), (name, alias))
        index = next(i for i, package in enumerate(self.lock["package"]) if package["name"] == "pos-owner-bridge-windows")
        for dependencies in [["windows"], ["webview2-com"], ["windows", "webview2-com", "windows-core"], ["windows", "windows", "webview2-com"]]:
            lock = copy.deepcopy(self.lock)
            lock["package"][index]["dependencies"] = dependencies
            self.assertTrue(check_windows(lock, self.shim, self.workspace), dependencies)
        for duplicate in [False, True]:
            lock = copy.deepcopy(self.lock)
            if duplicate:
                lock["package"].append(copy.deepcopy(lock["package"][index]))
            else:
                lock["package"].pop(index)
            self.assertTrue(check_windows(lock, self.shim, self.workspace))

    def test_forbidden_dependency_families(self):
        for name in ["openssl", "openssl-sys", "openssl-src", "tauri", "wry", "webauthn-rs", "webauthn-rs-core"]:
            lock = copy.deepcopy(self.lock)
            lock["package"].append({"name": name})
            self.assertTrue(check_windows(lock, self.shim, self.workspace), name)


if __name__ == "__main__":
    unittest.main()
