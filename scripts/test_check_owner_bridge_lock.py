#!/usr/bin/env python3
"""Adversarial fixtures for the E16 dependency pin, without invoking Cargo."""

import copy
import unittest

from check_owner_bridge_lock import CHECKSUM, SOURCE, TARGET, check


class OwnerBridgeLockTests(unittest.TestCase):
    def setUp(self):
        self.lock = {
            "package": [
                {"name": "rustix", "version": "0.38.44"},
                {"name": "rustix", "version": "1.1.5", "source": SOURCE, "checksum": CHECKSUM},
                {"name": "pos-owner-bridge", "dependencies": ["rustix 1.1.5"]},
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
        for dependencies in [["rustix 0.38.44"], ["rustix 1.1.5", "rustix 0.38.44"]]:
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
                    table.setdefault(kind, {})[name] = {"package": "rustix", "version": "1.1.5"}
                    self.assertTrue(check(self.lock, owner, self.workspace), (target, kind, name))

    def test_workspace_features_stay_unchanged(self):
        for field, value in [("version", "1.1.6"), ("default-features", True), ("features", ["fs", "std", "process"])]:
            workspace = copy.deepcopy(self.workspace)
            workspace["workspace"]["dependencies"]["rustix"][field] = value
            self.assertTrue(check(self.lock, self.owner, workspace))


if __name__ == "__main__":
    unittest.main()
