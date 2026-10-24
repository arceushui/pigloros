#!/usr/bin/env python3
"""Keep the piglor-gateway image carrying its third-party notices (#798).

deploy.yml is manual, so its steps cannot run in CI. This policy test pins the
contract instead: the reusable #545 workflow generates the bundle, the image
build needs it, the artifact is downloaded into the build context for both Docker builds,
the image is checked before it is pushed, and the Dockerfile copies the bundle
to the documented path. The ci docker-build job builds the same image without
pushing and runs the same image check.
"""

from __future__ import annotations

import copy
import pathlib
import re
import unittest

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
DEPLOY = ROOT / ".github" / "workflows" / "deploy.yml"
CI = ROOT / ".github" / "workflows" / "ci.yml"
DOCKERFILE = ROOT / "Dockerfile"
REUSABLE = "./.github/workflows/third-party-notices.yml"
DOWNLOAD = (
    "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131"
)
BUILD_PUSH = "docker/build-push-action@"
NOTICES_DIR = "third-party-notices"
IMAGE_DIR = "/usr/share/doc/piglor-gateway/third-party/"
CHECK_SCRIPT = "scripts/check-gateway-image-notices.sh"


def load(path: pathlib.Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def step_index(steps: list[dict], predicate, label: str) -> int:
    matches = [i for i, step in enumerate(steps) if predicate(step)]
    if len(matches) != 1:
        raise AssertionError(f"expected exactly one {label}, found {len(matches)}")
    return matches[0]


def check_download(steps: list[dict], label: str) -> int:
    index = step_index(
        steps, lambda s: s.get("uses", "").startswith("actions/download-artifact@"),
        f"{label} download-artifact step",
    )
    step = steps[index]
    if not step["uses"].startswith(DOWNLOAD + " ") and step["uses"] != DOWNLOAD:
        raise AssertionError(f"{label} must pin the reviewed download-artifact commit")
    if step.get("with") != {"name": "third-party-notices", "path": NOTICES_DIR}:
        raise AssertionError(f"{label} must download the third-party-notices artifact")
    return index


def check_builds(steps: list[dict], label: str, push: bool) -> list[int]:
    builds = [
        i for i, s in enumerate(steps) if s.get("uses", "").startswith(BUILD_PUSH)
    ]
    expected = 2 if push else 1
    if len(builds) != expected:
        raise AssertionError(f"{label} must have {expected} Docker build step(s)")
    for i in builds:
        if steps[i]["with"].get("context") != ".":
            raise AssertionError(f"{label} Docker builds must use the repository context")
    return builds


def check_image_check(steps: list[dict], label: str, image: str) -> int:
    index = step_index(
        steps, lambda s: CHECK_SCRIPT in s.get("run", ""), f"{label} image notice check"
    )
    if steps[index].get("run", "").strip() != f"bash {CHECK_SCRIPT} {image}":
        raise AssertionError(f"{label} must check the image it just built")
    if "continue-on-error" in steps[index]:
        raise AssertionError(f"{label} image notice check must stay blocking")
    return index


def check_deploy(workflow: dict) -> None:
    jobs = workflow["jobs"]
    if set(jobs) != {"third-party-notices", "build-and-push"}:
        raise AssertionError("deploy.yml must have exactly the notices and build jobs")
    notices = jobs["third-party-notices"]
    if notices.get("uses") != REUSABLE or notices.get("permissions") != {"contents": "read"}:
        raise AssertionError("deploy.yml must call the #545 reusable notice workflow")
    if "continue-on-error" in notices or "if" in notices:
        raise AssertionError("the notice job must always run and stay blocking")
    build = jobs["build-and-push"]
    if build.get("needs") != "third-party-notices" or "if" in build:
        raise AssertionError("the image build must need the notice job unconditionally")
    for name, job in jobs.items():
        if "runs-on" in job and job["runs-on"] != "ubuntu-24.04":
            raise AssertionError(f"{name} must run on ubuntu-24.04")
        if "continue-on-error" in job:
            raise AssertionError(f"{name} must stay blocking")
    steps = build["steps"]
    if any("continue-on-error" in step for step in steps):
        raise AssertionError("deploy.yml steps must stay blocking")
    download = check_download(steps, "deploy.yml")
    builds = check_builds(steps, "deploy.yml", push=True)
    check_ok = check_image_check(
        steps, "deploy.yml", "pigloros-gateway:${{ inputs.environment }}"
    )
    smoke = step_index(
        steps, lambda s: s.get("name") == "Smoke test", "smoke test step"
    )
    if not download < builds[0] < check_ok < smoke < builds[1]:
        raise AssertionError(
            "download, build, image check and smoke test must precede the push"
        )
    if steps[builds[1]]["with"].get("push") is not True:
        raise AssertionError("the last build step must be the push")
    if steps[builds[0]]["with"].get("push") is not False:
        raise AssertionError("the first build step must not push")


def check_ci(workflow: dict) -> None:
    job = workflow["jobs"]["docker-build"]
    if "third-party-notices" not in job["needs"]:
        raise AssertionError("docker-build must need the notice job")
    if "(needs.ci_change_scope.outputs.rust == 'true' || github.event_name != 'pull_request')" not in job["if"]:
        raise AssertionError("docker-build must keep the Rust-scope clause")
    if "needs.third-party-notices.result == 'success'" not in job["if"]:
        raise AssertionError("docker-build must require the notice job to succeed")
    steps = job["steps"]
    download = check_download(steps, "docker-build")
    builds = check_builds(steps, "docker-build", push=False)
    if steps[builds[0]]["with"].get("push") is not False:
        raise AssertionError("docker-build must never push")
    check_ok = check_image_check(steps, "docker-build", "pigloros-gateway:ci")
    if not download < builds[0] < check_ok:
        raise AssertionError("docker-build must download, build, then check the image")
    call = workflow["jobs"]["third-party-notices"]
    if call.get("uses") != REUSABLE:
        raise AssertionError("ci must call the same reusable notice workflow")


def check_dockerfile(text: str) -> None:
    copy_pattern = re.compile(
        r"^COPY third-party-notices/THIRD-PARTY-NOTICES\.txt \\\n"
        r"\s+third-party-notices/third-party-notices\.json \\\n"
        r"\s+" + re.escape(IMAGE_DIR) + r"\n"
        r"RUN chmod 0755 /usr/share/doc/piglor-gateway " + re.escape(IMAGE_DIR.rstrip("/")) + r" \\\n"
        r"\s+&& chmod 0644 " + re.escape(IMAGE_DIR) + r"\*$",
        re.MULTILINE,
    )
    runtime = text.split("AS runtime", 1)[-1]
    if not copy_pattern.search(runtime):
        raise AssertionError("the runtime stage must copy both notice files")
    if runtime.index("COPY third-party-notices/") > runtime.index("USER appuser"):
        raise AssertionError("copy the notices before dropping to appuser")


def check_dockerignore(text: str) -> None:
    if f"!{NOTICES_DIR}/" not in text.splitlines():
        raise AssertionError(".dockerignore must allow the notice bundle directory")


class DeployNoticePolicy(unittest.TestCase):
    def test_current_files_satisfy_the_contract(self) -> None:
        check_deploy(load(DEPLOY))
        check_ci(load(CI))
        check_dockerfile(DOCKERFILE.read_text(encoding="utf-8"))
        check_dockerignore((ROOT / ".dockerignore").read_text(encoding="utf-8"))

    def mutated_deploy(self, mutate) -> dict:
        workflow = copy.deepcopy(load(DEPLOY))
        mutate(workflow["jobs"])
        return workflow

    def assert_deploy_rejected(self, mutate, message: str) -> None:
        with self.assertRaisesRegex(AssertionError, message):
            check_deploy(self.mutated_deploy(mutate))

    def test_deploy_rejects_missing_or_bypassed_notice_job(self) -> None:
        self.assert_deploy_rejected(
            lambda j: j.pop("third-party-notices"), "exactly the notices and build"
        )
        self.assert_deploy_rejected(
            lambda j: j["build-and-push"].pop("needs"), "must need the notice job"
        )
        self.assert_deploy_rejected(
            lambda j: j["build-and-push"].update({"if": "always()"}), "must need the notice job"
        )
        self.assert_deploy_rejected(
            lambda j: j["third-party-notices"].update({"continue-on-error": True}),
            "always run and stay blocking",
        )
        self.assert_deploy_rejected(
            lambda j: j["third-party-notices"].update({"uses": "./.github/workflows/ci.yml"}),
            "reusable notice workflow",
        )

    def test_deploy_rejects_floating_runner_and_soft_steps(self) -> None:
        self.assert_deploy_rejected(
            lambda j: j["build-and-push"].update({"runs-on": "ubuntu-latest"}), "ubuntu-24.04"
        )
        self.assert_deploy_rejected(
            lambda j: j["build-and-push"]["steps"][0].update({"continue-on-error": True}),
            "steps must stay blocking",
        )

    def test_deploy_rejects_unpinned_or_misdirected_download(self) -> None:
        def unpin(jobs: dict) -> None:
            for step in jobs["build-and-push"]["steps"]:
                if step.get("uses", "").startswith("actions/download-artifact@"):
                    step["uses"] = "actions/download-artifact@v7"

        self.assert_deploy_rejected(unpin, "reviewed download-artifact commit")

        def rename(jobs: dict) -> None:
            for step in jobs["build-and-push"]["steps"]:
                if step.get("uses", "").startswith("actions/download-artifact@"):
                    step["with"]["name"] = "other"

        self.assert_deploy_rejected(rename, "third-party-notices artifact")

    def test_deploy_rejects_builds_outside_the_repository_context(self) -> None:
        def move_context(index: int):
            def mutate(jobs: dict) -> None:
                builds = [
                    s for s in jobs["build-and-push"]["steps"]
                    if s.get("uses", "").startswith(BUILD_PUSH)
                ]
                builds[index]["with"]["context"] = "elsewhere"

            return mutate

        self.assert_deploy_rejected(move_context(0), "repository context")
        self.assert_deploy_rejected(move_context(1), "repository context")

    def test_dockerignore_must_allow_the_bundle(self) -> None:
        check_dockerignore((ROOT / ".dockerignore").read_text(encoding="utf-8"))
        with self.assertRaisesRegex(AssertionError, "allow the notice bundle"):
            check_dockerignore("**\n!crates/\n")

    def test_deploy_rejects_push_before_checks(self) -> None:
        def drop_check(jobs: dict) -> None:
            steps = jobs["build-and-push"]["steps"]
            steps[:] = [s for s in steps if CHECK_SCRIPT not in s.get("run", "")]

        self.assert_deploy_rejected(drop_check, "image notice check")

        def check_other_image(jobs: dict) -> None:
            for step in jobs["build-and-push"]["steps"]:
                if CHECK_SCRIPT in step.get("run", ""):
                    step["run"] = f"bash {CHECK_SCRIPT} other:image"

        self.assert_deploy_rejected(check_other_image, "image it just built")

        def soften_check(jobs: dict) -> None:
            for step in jobs["build-and-push"]["steps"]:
                if CHECK_SCRIPT in step.get("run", ""):
                    step["continue-on-error"] = True

        self.assert_deploy_rejected(soften_check, "steps must stay blocking")

        def push_first(jobs: dict) -> None:
            steps = jobs["build-and-push"]["steps"]
            steps.insert(0, steps.pop())

        self.assert_deploy_rejected(push_first, "precede the push")

        def swap_push(jobs: dict) -> None:
            builds = [
                s for s in jobs["build-and-push"]["steps"]
                if s.get("uses", "").startswith(BUILD_PUSH)
            ]
            builds[0]["with"]["push"] = True

        self.assert_deploy_rejected(swap_push, "first build step must not push")

    def test_ci_rejects_missing_notice_dependency_or_check(self) -> None:
        workflow = load(CI)
        for mutate, message in (
            (lambda j: j["docker-build"]["needs"].remove("third-party-notices"), "must need"),
            (
                lambda j: j["docker-build"].update({"if": "${{ true }}"}),
                "Rust-scope clause",
            ),
            (
                lambda j: j["docker-build"].update(
                    {"if": j["docker-build"]["if"].replace(
                        "needs.third-party-notices.result == 'success' &&", "")}
                ),
                "require the notice job",
            ),
            (
                lambda j: j["third-party-notices"].update({"uses": "./x.yml"}),
                "same reusable",
            ),
        ):
            broken = copy.deepcopy(workflow)
            mutate(broken["jobs"])
            with self.assertRaisesRegex(AssertionError, message):
                check_ci(broken)

        broken = copy.deepcopy(workflow)
        steps = broken["jobs"]["docker-build"]["steps"]
        steps[:] = [s for s in steps if CHECK_SCRIPT not in s.get("run", "")]
        with self.assertRaisesRegex(AssertionError, "image notice check"):
            check_ci(broken)

        broken = copy.deepcopy(workflow)
        for step in broken["jobs"]["docker-build"]["steps"]:
            if step.get("uses", "").startswith(BUILD_PUSH):
                step["with"]["push"] = True
        with self.assertRaisesRegex(AssertionError, "never push"):
            check_ci(broken)

    def test_dockerfile_rejects_missing_or_misplaced_copy(self) -> None:
        text = DOCKERFILE.read_text(encoding="utf-8")
        with self.assertRaisesRegex(AssertionError, "copy both notice files"):
            check_dockerfile(text.replace("chmod 0644", "chmod 0600"))
        with self.assertRaisesRegex(AssertionError, "copy both notice files"):
            check_dockerfile(text.replace("third-party/\n", "elsewhere/\n"))
        moved = text.replace("USER appuser", "")
        moved = moved.replace("EXPOSE 8080", "USER appuser\nEXPOSE 8080")
        moved = moved.replace(
            "COPY third-party-notices/", "RUN true\nUSER appuser\nCOPY third-party-notices/", 1
        )
        with self.assertRaisesRegex(AssertionError, "before dropping"):
            check_dockerfile(moved)


if __name__ == "__main__":
    unittest.main()
