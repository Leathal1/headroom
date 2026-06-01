"""
Regression tests for dependency security (Next.js CVE remediation).
These are invoked from CI, not from test runners, so they are not under test_* filenames.
"""
import json
import sys
import os
import re

EXPECTED_NEXT_VERSION = "16.2.5"
DOCS_DIR = os.path.join(os.path.dirname(__file__), "..", "..")


def _get_manifest_path(name: str) -> str:
    return os.path.join(DOCS_DIR, name)


def _load_json(relpath: str) -> dict:
    path = _get_manifest_path(relpath)
    with open(path, "r") as f:
        return json.load(f)


def _get_bun_next_version() -> str:
    """Extract the direct 'next' dependency from bun.lock's workspaces dependencies block.
    The workspace 'dependencies' block appears before 'devDependencies'; scoping to it
    avoids matching peer/transitive entries elsewhere in the lockfile."""
    with open(_get_manifest_path("bun.lock"), "r") as f:
        head = ""
        for line in f:
            head += line
            if '"devDependencies"' in line:
                break
        match = re.search(r'"next":\s*"([^"]+)"', head)
        return match.group(1) if match else ""


def test_nextjs_version_not_vulnerable():
    """Ensure the 'next' package is pinned to a patched version (>= 16.2.5)
    across all manifest files. CVE: GHSA-36qx-fr4f-26g5 / CVE-2026-44573."""
    # package.json
    pkg = _load_json("package.json")
    next_dep = pkg.get("dependencies", {}).get("next", "")
    assert next_dep == EXPECTED_NEXT_VERSION, (
        f"package.json: expected next={EXPECTED_NEXT_VERSION}, got {next_dep}"
    )

    # package-lock.json
    lock = _load_json("package-lock.json")
    lock_next = lock.get("packages", {}).get("node_modules/next", {}).get("version", "")
    assert lock_next == EXPECTED_NEXT_VERSION, (
        f"package-lock.json: expected next={EXPECTED_NEXT_VERSION}, got {lock_next}"
    )

    # bun.lock — scoped to workspace dependencies block only
    bun_next = _get_bun_next_version()
    assert bun_next == EXPECTED_NEXT_VERSION, (
        f"bun.lock: expected next={EXPECTED_NEXT_VERSION}, got {bun_next}"
    )


def main():
    failures = []
    try:
        test_nextjs_version_not_vulnerable()
        print("PASS: test_nextjs_version_not_vulnerable")
    except AssertionError as e:
        failures.append(str(e))
        print(f"FAIL: {e}")

    if failures:
        print(f"\n{len(failures)} test(s) failed.")
        sys.exit(1)
    else:
        print("\nAll tests passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
