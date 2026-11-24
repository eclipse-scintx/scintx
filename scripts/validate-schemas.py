#!/usr/bin/env python3
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# SPDX-License-Identifier: EPL-2.0

"""Validate Eclipse SCINTX JSON Schemas against representative payloads."""

from __future__ import annotations

import json
import pathlib
import sys

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

SCHEMA_DIR = pathlib.Path(__file__).resolve().parent.parent / "schema"


def load_registry() -> tuple[Registry, dict[str, dict]]:
    resources = []
    schemas: dict[str, dict] = {}
    for p in sorted(SCHEMA_DIR.glob("*.schema.json")):
        data = json.loads(p.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(data)
        schemas[p.name] = data
        res = Resource.from_contents(data)
        resources.append((data["$id"], res))
        resources.append((f"https://scintx.example/schema/{p.name}", res))
    return Registry().with_resources(resources), schemas


FIXTURES = [
    (
        "artifact.schema.json",
        "artifact purl",
        {"purl": "pkg:npm/lodash@4.17.20"},
        True,
    ),
    (
        "artifact.schema.json",
        "artifact digest",
        {"digest": "sha256:" + "a" * 64},
        True,
    ),
    (
        "artifact.schema.json",
        "artifact empty (should fail)",
        {},
        False,
    ),
    (
        "artifact.schema.json",
        "artifact multiple types (should fail)",
        {"purl": "pkg:npm/lodash@4.17.20", "digest": "sha256:" + "a" * 64},
        False,
    ),
    (
        "submission-create.schema.json",
        "submission-create request",
        {"artifact": {"purl": "pkg:npm/lodash@4.17.20"}},
        True,
    ),
    (
        "submission.schema.json",
        "submission completed response",
        {
            "schemaVersion": "1",
            "id": "submission-" + "a" * 32,
            "status": "completed",
            "acceptedAt": "2026-04-20T21:14:03Z",
            "completedAt": "2026-04-20T21:14:05Z",
            "artifact": {"purl": "pkg:npm/lodash@4.17.20"},
        },
        True,
    ),
    (
        # A submission that was interrupted by one graceful shutdown and then
        # retried. "interruptions" must be accepted by the schema.
        "submission.schema.json",
        "submission running after a shutdown interruption",
        {
            "schemaVersion": "1",
            "id": "submission-" + "b" * 32,
            "status": "running",
            "attempts": 2,
            "interruptions": 1,
            "acceptedAt": "2026-04-20T21:14:03Z",
            "artifact": {"purl": "pkg:npm/lodash@4.17.20"},
        },
        True,
    ),
    (
        "submission.schema.json",
        "submission invalid id format (should fail)",
        {
            "schemaVersion": "1",
            "id": "submission-short",
            "status": "completed",
            "acceptedAt": "2026-04-20T21:14:03Z",
            "artifact": {"purl": "pkg:npm/lodash@4.17.20"},
        },
        False,
    ),
    (
        "problem-details.schema.json",
        "problem-details basic",
        {
            "type": "https://scintx.example/problems/validation_failed",
            "title": "validation_failed",
            "status": 422,
            "detail": "invalid purl",
        },
        True,
    ),
]


def main() -> int:
    print("== Eclipse SCINTX schema validation ==\n")
    registry, schemas = load_registry()
    passed = 0
    failed = 0

    for schema_name, label, instance, should_pass in FIXTURES:
        validator = Draft202012Validator(schemas[schema_name], registry=registry)
        errors = list(validator.iter_errors(instance))
        ok = (len(errors) == 0) if should_pass else (len(errors) > 0)
        if ok:
            passed += 1
            suffix = " (correctly rejected)" if not should_pass else ""
            print(f"  PASS  {label}{suffix}")
        else:
            failed += 1
            print(f"  FAIL  {label}: {[e.message for e in errors]}")

    print(f"\n{passed} passed, {failed} failed")
    if failed:
        return 1
    print("All schema validations complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
