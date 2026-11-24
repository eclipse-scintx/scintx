#!/usr/bin/env python3
"""Validate SCINTX JSON Schema 2020-12 definitions against issue #67-#75 fixtures."""
import json
import sys
from pathlib import Path
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

SCHEMA_DIR = Path("schema")
FAIL = 0
PASS = 0


def load_schema(name):
    with open(SCHEMA_DIR / name) as f:
        return json.load(f)


resources = []
for p in SCHEMA_DIR.glob("*.schema.json"):
    with open(p) as f:
        doc = json.load(f)
    resources.append((doc["$id"], Resource.from_contents(doc)))
registry = Registry().with_resources(resources)


def validate(schema_name, instance, label, should_fail=False):
    global FAIL, PASS
    schema = load_schema(schema_name)
    validator = Draft202012Validator(schema, registry=registry)
    errors = list(validator.iter_errors(instance))
    if should_fail:
        if errors:
            PASS += 1
            print(f"  PASS  {label} (correctly rejected)")
        else:
            FAIL += 1
            print(f"  FAIL  {label} (should have been rejected but wasn't)")
    else:
        if errors:
            FAIL += 1
            for e in errors:
                print(f"  FAIL  {label}: {e.message}")
                print(f"        path: {list(e.absolute_path)}")
        else:
            PASS += 1
            print(f"  PASS  {label}")


print("== SCINTX schema validation ==\n")

validate("artifact.schema.json", {"purl": "pkg:npm/lodash@4.17.21"}, "artifact purl")
validate("artifact.schema.json", {
    "digest": {
        "algorithm": "sha256",
        "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
}, "artifact digest")
validate("artifact.schema.json", {}, "artifact empty (should fail)", should_fail=True)

validate("submission-create.schema.json", {
    "artifact": {"purl": "pkg:npm/lodash@4.17.21"},
    "policy": "baseline-security"
}, "submission-create with policy")

validate("submission.schema.json", {
    "schemaVersion": "1",
    "id": "submission-123",
    "status": "completed",
    "acceptedAt": "2026-11-20T14:00:00Z",
    "completedAt": "2026-11-20T14:00:02Z",
    "artifact": {"purl": "pkg:npm/lodash@4.17.21"},
    "policy": {"id": "baseline-security", "version": "1.0.0"},
    "providerSummary": {
        "selected": 2,
        "completed": 1,
        "failed": 0,
        "timedOut": 0,
        "incomplete": 1
    },
    "evidenceStatus": "partial",
    "policyVerdict": "violated",
    "aggregateReportId": "aggregate-123",
    "policyReportId": "policy-report-001"
}, "submission completed response")

validate("finding.schema.json", {
    "id": "finding-001",
    "type": "vulnerability",
    "severity": "critical",
    "title": "Example vulnerability",
    "artifact": {"purl": "pkg:npm/example@1.2.3"},
    "identifiers": ["CVE-2026-12345"]
}, "finding critical")

validate("aggregate-report.schema.json", {
    "schemaVersion": "1",
    "id": "aggregate-123",
    "submission": {
        "id": "submission-123",
        "acceptedAt": "2026-11-20T14:00:00Z"
    },
    "artifact": {"purl": "pkg:npm/example@1.2.3"},
    "gateway": {
        "instanceId": "gateway-001",
        "version": "1.0.0",
        "configuration": {
            "revision": "abc123",
            "snapshotRef": "config-snapshot-001"
        }
    },
    "policy": {
        "id": "baseline-security",
        "version": "1.0.0",
        "capabilities": ["vulnerabilities"],
        "evaluationDeadlineMs": 30000
    },
    "providers": [
        {
            "slug": "osv",
            "adapterVersion": "1.0.0",
            "available": True,
            "eligible": True,
            "selected": True,
            "matched_capabilities": ["vulnerabilities"],
            "reasons": [],
            "providerRunId": "run-001"
        },
        {
            "slug": "acme",
            "adapterVersion": "1.0.0",
            "available": False,
            "eligible": False,
            "selected": False,
            "matched_capabilities": [],
            "reasons": ["missing_credentials"]
        }
    ],
    "providerRuns": [
        {
            "id": "run-001",
            "provider": "osv",
            "status": "completed",
            "startedAt": "2026-11-20T14:00:01Z",
            "completedAt": "2026-11-20T14:00:02Z",
            "durationMs": 1000,
            "reportId": "report-001"
        },
        {
            "id": "run-002",
            "provider": "ossindex",
            "status": "incomplete",
            "startedAt": "2026-11-20T14:00:01Z",
            "completedAt": None,
            "durationMs": 29900,
            "reportId": None
        }
    ],
    "providerReports": [
        {
            "id": "report-001",
            "providerRunId": "run-001",
            "provider": "osv",
            "capabilities": {
                "vulnerabilities": {
                    "status": "completed",
                    "findings": [
                        {
                            "id": "finding-001",
                            "type": "vulnerability",
                            "severity": "critical",
                            "title": "Example vulnerability",
                            "artifact": {"purl": "pkg:npm/example@1.2.3"},
                            "identifiers": ["CVE-2026-12345"]
                        }
                    ]
                }
            },
            "providerVerdict": None,
            "rawEvidenceRef": "evidence-001"
        }
    ]
}, "aggregate-report issue #68 example")

validate("policy-report.schema.json", {
    "id": "policy-report-001",
    "submissionId": "submission-123",
    "aggregateReportId": "aggregate-123",
    "policy": {"id": "baseline-security", "version": "1.0.0"},
    "artifact": {"purl": "pkg:npm/my-app@1.0.0"},
    "evaluationStatus": "completed",
    "evidenceStatus": "partial",
    "policyVerdict": "violated",
    "violations": [
        {
            "id": "critical-vulnerability",
            "description": "Critical vulnerability detected",
            "matches": [
                {
                    "artifact": {"purl": "pkg:npm/lodash@4.17.21"},
                    "dependencyPath": [
                        "pkg:npm/my-app@1.0.0",
                        "pkg:npm/middleware@2.0.0",
                        "pkg:npm/lodash@4.17.21"
                    ],
                    "evidence": [
                        {
                            "type": "finding",
                            "capability": "vulnerabilities",
                            "provider": "osv",
                            "providerRunId": "run-001",
                            "providerReportId": "report-001",
                            "findingId": "finding-001"
                        }
                    ]
                }
            ]
        },
        {
            "id": "provider-run-incomplete",
            "description": "Provider execution did not complete",
            "matches": [
                {
                    "artifact": {"purl": "pkg:npm/my-app@1.0.0"},
                    "evidence": [
                        {
                            "type": "providerRun",
                            "provider": "ossindex",
                            "providerRunId": "run-002",
                            "status": "timed_out"
                        }
                    ]
                }
            ]
        }
    ],
    "annotations": []
}, "policy-report issue #68 example")

validate("problem-details.schema.json", {
    "type": "https://scintx.example/problems/validation_failed",
    "title": "validation_failed",
    "status": 422,
    "detail": "invalid purl"
}, "problem-details basic")

print(f"\n{PASS} passed, {FAIL} failed")
if FAIL:
    sys.exit(1)
print("All schema validations complete")
