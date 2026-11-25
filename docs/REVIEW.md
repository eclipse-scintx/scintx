# Review and merge policy

This policy covers pull requests targeting `main` in [Eclipse SCINTX](https://github.com/eclipse-scintx/scintx), including changes from committers, external contributors, and dependency update bots.

## Required reviews

Before merging a pull request:

- Obtain approval of the current changes from at least one SCINTX committer other
  than the author. Obtain code-owner approval for paths with assigned owners.
- Address blocking review feedback and request further review when needed.
- Meet the verified commit signature and Eclipse contributor-agreement
  requirements. Use the commit author email associated with the contributor's
  Eclipse Foundation account, as described in [CONTRIBUTING.md](../CONTRIBUTING.md).
- Confirm that `eclipsefdn/eca`, reported by the Eclipse ECA Validation app, passes.

Reviewers should check the following where applicable:

- The change is in scope, correct, and tested. Involve the affected maintainers
  when changing public contracts or security-sensitive behavior.
- API, schema, adapter, policy, and integration changes preserve agreed contracts
  or describe compatibility and migration implications. Update generated files,
  examples, and documentation for the change.
- Error handling, privacy, and treatment of provider evidence are appropriate.
  Review new or changed dependencies and third-party material under the
  [Eclipse IP due diligence process](https://www.eclipse.org/legal/committer-guidelines/).
- Contributors have appropriate Eclipse agreement coverage. Disclose material
  AI assistance and have a human verify the contribution under the
  [Eclipse Project Handbook](https://www.eclipse.org/projects/handbook/).

## CI and security evidence for reviewers

Reviewers can consult the CI and security workflow results when assessing a change.

| GitHub check | Source | Purpose |
| --- | --- | --- |
| `test` | [ci.yml](../.github/workflows/ci.yml) | Check formatting, license headers, generated files, Go vet, tests, and schema fixtures. Report coverage. |
| `Scan secrets` | [trufflehog.yml](../.github/workflows/trufflehog.yml) | Scan proposed changes for secrets. |
| `GitHub Actions security lint` | [zizmor.yml](../.github/workflows/zizmor.yml) | Lint GitHub Actions workflows for insecure patterns. |

Run `make check` locally as described in [CONTRIBUTING.md](../CONTRIBUTING.md).
CI reports coverage for review. Scorecard and release SBOM workflows retain
their existing triggers. Dependency security and IP review remain part of the
review when relevant.

## References

- [Eclipse Project Handbook](https://www.eclipse.org/projects/handbook/)
- [Eclipse Committer Due Diligence Guidelines](https://www.eclipse.org/legal/committer-guidelines/)
- [Eclipse Security Handbook: Rapid Security Review](https://eclipse-csi.github.io/security-handbook/project/reviews.html)
- [GitHub ruleset rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
- [OpenSSF Scorecard branch protection](https://github.com/ossf/scorecard/blob/main/docs/checks.md#branch-protection)
