# Contributing to Eclipse SCINTX

Eclipse SCINTX (Supply Chain Intelligence Exchange) provides a vendor-neutral
standard and reference implementation for integrating package registries and
security providers. We welcome code, tests, documentation, provider integrations,
and design feedback. See the [project page](https://projects.eclipse.org/projects/technology.scintx),
[README](README.md), and [architecture](docs/ARCHITECTURE.md).

Follow the [Eclipse Foundation Code of Conduct](CODE_OF_CONDUCT.md) and the
[Eclipse Foundation Terms of Use](https://www.eclipse.org/legal/termsofuse.php).

## Reporting issues and proposing changes

Search [existing issues](https://github.com/eclipse-scintx/scintx/issues) first.
Use the [issue chooser](https://github.com/eclipse-scintx/scintx/issues/new/choose)
to find the general issue form for bugs, enhancements, and questions, or the
provider adapter request template for a new in-tree provider integration.
Discuss substantial changes in an issue before implementing them. Small fixes
can be submitted directly as pull requests.

Report suspected vulnerabilities privately through the [security policy](.github/SECURITY.md).
Keep credentials, customer data, private artifacts, and non-public security
findings out of public issues, pull requests, logs, and test fixtures.

## Eclipse contribution requirements

SCINTX follows the [Eclipse Foundation Development Process](https://www.eclipse.org/projects/dev_process/)
and distributes project material under the [Eclipse Public License 2.0](LICENSE).
Before contributing code or documentation, create an [Eclipse Foundation account](https://accounts.eclipse.org/)
and sign the [Eclipse Contributor Agreement](https://www.eclipse.org/legal/ECA.php)
unless an applicable Eclipse contributor or committer agreement already covers
you. Set Git to use your real name and the email associated with your Eclipse
Foundation account.

Submit material you have the right to contribute. Follow existing copyright and
SPDX header conventions. Identify third-party code, assets, and dependency
changes in the PR for [Eclipse IP due diligence](https://www.eclipse.org/legal/committer-guidelines/).

Disclose material AI assistance and identify the tool in the PR and commit
message, for example with an `Assisted-by` trailer. For largely AI-generated
files, follow the file disclosure and licensing guidance in the
[Eclipse Project Handbook](https://www.eclipse.org/projects/handbook/).
Review and verify the contribution yourself before requesting review.

## Development setup

Install Git, Go (see [go.mod](go.mod)), GNU Make, Bash, Python 3 with pip, and a
C compiler if you want to run the race detector. Fork the repository and create
a branch from the current `main`:

```sh
git clone https://github.com/YOUR-GITHUB-USERNAME/scintx.git
cd scintx
git switch -c my-change
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r scripts/requirements-schemas.txt
make build
make check
```

Use `make help` for development targets and see the [README](README.md) for
instructions on running the project.
Keep virtual environments, local configuration, and credentials out of commits.

## Submitting a pull request

- Keep the change focused and use short, imperative Conventional Commit subjects.
- Include tests for changed behavior and regression fixes. Update applicable API
  definitions, schema, examples, and documentation for public contract changes.
- Run `make fmt` and `make check`. Run `make generate` and commit the affected
  generated files when applicable.
- Use [verified commit signing](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits)
  (`-S`) for commits targeting `main`.

```sh
git add <changed-files>
git commit -S -m "fix(adapter): handle empty responses"
git push -u origin my-change
```

Open a pull request against `main`. Explain what changed and why, link related
issues, and include test results or other evidence. Use a draft PR for early
feedback. Address review feedback and failed checks before the PR is merged.
