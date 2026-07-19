# Contributing

Thanks for considering a contribution!

## Development setup

Requirements: Go ≥ 1.25, `make`, Docker (optional), [`uv`](https://docs.astral.sh/uv/)
or `pip` for docs preview.

```shell
make tools   # installs golangci-lint and goreleaser
make build
make test
make lint
```

## Commit messages — Conventional Commits (required)

Releases are cut automatically by [semantic-release](https://semantic-release.gitbook.io/)
from commit messages, so every commit on `main` **must** follow
[Conventional Commits](https://www.conventionalcommits.org/). CI enforces this
with commitlint.

| Commit prefix | Release effect |
| --- | --- |
| `fix:` | patch release |
| `feat:` | minor release |
| `feat!:`, `fix!:` or `BREAKING CHANGE:` footer | major release |
| `docs:`, `chore:`, `ci:`, `refactor:`, `test:`, `build:`, `perf:` | no release (perf → patch) |

Examples:

```
feat(tls): mint leaf certificates from Vault PKI per SNI
fix(echo): preserve duplicate query parameters
docs: document h2c usage with curl
```

## Pull requests

- Branch from `main`, open the PR against `main`.
- CI must pass: lint, tests (race detector), build, commitlint.
- Add or update documentation in `docs/` for user-visible changes.
- Keep the spec ([docs/specification.md](docs/specification.md)) in sync with
  behaviour changes.

## Docs

Docs are built with [zensical](https://zensical.org/) from `docs/` and
`zensical.toml`, and deployed to GitHub Pages automatically on push to `main`:

```shell
make docs-serve   # http://localhost:8000
```

## Release flow (automated — do not tag manually)

1. PR merged into `main` with conventional commits.
2. `release.yml` runs semantic-release → computes the next version, creates the
   git tag and the GitHub release with generated notes.
3. GoReleaser builds multi-platform binaries and multi-arch Docker images
   (GHCR), attaching them to that release.
