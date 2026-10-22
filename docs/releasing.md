# Releasing

A checklist for maintainers. The engine and gateway images already
publish from CI on a version tag. The three SDKs have never been
published: the names below were free on PyPI and npm when this was
written (2026-10-22), and no `sdk/go/*` tag exists. Nothing here runs by
itself; the workflow snippets are sketches to adapt, not files in the
repo.

## Tag scheme

| What | Tag | Published as |
| --- | --- | --- |
| Engine + gateway images | `vX.Y.Z` | `ghcr.io/seahop/loomctx:vX.Y.Z`, `ghcr.io/seahop/loomctx-gateway:vX.Y.Z` |
| Python SDK | `sdk/python/vX.Y.Z` | `loomctx-sdk` on PyPI |
| TypeScript SDK | `sdk/typescript/vX.Y.Z` | `loomctx-sdk` on npm |
| Go SDK | `sdk/go/vX.Y.Z` | the module `github.com/seahop/loomctx/sdk/go` |

The Go prefix is not a choice: a module in a subdirectory is versioned by
tags named after that directory. The other two follow it so every SDK tag
reads the same. `ci.yml` triggers on `v*`, which does not match a tag that
starts with `sdk/`, so an SDK tag never re-promotes the images.

`main` is protected (PRs only); tags are not branches and are pushed
directly. A pushed tag is public at once; for the Go module it is
permanent (see below).

## Before any release

1. `main` is green: the five CI jobs on the merge commit.
2. Versions agree. Today every place says `0.2.0`:
   - engine: `pyproject.toml`, `src/loomctx/__init__.py`,
     `src/loomctx/api/http.py` (the FastAPI `version`), and
     `contracts/openapi.json`, which is regenerated from it
     (`python -m loomctx.schemas openapi`, drift-checked in CI);
   - `sdk/python/pyproject.toml`;
   - `sdk/typescript/package.json` and `package-lock.json`: bump both with
     `npm version X.Y.Z --no-git-tag-version` inside the Node image, never
     on the host.
   An SDK may move on its own (a client fix needs no engine release); say
   in the CHANGELOG which engine versions it was tested against.
3. `CHANGELOG.md`: move "Unreleased" under the new version heading.
4. Build locally, in Docker, and look at what would ship:

```bash
# Python: sdist + wheel, metadata check
docker run --rm -v "$PWD/sdk/python:/src:ro" python:3.12-slim sh -c \
  'cp -r /src /b && cd /b && pip install -q build twine && python -m build && twine check dist/*'
# TypeScript: the tarball's file list (prepack builds dist/)
docker run --rm -v "$PWD/sdk/typescript:/src:ro" -v "$PWD/contracts:/contracts:ro" node:22-alpine sh -c \
  'cp -r /src /b && cd /b && npm ci && npm pack --dry-run'
# Go: tidy, vet and the contract + live tests
docker compose up -d --wait loomctx && docker compose --profile sdk run --rm sdk-go
```

Each package carries its own `LICENSE` and `NOTICE`; CI fails if they
differ from the root ones.

## Engine and gateway images

1. Tag the merge commit on `main`: `git tag -a vX.Y.Z -m "vX.Y.Z" <sha>`,
   then `git push origin vX.Y.Z`.
2. CI's `publish-image` job re-tags the image that commit already pushed
   and tested (`:<sha>`) as `:vX.Y.Z` after a Trivy gate. Nothing is
   rebuilt.
3. Create the GitHub release from the CHANGELOG section, and check the
   tag pulls anonymously: `docker pull ghcr.io/seahop/loomctx:vX.Y.Z`.

## Python SDK to PyPI (trusted publishing)

Trusted publishing lets a GitHub Actions job upload with a short-lived
OIDC token: no API token is stored anywhere.

One-time setup:

1. On pypi.org, add a pending publisher for the project `loomctx-sdk`:
   owner `seahop`, repository `loomctx`, workflow file
   `release-sdk-python.yml`, environment `pypi`. (The first upload creates
   the project.) Do the same on test.pypi.org for a dry run.
2. In the repository settings, create the environment `pypi`; require a
   reviewer if publishing should need a second pair of eyes.

The workflow, pinned to commit SHAs like `ci.yml`:

```yaml
# .github/workflows/release-sdk-python.yml (sketch)
name: release-sdk-python
on:
  push:
    tags: ["sdk/python/v*"]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha> # v5
      - name: Tag matches the package version
        run: test "sdk/python/v$(grep -m1 '^version' sdk/python/pyproject.toml | cut -d'"' -f2)" = "$GITHUB_REF_NAME"
      - name: Build in Docker
        run: docker run --rm -v "$PWD/sdk/python:/src" -w /src python:3.12-slim sh -c "pip install build twine && python -m build && twine check dist/*"
      - uses: actions/upload-artifact@<sha> # v4
        with: {name: dist, path: sdk/python/dist/}
  publish:
    needs: build
    runs-on: ubuntu-latest
    environment: pypi
    permissions:
      id-token: write
    steps:
      - uses: actions/download-artifact@<sha> # v4
        with: {name: dist, path: dist/}
      - uses: pypa/gh-action-pypi-publish@<sha> # release/v1
```

Release: bump `sdk/python/pyproject.toml`, merge, then
`git tag -a sdk/python/vX.Y.Z -m "Python SDK vX.Y.Z" <sha> && git push origin sdk/python/vX.Y.Z`.
PyPI never accepts the same version twice, even after a delete: a broken
upload is fixed with a new version.

## TypeScript SDK to npm (with provenance)

`npm publish --provenance` from GitHub Actions attaches a signed
statement of which workflow and commit built the package. It needs a
public repository and `repository.url` in `package.json` matching it
(both true).

One-time setup:

1. An npm account (or organisation) that will own `loomctx-sdk`, with
   two-factor authentication on.
2. Either an npm granular access token limited to this package, stored as
   the secret `NPM_TOKEN` in a repository environment `npm`, or npm's
   trusted publishing for GitHub Actions, which needs no token (check
   npm's documentation for the current setup and the npm CLI version it
   requires).

```yaml
# .github/workflows/release-sdk-typescript.yml (sketch)
name: release-sdk-typescript
on:
  push:
    tags: ["sdk/typescript/v*"]
permissions:
  contents: read
jobs:
  publish:
    runs-on: ubuntu-latest
    environment: npm
    permissions:
      contents: read
      id-token: write
    defaults:
      run:
        working-directory: sdk/typescript
    steps:
      - uses: actions/checkout@<sha> # v5
      - uses: actions/setup-node@<sha> # v4
        with: {node-version: 22, registry-url: "https://registry.npmjs.org"}
      - name: Tag matches the package version
        run: test "sdk/typescript/v$(node -p 'require("./package.json").version')" = "$GITHUB_REF_NAME"
      - run: npm ci
      - run: npm run check-gen
      - run: npm publish --provenance --access public
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

npm runs on the runner here rather than in a container: provenance reads
the job's OIDC token from the runner environment. `prepack` builds
`dist/`; the live client test needs an engine and stays in `ci.yml`.

Release: bump the version (step 2 above), merge, then tag
`sdk/typescript/vX.Y.Z` and push it. A published version can be
deprecated (`npm deprecate`) but not reused.

## Go SDK (a tag)

There is nothing to upload: the Go module proxy fetches a tagged version
from GitHub the first time someone asks for it.

1. `sdk/go/go.mod` names `module github.com/seahop/loomctx/sdk/go`, and
   the `sdk-go` container passes (`go mod tidy -diff`, `go vet`, tests).
2. Tag and push:

```bash
git tag -a sdk/go/vX.Y.Z -m "Go SDK vX.Y.Z" <sha on main>
git push origin sdk/go/vX.Y.Z
```

3. Ask the proxy for it, so the version shows on pkg.go.dev without
   waiting for a user:

```bash
curl -s https://proxy.golang.org/github.com/seahop/loomctx/sdk/go/@v/vX.Y.Z.info
```

4. Users then `go get github.com/seahop/loomctx/sdk/go@vX.Y.Z`.

Once the proxy and the checksum database have seen a version it is fixed
for good: never move or delete a pushed `sdk/go/*` tag. A mistake is fixed
by tagging the next patch version (and, if needed, a `retract` directive
in `go.mod`). Versions stay `v0.x` / `v1.x` under this path; a `v2` would
need the module path to end in `/v2`.

## After a release

- Drop "planned" from the Install sections of the SDK READMEs
  (`sdk/*/README.md`) and from [sdk.md](sdk.md) once a package is live.
- Check each install line from a clean container: `pip install
  loomctx-sdk`, `npm install loomctx-sdk`, `go get …@vX.Y.Z`.
