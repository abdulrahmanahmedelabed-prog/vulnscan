# Publishing checklist (for the owner)

Kashif's free distribution channels beyond GitHub Releases, the container image and Homebrew. Each one needs a
one-time step that only the repository owner can take (an account, a token or a setting); until then the release
workflow skips it and nothing fails. Everything here costs nothing.

## 1. PyPI as `kashif` (Trusted Publishing, no token)

The distribution is called `kashif` (`pyproject.toml`); the import package stays `vulnscan` and both commands,
`kashif` and `vulnscan`, are installed. Do not use the name `vulnscan` on PyPI: it belongs to an unrelated project.

The jobs `pypi-build` and `pypi-publish` in `.github/workflows/release.yml` build the sdist and the wheel, check that
their version matches the release tag and that the wheel runs, and upload them with `pypa/gh-action-pypi-publish`
through Trusted Publishing: PyPI trusts this repository's workflow through OpenID Connect, so no API token exists
anywhere. They run only in a release run (a manual run of `release.yml` with `release_tag`; the workflow also
accepts a pushed `v*` tag, which this project does not use), only after the binaries are published, and only once
the repository variable `PYPI_PUBLISH` is `true`.

1. **Create the pending publisher on PyPI.** Sign in at pypi.org (an account with two-factor authentication),
   open *Your account > Publishing* and add a new **pending publisher** for GitHub Actions:

   | Field | Value |
   |---|---|
   | PyPI project name | `kashif` |
   | Owner | `abdulrahmanahmedelabed-prog` |
   | Repository name | `vulnscan` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

   A pending publisher does **not** reserve the name: the project is created by the first successful upload, and
   until then anyone can register `kashif` on PyPI. Take the next steps before the next release. (`kashif update`
   names `kashif` as something to install only for an install that itself came from a package index; every other
   pip install is told to reinstall from git.)
2. **Create the environment.** In the repository: *Settings > Environments > New environment*, name it `pypi`.
   Recommended: under *Deployment protection rules* tick *Required reviewers* and add yourself, so that every
   upload waits for one click of approval in the run. Leave *Deployment branches and tags* at *No restriction*. Do
   not limit the environment to tags matching `v*`: releases of this project are manual runs of `release.yml`,
   which run on a branch (normally `main`), not on a tag, so a tag-only rule would block every PyPI upload. The
   required reviewer is what keeps an unintended run from uploading.
3. **Opt in.** *Settings > Secrets and variables > Actions > Variables > New repository variable*:
   `PYPI_PUBLISH` = `true`. Deleting the variable (or setting anything else) turns publishing off again.
4. **Release as usual:** *Actions > Build executables (`release.yml`) > Run workflow*, on `main`, with
   `release_tag` set to `vX.Y.Z`. The run shows `pypi-build` and `pypi-publish`; `pypi-publish` waits for your
   approval as the environment's reviewer, and the upload also carries PEP 740 attestations (Sigstore) for both
   files.
5. **Check the result** in a clean virtual environment:

   ```bash
   python3 -m venv /tmp/k && /tmp/k/bin/pip install kashif && /tmp/k/bin/kashif --version && /tmp/k/bin/vulnscan --version
   ```

   Only then switch the install instructions (README, docs, the site, `editors/`) to `pip install kashif`. Until
   that release exists they must keep the `git+https://...` form.

Notes:

- A version can be uploaded to PyPI only once. To get a version that is already released onto PyPI, release the
  next patch version (a new manual run of `release.yml` with `release_tag` set to that version) rather than
  running the workflow again with the old `release_tag`: such a run rebuilds and re-uploads that release's
  binaries too.
- The README is the project description on PyPI; its screenshots and links use repository-relative paths, which PyPI
  does not resolve, so they show as broken images there until those paths are made absolute.
- Users who installed 1.0.1 or older from git have the distribution `vulnscan`. Installing `kashif` over it leaves
  two distributions owning the same files, so they must run `pip uninstall -y vulnscan kashif` first;
  `kashif update` and the UI show that command, and `docs/production.md` (*Upgrading a pip install to 1.0.2*)
  explains it.

## 2. Visual Studio Marketplace (Trusted Publishing, no token)

The job `publish-vscode-extension` publishes `kashif-vscode.vsix` to the Marketplace once the repository variable
`VSCE_TRUSTED_PUBLISHING` is `true`; without it (and without the older `VSCE_PAT` secret) the step is skipped and the
`.vsix` stays attached to the release.

Use Trusted Publishing, not a personal access token. Publishing with a token needs an Azure DevOps *global* PAT
(organization: *All accessible organizations*). Azure DevOps has blocked creating new global PATs since March 2026,
and existing ones stop working at the end of 2026 (Microsoft has moved the date more than once). Trusted Publishing
works like PyPI's: the Marketplace trusts this repository's workflow through OpenID Connect (`vsce publish --oidc`,
vsce 4 or newer; the job uses `@vscode/vsce@4.1.0`), so no token is stored anywhere.

1. Sign in to the Visual Studio Marketplace publisher management page (marketplace.visualstudio.com/manage) with a
   Microsoft account and create the publisher **`kashif`**: its ID must equal `"publisher"` in
   `editors/vscode/package.json`. If that ID is taken, pick another and change `package.json` to match.
2. On that publisher's page, add a **Trusted Publishing** policy for GitHub Actions: owner
   `abdulrahmanahmedelabed-prog`, repository `vulnscan`, workflow `release.yml` (no environment: the job has none).
3. In the repository: *Settings > Secrets and variables > Actions > Variables > New repository variable*:
   `VSCE_TRUSTED_PUBLISHING` = `true`.
4. If a `VSCE_PAT` secret exists from earlier instructions, delete it once a release has been published this way:
   the token step is skipped while the variable is `true`, and the token stops working anyway.

## 3. Open VSX (`OVSX_PAT`): VSCodium, Cursor, Gitpod, Eclipse Theia

1. Create a free Eclipse Foundation account (accounts.eclipse.org).
2. Sign in to open-vsx.org with GitHub, link the Eclipse account in your profile and accept the Open VSX publisher
   agreement there.
3. Create an access token (open-vsx.org, *Settings > Access Tokens*), then create the namespace once:
   `npx ovsx create-namespace kashif -p <token>`. The namespace must equal the publisher in `package.json`.
   Creating a namespace does not make it exclusive: to have extensions shown as verified, claim the namespace
   through the Open VSX namespace-ownership process (an issue on the Open VSX repository).
4. Add the repository secret `OVSX_PAT` with the token. Open VSX tokens do not expire, so delete and replace it if
   it ever leaks. (Open VSX also offers trusted publishing through `ovsx` 1.x; the workflow still uses the token.)

## 4. Optional: code signing for Windows (SignPath Foundation)

`kashif.exe` and `kashif-setup.exe` are not Authenticode-signed today, so Windows SmartScreen may warn on first
launch. The SignPath Foundation signs release binaries of open-source projects for free, with a certificate issued
to the Foundation, from builds made on CI. Requirements include an OSI-approved license (MIT), a public repository,
releases built by GitHub Actions from that repository, and a short application describing the project. After
approval, signing is a step in the `build` job (SignPath's GitHub Action submits the unsigned `.exe` and returns the
signed one) placed before the checksums and provenance are computed; that workflow change is not made yet.
