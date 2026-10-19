# Versioning and deprecating

## Portuguese fork (`amagovpt/udata-pt`)

This fork versions itself as `vX.Y.Z.N`, where `X.Y.Z` is the upstream udata release it is built
on — today **16.0.0** — and `N` is the Portuguese revision, incremented on every promotion to
`main` and reset to `1` at each upstream sync. Upstream only ever publishes three segments, so a
fourth one can never collide with it, and PEP 440 orders the result correctly:
`16.0.0 < 16.0.0.1 < 16.0.1 < 16.1.0`.

### Which upstream version is this fork on, and why `pyproject.toml` cannot answer it

**Do not read the version out of `pyproject.toml` or out of what `uv sync` prints.** Both report
the same frozen literal, and that literal has been wrong for months at a time.

Upstream never writes its version by hand: it declares `dynamic = ["version"]` and lets
setuptools-scm compute it from the git tag. This fork disabled that and hardcoded a literal
instead, which was accurate on the day it was written and stopped tracking anything afterwards.
The result, found in October 2026:

| what | said |
| --- | --- |
| `pyproject.toml` in every tag from `v16.0.0.1` to `v16.0.0.12` | `15.1.0` |
| `uv sync` installing any of them | `udata==15.1.0` |
| the code in those same commits | upstream **16.0.0** |

The number was eight months stale. The code was not.

#### How to establish the base for real

Three independent checks. Run all three at every upstream sync, and write the answer into
`pyproject.toml` so the literal stops lying.

**1. Ancestry — is the upstream release fully contained?**

```bash
git remote add upstream https://github.com/opendatateam/udata.git   # once
git config remote.upstream.tagOpt --no-tags                          # once
git fetch upstream '+refs/tags/*:refs/tags/upstream/*' --no-tags

# 0 commits missing means that release is entirely inside this branch
git rev-list --count refs/tags/upstream/v16.0.0 ^origin/main
git rev-list --count refs/tags/upstream/v16.1.0 ^origin/main   # expect > 0
```

The base is the newest upstream release whose count is `0`.

**2. Content — the files that only exist from that release onwards.**

Ancestry alone can mislead: a badly resolved sync can record upstream commits as ancestors while
dropping what they added. So check the files, too.

```bash
# what the upstream release actually added and removed
git diff --name-status --diff-filter=A refs/tags/upstream/v15.1.0 refs/tags/upstream/v16.0.0 -- udata/
git diff --name-status --diff-filter=D refs/tags/upstream/v15.1.0 refs/tags/upstream/v16.0.0 -- udata/

# then, for the commit you are checking
git cat-file -e "<ref>":"udata/core/api_token/models.py" && echo present
```

For the 16.0.0 base this gave 8 added files and 2 removed, and all twelve Portuguese tags carried
8 of 8 and 0 of 2 — conclusive.

> **Shell trap.** In zsh, `git show $ref:udata/...` silently applies the `:u` parameter modifier
> and mangles the path, so every check answers "absent". Quote it as `"$ref":"udata/..."`.

**3. Migrations — the check with consequences.**

`udata/migrations/2026-01-28-migrate-apikeys-to-api-tokens.py` exists from 16.0.0 and not before.
If a database has run it, the deployment is on 16.0.0 whatever any file claims — and labelling
that code `15.1.0` would invite someone to "go back" to a real 15.1.0 against a migrated
database. Migrations do not revert.

#### Why the Portuguese revision resets at each sync

`N` does not count Portuguese releases; it counts the revisions that sit **on this upstream
base**. Measured in October 2026, of 286 files the fork changes against upstream 16.0.0, **114
are new files of ours and 172 are upstream files we modified** — nearly two thirds. Those 172 do
not travel to a new base for free: each sync reconciles them, some conflict, some stop making
sense because upstream solved the same problem differently.

So what comes out of a sync is not "the 13th Portuguese version continuing", it is the first
Portuguese revision of a new base. Resetting says that; a running counter would claim a history
that did not happen on that base, and leave a reader asking where `.1` through `.12` of it went.
It is also what Debian revisions and RPM `Release` fields have done for decades, for the same
reason: the revision belongs to the combination, not to the packager.

Determine the upstream base by ancestry rather than by reading `pyproject.toml`, which has gone
stale before:

```bash
git remote add upstream https://github.com/opendatateam/udata.git
git config remote.upstream.tagOpt --no-tags
git fetch upstream '+refs/tags/*:refs/tags/upstream/*' --no-tags   # keep their tags namespaced
git merge-base --is-ancestor refs/tags/upstream/v16.0.0 origin/main && echo "base is 16.0.0"
```

Releases are cut from `main`, one per promotion, with the changelog section written by hand during
the promotion flow and `./tag-version.sh <version> --keep-changelog` doing the tag and the GitHub
release. The rest of this document describes the upstream project's own process.

## Versioning process

udata follows [Python PEP 440 on versioning][pep440] to version its published releases.

### Branches management

There is a main branch on the [udata git repository][github], `main` and some temporary feature branches.

The `main` is the stable development branch on which:

- bug fixes should occur (unless the bug is only present on a maintenance branch)
- security upgrades are done (unless only necessary on a maintenance branch)
- the incoming new features (and their bug fixes)
- the refactoring
- the dependencies upgrades
- translations are done
- releases are done

Every version has a git tag `vX.Y.Z`.

Otherwise the version is `X.Y.Z.dev` (1.1.7.dev) so you can easily see when you are not using a stable release.

The contents of each version (expected or real) is tracked trough [issues][], [pull requests][pulls] and sometimes [discussions][].


## Releasing

udata uses a custom release script (`tag-version.sh`) to automate its release process.

To create a release, you need to:
- have administrator permission on the udata repository (to allow direct push)
- have the [GitHub CLI (`gh`)](https://cli.github.com/) installed and authenticated (`gh auth login`)

The steps to make a release are:

1. ensure translations are up to date
2. ensure the CircleCI build is successful on the main branch
3. run `./tag-version.sh X.Y.Z --dry-run` to preview the changelog and actions that will be performed
4. run `./tag-version.sh X.Y.Z` to perform the release. The script will automatically check that you are on the main branch, that your working copy is clean, and that you are up to date with the remote. It will then:
    - retrieve all commits since the last tag
    - sort commits alphabetically
    - detect breaking changes (commits with `!` before `:`) and put them first in bold
    - convert PR references (`#XXXX`) to markdown links
    - update CHANGELOG.md with the new version and date
    - commit the changelog update
    - create a git tag with the version (`vX.Y.Z`)
    - push both the commit and the tag to origin
    - create a GitHub release with the same changelog content
5. check on [github][] that the release has been created
6. wait for [CircleCI][] tagged build to succeed
7. check on [PyPI](https://pypi.org/project/udata/#history) that the new release is present
8. celebrate!

## Feature branches

Sometimes a new feature or an EPIC requires more than one pull request and a lot of testing.
For these cases, it's not desirable to use the `main` branch to test until it's stable because we want to keep the `main` branch as stable as possible.

To handle these cases we are using feature branches, named like `feature/my-feature`. These branches will build on CircleCI and produce a [local version](pep440-local) package.

The local identifier will be the feature branch name so the version number will be `X.Y.Z.devBBB+my-feature` where `BBB` is the build number.

## Deprecation policy

**When it's possible** deprecations are published 2 minor versions before being really dropped.
It's up to the developers and system administrators to read the [changelog](changelog.md) before upgrading
(deprecations and breaking changes are published).

[github]: https://github.com/opendatateam/udata
[issues]: https://github.com/opendatateam/udata/issues
[pulls]: https://github.com/opendatateam/udata/pulls
[discussions]: https://github.com/opendatateam/udata/discussions
[CircleCI]: https://circleci.com/gh/opendatateam/udata
[pep440]: https://www.python.org/dev/peps/pep-0440/
[pep440-local]: https://www.python.org/dev/peps/pep-0440/#local-version-segments
