# Changesets

This folder is managed by [Changesets](https://github.com/changesets/changesets).

After making a change to any package, add a changeset:

```bash
npm run changeset
```

Pick the affected package(s) and the bump type:

- **patch**: bug fix, no API change.
- **minor**: additive (e.g. a new token, a new component, a new export).
- **major**: breaking (e.g. renaming/removing a token, changing a component API).
  Prefer **deprecate → alias → remove-in-next-major** over hard removals.

On push to `main`, the version workflow consumes pending changesets, bumps each
package independently, and commits the result. Publishing happens on a GitHub
Release (or manual dispatch) via `changeset publish`.
