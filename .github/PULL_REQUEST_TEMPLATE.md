<!-- Thanks for contributing! See CONTRIBUTING.md for the full schema and rules. -->

## Summary

<!-- One or two sentences on what this PR changes and why. -->

## Type of change

- [ ] New threat(s)
- [ ] New control(s) on an existing threat
- [ ] Wording fix to `name` / `description` / `controls[].description`
- [ ] Rename of a threat or control ID (requires alias — see checklist below)
- [ ] Schema or tooling change
- [ ] Other

## ID-stability checklist

<!-- Threat and control IDs are permanent once released. Consumers store them. -->

- [ ] No existing threat `id` was renamed without preserving the old ID in `aliases`.
- [ ] No existing control `id` was renamed without preserving the old ID in `aliases`.
- [ ] No existing threat or control was deleted (or, if it was: this is a major version bump and is called out below).
- [ ] New IDs follow the conventions in CONTRIBUTING.md (kebab-case threats; `ctrl-{shortname}-{n}` controls).

## Version bump

<!-- See CONTRIBUTING.md → Releasing. -->

- [ ] Patch — wording / typo fixes only.
- [ ] Minor — new threats, new controls, or additive schema changes.
- [ ] Major — deletions, alias removals, or breaking schema changes.

## Notes for reviewers

<!-- Anything non-obvious about severity judgements, MITRE mappings, sources, etc. -->
