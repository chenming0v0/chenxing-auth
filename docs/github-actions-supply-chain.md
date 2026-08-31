# GitHub Actions supply-chain policy

All third-party `uses:` entries in workflows and composite actions must reference a
full 40-character commit SHA. Keep the audited release or channel in an inline
comment, for example:

```yaml
- uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
```

Repository-local actions referenced with `./...` are exempt. Release tools installed
by `taiki-e/install-action` must also use exact `x.y.z` versions and `fallback: none`
so the action cannot silently switch to a different installation path.

Dependabot checks the `github-actions` ecosystem weekly and targets `dev`. Before
merging an update, review the upstream release notes and verify that the proposed SHA
resolves from the declared release tag or channel, for example:

```bash
gh api repos/actions/checkout/commits/v4.4.0 --jq .sha
```

Keep the version comment synchronized with the SHA. The CI quality job runs
`.github/scripts/verify_action_pins.py`, which scans workflows, reusable workflows,
and repository-wide composite action manifests and rejects mutable references or
floating versions of the protected Rust release tools.
