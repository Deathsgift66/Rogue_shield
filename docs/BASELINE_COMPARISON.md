# Deterministic Baseline Comparison (v0.5)

RogueShield v0.5 can compare two **offline JSON reports** to gate newly
introduced or worsening review indicators without pretending existing
indicators have been fixed.

## Example

```bash
# On an authorized, local source tree:
python -m rogueshield review ./your-project --format json --out baseline.json

# Later, after changes (write to a different file; no overwrites):
python -m rogueshield review ./your-project --format json --out current.json

python -m rogueshield compare current.json baseline.json --fail-on high
python -m rogueshield compare current.json baseline.json --format json --out diff.json
```

Comparison returns `0` if no **new or worsened** findings meet the
`--fail-on` threshold, `2` if they do, or `3` on invalid input or
unwritable output. Existing baseline findings do not cause a new failure.
The `compare` command accepts `--format text|json`, not HTML/SARIF.

Each normalized finding has a SHA-256 fingerprint of the rule ID, location
and message, with a versioned namespace. Severity is excluded: increasing
severity is a **worsened** finding, not an unrelated new finding.
SARIF includes the same fingerprint under `partialFingerprints`.

The diff tracks `new`, `resolved`, `worsened`, `improved`, and
`unchanged` indicators. Identical duplicate findings are compared as
multisets; an extra duplicate is new. v0.3/v0.4 JSON reports lacking
fingerprints are accepted if their finding fields are otherwise valid.
A present but incorrect fingerprint is rejected.

## Important limits

- Baseline comparison is **not** a security certification. A baseline can
  contain real unresolved issues; a passing comparison does not clear them.
- Fingerprints are stable for unchanged normalized findings, not across
  renamed files, moved lines, changed messages or revised rule text.
- The tool validates report identity, schema version, severity and finding
  fingerprints. JSON duplicate keys and nonstandard numeric constants are
  rejected.
- Each report is currently limited to 1 MB of local JSON; outputs are private
  and never overwrite an existing file.
- Reports can expose source-relative paths and API route names. Treat them as
  potentially sensitive, review them before publishing, and keep baseline
  files private unless intentionally approved for a public repository.
