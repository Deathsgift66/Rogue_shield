# RogueShield

**Defensive review toolkit for software maintainers.** This is a small, standalone Python developer preview for *offline* static checks, OpenAPI contract inspection, and synthetic state-integrity testing.

**Current public build: foundation release.** The full v0.1 prototype exists separately; this repository currently implements the three offline commands below. Network scanning, SARIF output, AI planners, exploit validation, and plugin execution are **not** yet implemented in the GitHub version. No security certification is implied.

## Getting started

Requires Python 3.11 or newer. There are no runtime third-party dependencies.

```sh
python -m unittest discover -s tests -v
python -m rogueshield static rogueshield --out static-report.json
python -m rogueshield openapi path/to/openapi.json --out api-report.json
python -m rogueshield invariants examples/demo-invariants.json --out invariant-report.json
```

Each command produces a JSON report. Exit status `0` means no findings at the selected threshold, `2` means findings reached the threshold, and `3` means input or output failure. Use `--fail-on low|medium|high|critical` to adjust the threshold (default `high`). Findings are **review indicators**, not verified security defects.

## Independence from other projects

RogueShield is an independent, general-purpose project. **No proprietary Thronestead code, game configuration, game architecture details, player information, private audits, credentials, unreleased mechanics, or proprietary assets should ever be copied here.** Fixtures in this repository must use imaginary identifiers and invented data.

## Responsible use

The current commands operate on local files only. Any future network testing must require explicit owner authorization and strong safety limits. Do not use this software on services or data you do not have authorization to assess.

## License status

The MIT License was proposed for the earlier prototype, but the maintainer has not yet finalized the terms. **This publicly viewable repository has not yet been granted an open-source license.** Public visibility is not a grant of unrestricted reuse rights. The license and accurate copyright notice should be selected before a formal public release.

See [ROADMAP.md](ROADMAP.md), [CONTRIBUTING.md](CONTRIBUTING.md), and [SECURITY.md](SECURITY.md) for the project direction and policies.
