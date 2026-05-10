# scripts/

Tooling for maintaining this dataset.

## `validate-mitre.mjs`

Checks every `mitreAttack` block in every dataset JSON against the official MITRE ATT&CK STIX bundle for a pinned version. Reports — does not modify — entries whose `techniqueId`, `techniqueName`, `tacticId`, `tacticName`, or `(technique, tactic)` pairing diverges from MITRE.

### Usage

```sh
node scripts/validate-mitre.mjs              # validate every dataset file
node scripts/validate-mitre.mjs --file FN    # validate a single file (basename or path)
node scripts/validate-mitre.mjs --refresh    # force re-download of the STIX bundle
```

Exit code is `0` when clean, `1` when there are findings. The full report is written to `scripts/mitre-v<N>-report.json`; a per-file and per-issue summary goes to stdout. Requires Node 18+ (uses built-in `fetch`); no `npm install` step.

### Issue types

- **`technique-revoked`** / **`technique-deprecated`** — the technique no longer exists. Includes the `revoked-by` target if MITRE provides one (e.g. `T1562.001 → T1685`).
- **`technique-unknown`** — the `techniqueId` doesn't appear in the bundle (often a stray Mobile/ICS ID in an Enterprise dataset).
- **`technique-name-mismatch`** — `techniqueName` doesn't match. The script accepts both the bare STIX form (`DCSync`) and the dataset's `Parent: Sub` form (`OS Credential Dumping: DCSync`).
- **`tactic-unknown`** — `tacticId` isn't in the v19 tactic list.
- **`tactic-name-mismatch`** — `tacticId` is fine but the `tacticName` doesn't match (e.g. `TA0005` was renamed from "Defense Evasion" to "Stealth" in v19).
- **`technique-tactic-mismatch`** — the `(techniqueId, tacticId)` pair is not associated in the current bundle. The `suggestion.validTactics` field lists the tactics MITRE currently associates with that technique.

### Bumping for a new ATT&CK version

1. Update `ATTACK_VERSION` at the top of `validate-mitre.mjs` (e.g. `"19.0"` → `"20.0"`).
2. Run `node scripts/validate-mitre.mjs --refresh` to fetch the new bundle.
3. Work through findings. Mechanical updates (renames, no-op tactic-name changes) can be applied directly. Tactic reassignments and revoked-technique replacements require reading the EID's `details` / `notesGuidance` to pick the most appropriate replacement.
4. For each modified entry, set `lastReviewed` to the review date and bump the file's `version` (MINOR) and `generatedAt`. See the General Rules in the repo root.
5. Re-run until the script reports zero findings.

### Files

- `validate-mitre.mjs` — the validator (committed).
- `.cache/` — local STIX bundle cache (gitignored).
- `mitre-v<N>-report.json` — last run's findings (gitignored).
