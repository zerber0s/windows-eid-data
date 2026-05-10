# Windows EID Data

Structured JSON reference for Windows Event IDs — what each event means, when it fires, what fields matter, and how to use it for investigation and threat hunting. Sourced from and consistent with [Microsoft Learn](https://learn.microsoft.com/) documentation, with MITRE ATT&CK mappings on every entry that warrants one.

Maintained as the data source for the [EIDVault](https://apps.apple.com/) iOS app, but published as a standalone reference for anyone who finds it useful.

## Layout

```
.
├── schema.json                         # JSON Schema all dataset files conform to
├── *.json                              # 51 dataset files, one per log/provider
├── enrichments/
│   └── scenario-enrichment.json        # Supplementary tools/techniques/definitions
├── scripts/
│   ├── validate-mitre.mjs              # MITRE ATT&CK validator
│   └── README.md                       # Script usage & how to bump for new ATT&CK versions
└── LICENSE                             # CC-BY-4.0
```

Each dataset file at the root is a single log source — `security.json`, `sysmon.json`, `powershell.json`, `kerberos.json`, etc. — with ~510 EID entries total across all files.

## Schema (per-entry)

The full schema is in [`schema.json`](schema.json). Every entry has at minimum `id`, `log`, `title`, `summary`, `details`, `category`, `tags`, and `source`. Optional fields:

- `mitreAttack[]` — `{techniqueId, techniqueName?, tactics[]}`, validated against the MITRE ATT&CK Enterprise STIX bundle (currently v19).
- `keyFields[]` — important event XML fields with their xpath and a description.
- `notesGuidance` — `investigationPivots[]` (how to use the event in an investigation) and `commonFalsePositives[]`.
- `relatedEventIds[]`, `prerequisites[]`, `detectionRules[]`, `volumeIndicator`, `windowsVersions`, `lastReviewed`.

## Field separation

The dataset enforces a clear split between *factual* and *interpretive* content so consumers can reason over each independently:

- **`details`** — what the event is and when it fires. Factual only, no investigation guidance.
- **`notesGuidance.investigationPivots`** — actionable correlation, hunting, and triage guidance.
- **`keyFields`** — structured documentation of important XML fields.

## Enrichments

The [`enrichments/`](enrichments/) folder contains supplementary records (`tool` / `technique` / `definition`) that ground higher-level reasoning in the EIDVault app. These do **not** conform to `schema.json` — they have their own structure: `{name, type, keywords, summary, relatedEventIds}`.

## Validation

MITRE ATT&CK references in every entry are checked against the official STIX bundle by `scripts/validate-mitre.mjs`. See [scripts/README.md](scripts/README.md) for usage and for instructions on bumping the script when MITRE releases a new ATT&CK version.

**Last validated against:** MITRE ATT&CK Enterprise **v19** (released 2026-04-28).

```sh
node scripts/validate-mitre.mjs    # 0 findings = clean
```

JSON Schema validation can be run with any standard validator pointed at `schema.json`.

## License

Creative Commons Attribution 4.0 International ([CC-BY-4.0](LICENSE)). Event descriptions are paraphrased summaries written for this dataset; source links point to authoritative references on Microsoft Learn.
