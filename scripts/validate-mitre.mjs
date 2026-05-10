#!/usr/bin/env node
// validate-mitre.mjs
//
// Validates every `mitreAttack` entry in this repo's dataset JSON files
// against the official MITRE ATT&CK STIX bundle for a given version.
//
// Usage:
//   node scripts/validate-mitre.mjs              # validate all dataset files
//   node scripts/validate-mitre.mjs --file FN    # validate a single file (basename or path)
//   node scripts/validate-mitre.mjs --refresh    # force re-download of STIX bundle
//
// Output:
//   - scripts/mitre-vNN-report.json   (one record per finding)
//   - stdout summary (counts per file, per issue type)
//
// To bump for a new ATT&CK version, change ATTACK_VERSION below.

import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from "node:fs";
import { dirname, resolve, basename } from "node:path";
import { fileURLToPath } from "node:url";

const ATTACK_VERSION = "19.0";
const STIX_URL = `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-${ATTACK_VERSION}.json`;

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..");
const CACHE_DIR = resolve(__dirname, ".cache");
const CACHE_FILE = resolve(CACHE_DIR, `enterprise-attack-${ATTACK_VERSION}.json`);
const REPORT_FILE = resolve(__dirname, `mitre-v${ATTACK_VERSION.split(".")[0]}-report.json`);

const args = process.argv.slice(2);
const refresh = args.includes("--refresh");
const fileArgIdx = args.indexOf("--file");
const fileArg = fileArgIdx >= 0 ? args[fileArgIdx + 1] : null;

async function loadStix() {
  if (!existsSync(CACHE_DIR)) mkdirSync(CACHE_DIR, { recursive: true });
  if (!refresh && existsSync(CACHE_FILE)) {
    return JSON.parse(readFileSync(CACHE_FILE, "utf8"));
  }
  console.log(`Fetching STIX bundle from ${STIX_URL} ...`);
  const res = await fetch(STIX_URL);
  if (!res.ok) throw new Error(`STIX fetch failed: ${res.status} ${res.statusText}`);
  const text = await res.text();
  writeFileSync(CACHE_FILE, text, "utf8");
  return JSON.parse(text);
}

function buildIndex(bundle) {
  const tacticByShortname = new Map();
  const tacticById = new Map();
  const tacticByName = new Map();
  const techniqueByExtId = new Map();
  const stixIdToExtId = new Map();
  const revokedBy = new Map();

  for (const o of bundle.objects) {
    if (o.type === "x-mitre-tactic") {
      const ext = (o.external_references || []).find((r) => r.source_name === "mitre-attack");
      if (!ext) continue;
      const t = { id: ext.external_id, name: o.name, shortname: o.x_mitre_shortname };
      tacticByShortname.set(o.x_mitre_shortname, t);
      tacticById.set(ext.external_id, t);
      tacticByName.set(o.name, t);
    } else if (o.type === "attack-pattern") {
      const ext = (o.external_references || []).find((r) => r.source_name === "mitre-attack");
      if (!ext) continue;
      const tactics = new Set(
        (o.kill_chain_phases || [])
          .filter((p) => p.kill_chain_name === "mitre-attack")
          .map((p) => p.phase_name)
      );
      const rec = {
        extId: ext.external_id,
        stixId: o.id,
        name: o.name,
        revoked: !!o.revoked,
        deprecated: !!o.x_mitre_deprecated,
        tacticShortnames: tactics,
      };
      techniqueByExtId.set(ext.external_id, rec);
      stixIdToExtId.set(o.id, ext.external_id);
    }
  }

  for (const o of bundle.objects) {
    if (o.type === "relationship" && o.relationship_type === "revoked-by") {
      const fromExt = stixIdToExtId.get(o.source_ref);
      const toExt = stixIdToExtId.get(o.target_ref);
      if (fromExt && toExt) revokedBy.set(fromExt, toExt);
    }
  }

  return { tacticByShortname, tacticById, tacticByName, techniqueByExtId, revokedBy };
}

function listDatasetFiles() {
  const all = readdirSync(REPO_ROOT)
    .filter((f) => f.endsWith(".json") && f !== "schema.json")
    .map((f) => resolve(REPO_ROOT, f));
  if (!fileArg) return all;
  const want = basename(fileArg);
  const match = all.filter((p) => basename(p) === want);
  if (match.length === 0) throw new Error(`No dataset file matched --file ${fileArg}`);
  return match;
}

function validateEntry(entry, file, idx, ctx) {
  const findings = [];
  const ma = entry.mitreAttack;
  if (!Array.isArray(ma)) return findings;

  for (let i = 0; i < ma.length; i++) {
    const m = ma[i];
    const techId = m.techniqueId;
    const techRec = ctx.techniqueByExtId.get(techId);
    const path = `entries[${idx}].mitreAttack[${i}]`;

    if (!techRec) {
      const replacement = ctx.revokedBy.get(techId);
      if (replacement) {
        const repRec = ctx.techniqueByExtId.get(replacement);
        findings.push({
          file: basename(file),
          eid: entry.id,
          title: entry.title,
          path,
          issue: "technique-revoked",
          current: { techniqueId: techId, techniqueName: m.techniqueName },
          suggestion: { techniqueId: replacement, techniqueName: repRec?.name },
        });
      } else {
        findings.push({
          file: basename(file),
          eid: entry.id,
          title: entry.title,
          path,
          issue: "technique-unknown",
          current: { techniqueId: techId, techniqueName: m.techniqueName },
          suggestion: null,
        });
      }
      continue;
    }

    if (techRec.revoked || techRec.deprecated) {
      const replacement = ctx.revokedBy.get(techId);
      const repRec = replacement ? ctx.techniqueByExtId.get(replacement) : null;
      findings.push({
        file: basename(file),
        eid: entry.id,
        title: entry.title,
        path,
        issue: techRec.revoked ? "technique-revoked" : "technique-deprecated",
        current: { techniqueId: techId, techniqueName: m.techniqueName },
        suggestion: replacement
          ? { techniqueId: replacement, techniqueName: repRec?.name }
          : null,
      });
      continue;
    }

    if (m.techniqueName) {
      const acceptableNames = new Set([techRec.name]);
      const dot = techId.indexOf(".");
      if (dot > 0) {
        const parentId = techId.slice(0, dot);
        const parent = ctx.techniqueByExtId.get(parentId);
        if (parent) acceptableNames.add(`${parent.name}: ${techRec.name}`);
      }
      if (!acceptableNames.has(m.techniqueName)) {
        const dotted = techId.indexOf(".") > 0;
        const parent = dotted ? ctx.techniqueByExtId.get(techId.slice(0, techId.indexOf("."))) : null;
        const suggestedName = parent ? `${parent.name}: ${techRec.name}` : techRec.name;
        findings.push({
          file: basename(file),
          eid: entry.id,
          title: entry.title,
          path,
          issue: "technique-name-mismatch",
          current: { techniqueId: techId, techniqueName: m.techniqueName },
          suggestion: { techniqueId: techId, techniqueName: suggestedName },
        });
      }
    }

    const tactics = Array.isArray(m.tactics) ? m.tactics : [];
    for (let j = 0; j < tactics.length; j++) {
      const t = tactics[j];
      const tPath = `${path}.tactics[${j}]`;
      const tacRec = ctx.tacticById.get(t.tacticId);

      if (!tacRec) {
        findings.push({
          file: basename(file),
          eid: entry.id,
          title: entry.title,
          path: tPath,
          issue: "tactic-unknown",
          current: t,
          suggestion: null,
          context: { techniqueId: techId, validTactics: [...techRec.tacticShortnames].map((sn) => {
            const r = ctx.tacticByShortname.get(sn);
            return r ? { tacticId: r.id, tacticName: r.name } : null;
          }).filter(Boolean) },
        });
        continue;
      }

      if (t.tacticName !== tacRec.name) {
        findings.push({
          file: basename(file),
          eid: entry.id,
          title: entry.title,
          path: tPath,
          issue: "tactic-name-mismatch",
          current: t,
          suggestion: { tacticId: tacRec.id, tacticName: tacRec.name },
        });
      }

      if (!techRec.tacticShortnames.has(tacRec.shortname)) {
        const validTactics = [...techRec.tacticShortnames]
          .map((sn) => ctx.tacticByShortname.get(sn))
          .filter(Boolean)
          .map((r) => ({ tacticId: r.id, tacticName: r.name }));
        findings.push({
          file: basename(file),
          eid: entry.id,
          title: entry.title,
          path: tPath,
          issue: "technique-tactic-mismatch",
          current: { techniqueId: techId, ...t },
          suggestion: { validTactics },
        });
      }
    }
  }

  return findings;
}

async function main() {
  const bundle = await loadStix();
  const ctx = buildIndex(bundle);
  console.log(
    `Loaded ATT&CK v${ATTACK_VERSION}: ${ctx.techniqueByExtId.size} techniques, ${ctx.tacticById.size} tactics, ${ctx.revokedBy.size} revoked-by relationships`
  );

  const files = listDatasetFiles();
  const allFindings = [];
  const perFileCounts = {};
  const perIssueCounts = {};

  for (const file of files) {
    const data = JSON.parse(readFileSync(file, "utf8"));
    const entries = data.entries || [];
    const fileFindings = [];
    for (let i = 0; i < entries.length; i++) {
      const f = validateEntry(entries[i], file, i, ctx);
      fileFindings.push(...f);
    }
    perFileCounts[basename(file)] = fileFindings.length;
    for (const f of fileFindings) {
      perIssueCounts[f.issue] = (perIssueCounts[f.issue] || 0) + 1;
    }
    allFindings.push(...fileFindings);
  }

  writeFileSync(REPORT_FILE, JSON.stringify(allFindings, null, 2), "utf8");

  console.log(`\nTotal findings: ${allFindings.length}`);
  console.log(`Report written to: ${REPORT_FILE}`);
  console.log(`\nFindings per issue type:`);
  for (const [k, v] of Object.entries(perIssueCounts).sort((a, b) => b[1] - a[1])) {
    console.log(`  ${k.padEnd(28)} ${v}`);
  }
  console.log(`\nFindings per file (non-zero):`);
  for (const [k, v] of Object.entries(perFileCounts).sort((a, b) => b[1] - a[1])) {
    if (v > 0) console.log(`  ${k.padEnd(32)} ${v}`);
  }

  process.exit(allFindings.length === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(2);
});
