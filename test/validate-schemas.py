"""Validate preset reports against local, unmodified standards schemas.

Pass a directory containing sarif.json (OASIS SARIF 2.1.0),
bom-1.5.schema.json, spdx.schema.json and jsf-0.82.schema.json (CycloneDX 1.5).
Requires the developer-only Python packages jsonschema and referencing.
"""

import json
from pathlib import Path
import subprocess
import sys

from jsonschema import Draft7Validator
from referencing import Registry, Resource


workspace = Path(__file__).resolve().parent.parent
directory = Path(sys.argv[1])
files = ("sarif.json", "bom-1.5.schema.json", "spdx.schema.json", "jsf-0.82.schema.json")
schemas = {name: json.loads((directory / name).read_text(encoding="utf-8")) for name in files}
resources = [(schema["$id"], Resource.from_contents(schema)) for schema in schemas.values() if "$id" in schema]
registry = Registry().with_resources(resources)
validators = {
    kind: Draft7Validator(schemas[name], registry=registry, format_checker=Draft7Validator.FORMAT_CHECKER)
    for kind, name in (("sarif", files[0]), ("cyclonedx", files[1]))
}
snapshot = """
import { presets, loadPreset } from './src/presets.js';
import { analyze, simulate } from './src/detectors.js';
import { makeExport } from './src/exports.js';
const samples = presets.map(({ id }) => [id, analyze(loadPreset(id))]);
samples.push(['quarantine', analyze(simulate(loadPreset('lifecycle'),
  new Map([['npm:node_modules/snapshot-codec', { action: 'quarantine' }]])))]);
for (const [label, analysis] of samples) {
  for (const kind of ['sarif', 'cyclonedx']) {
    console.log(JSON.stringify([label, kind, JSON.parse((await makeExport(kind, analysis)).text)]));
  }
}
"""
output = subprocess.check_output(["node", "--input-type=module", "-e", snapshot], cwd=workspace, text=True)
rows = [json.loads(line) for line in output.splitlines()]
assert len(rows) == 10, "Expected four presets and one remediation snapshot in two formats"
for label, kind, data in rows:
    validators[kind].validate(data)
    print(f"{label} {kind}: valid")
