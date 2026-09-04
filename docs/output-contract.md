# Output contract

`--format json` and its compatibility alias `--json` emit a versioned envelope
for every command. Consumers should read `schema_version` before interpreting
the rest of the document.

```json
{
  "schema_version": "1",
  "peta_version": "<installed version>",
  "generated_at": "2026-09-04T12:00:00Z",
  "query": {
    "command": "info",
    "arguments": {"package": "requests"},
    "target_environment": {
      "implementation": "CPython",
      "python_version": "3.14.0",
      "platform": "darwin"
    }
  },
  "status": "success",
  "sources": [],
  "warnings": [],
  "errors": [],
  "result": {}
}
```

## Status and source states

The envelope `status` is one of:

- `success`: the query completed with a result;
- `partial`: the primary result is usable, but optional enrichment failed;
- `empty`: the query succeeded and returned no items; or
- `failed`: the command failed and `result` is `null`.

Each source record has its own `state`: `success`, `empty`, `skipped`,
`unavailable`, or `failed`. This distinguishes a source that returned no data
from one that was disabled, could not be configured, or failed during retrieval.
Successful retrievals include the time captured when the source returned in
`retrieved_at`. The `fields` array links a source to JSON paths in `result`;
records may also include a query `target` or failure `reason`.

Warnings and errors contain stable `code` and `message` fields, plus `source`
when a specific provider is responsible. When two providers answer the same
result field with different values, the first one consulted wins and the
disagreement is reported as a `provider_conflict` warning naming both; every
consulted provider still appears in `sources`, so neither side is lost. Optional enrichment failures produce a
`partial` envelope and exit code 0. Fatal errors produce a `failed` envelope and
retain the documented nonzero CLI exit code. When command-line validation fails
before a command handler runs, `query.arguments.argv` preserves the unparsed
argument vector in the same failed envelope.

Dependency-tree lookups preserve empty or failed transitive resolutions on the
affected node. The envelope is `partial`, its source record identifies the
affected result path, and a `dependency_resolution_failed` warning explains the
failure; the successfully resolved portion of the tree remains available. For
`deps --why`, a failure on a branch that no returned path covers is still
reported, with an empty `fields` array because no result path identifies it.

Source names identify the provider, not the lookup strategy: packages read from
the installed environment are `local` and packages read from PyPI are `pypi`,
matching the names used by `versions` and by network failures. The legacy
`remote` value survives only in `result.source`.

## Compatibility policy

Schema version `1` replaces the original unversioned command-specific JSON.
The previous top-level payload is now under `result`; for example, migrate
`output["name"]` to `output["result"]["name"]`.

Within a schema version, consumers must tolerate new object fields and new
warning/error codes. Existing fields will not be removed or change meaning.
A backward-incompatible shape or semantic change increments `schema_version`.
The installed application version is reported separately as `peta_version` and
does not imply a schema change.
