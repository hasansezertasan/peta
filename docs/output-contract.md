# Output contract

`--format json` and its compatibility alias `--json` emit a versioned envelope
for every command. Consumers should read `schema_version` before interpreting
the rest of the document.

```json
{
  "schema_version": "2",
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
- `partial`: the primary result is usable, but optional enrichment failed or a
  dependency tree is incomplete because of a conflict, depth limit, or
  transitive resolution failure;
- `empty`: the query succeeded and returned no items; or
- `failed`: the command failed and `result` is `null`.

Each source record has its own `state`: `success`, `empty`, `skipped`,
`unavailable`, `unsupported`, or `failed`. This distinguishes a source that
returned no data from one that was disabled, could not be configured, does not
support the query, or failed during retrieval.
Successful retrievals include the time captured when the source returned in
`retrieved_at`. The `fields` array links a source to JSON paths in `result`;
records may also include a query `target` or failure `reason`.

A record that completed a retrieval also carries `freshness`, saying where the
data came from: `live` means the source answered, `cached` means peta served a
stored response without contacting the source, and `revalidated` means the
source confirmed a stored response was still current without resending it. The
field is absent when the question does not apply — a package read from the
installed environment, or a source that never completed a lookup. Freshness
describes provenance, not quality: a `cached` record is a real answer, and
`--refresh` forces a `live` one.

Warnings and errors contain stable `code` and `message` fields, plus `source`
when a specific provider is responsible. When two providers answer the same
result field with different values, the first one consulted wins and the
disagreement is reported as a `provider_conflict` warning naming both; every
consulted provider still appears in `sources`, so neither side is lost. Under `--offline` peta contacts no source. A fatal lookup that the cache cannot
answer produces a `failed` envelope with an `offline_unavailable` error and exit
code 2, naming the URL it could not answer; this is deliberately distinct from
`network_error`, because nothing went wrong and the fix is to warm the cache or
drop `--offline` rather than to check connectivity. An *optional* source that
the cache cannot answer stays non-fatal, and an entry past its TTL is still
served offline rather than withheld — reported as `cached`, so the staleness is
visible. Optional enrichment failures produce a
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

`artifacts` represents a release's files as structured data under
`result.files`, each with its digest, size, upload time, wheel tags, and a
`provenance` object. `compatible` is nullable: `null` means peta could not read
the evidence, which is a different answer from `false`. `provenance.available`
reports whether the index exposes a PEP 740 document, and
`provenance.publishers` carries the Trusted Publisher identities PyPI supplied
— both are reports of published evidence, never verification results, and their
absence is not a failure. It is an array because PEP 740 permits one
attestation bundle per publisher, and each entry names its `kind` plus a `claims` object carrying that kind's own fields
verbatim, since each publisher kind describes itself differently. `summary.total_size` sums the sizes the
index reported, so `summary.unsized_files` says how many files contributed
none — any value above zero makes the total a lower bound. With
`--provenance`, `pypi-provenance` source records name the exact
`result.files[i].provenance.publishers` paths the lookup reached; completed
lookups and failed ones are separate records, because one `state` cannot
describe both and a consumer must be able to tell a path PyPI supplied nothing
for from a path peta could not reach. A reached path is listed whether or not
PyPI supplied a publisher for it, and survives a sibling file's failure. Where
the per-file retrievals mix live and cached answers, the record reports the
stalest of them, so it never describes any part of the evidence as fresher
than it is. A release whose files expose no provenance at all is recorded as
`skipped` with no `retrieved_at`, since nothing was requested. A failure also warns and makes the
envelope `partial` rather than discarding the artifact listing.

Source names identify the provider, not the lookup strategy: packages read from
the installed environment are `local` and packages read from PyPI are `pypi`,
matching the names used by `versions` and by network failures. The legacy
`remote` value survives only in `result.source`.

## Compatibility policy

Schema version `1` replaces the original unversioned command-specific JSON.
The previous top-level payload is now under `result`; for example, migrate
`output["name"]` to `output["result"]["name"]`.

Schema version `2` updates dependency nodes for declared-metadata resolution.
Consumers should migrate `installed_version` to `selected_version` and replace
the `circular` boolean check with the `state` field, whose `"circular"` value
represents the former `true` case and whose other values describe additional
resolution outcomes.

Within a schema version, consumers must tolerate new object fields and new
warning/error codes. Existing fields will not be removed or change meaning.
A backward-incompatible shape or semantic change increments `schema_version`.
The installed application version is reported separately as `peta_version` and
does not imply a schema change.
