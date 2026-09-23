Threat Model
============

Scope and security promise
--------------------------

Peta is a read-only metadata inspector. It may read installed metadata, fetch
metadata from configured services, inspect archive *names and metadata reported
by an index*, and persist validated HTTP responses in its disposable cache.
Inspection does not install packages, import inspected packages, run
``setup.py`` or build backends, or execute archive members. A package name,
filename, URL, response body, terminal string, cache file, or local Python
interpreter selected by the user is untrusted input.

This is not a sandbox. The process, its Python dependencies, the configured
interpreter, and the operating system remain trusted. Peta also does not
promise that a package is safe to install, that an index is authentic beyond
HTTPS and the HTTP client's certificate checks, or that reported provenance is
verified locally.

Trust boundaries and assets
---------------------------

The following boundaries are crossed by the current sources:

* **Local environment:** ``importlib.metadata`` reads installed distributions;
  the optional ``--python`` target is an explicitly trusted interpreter
  boundary and is queried with a fixed, timed-out inspection command. Its
  output is treated as untrusted JSON and validated before use.
* **Package indexes and APIs:** PyPI, alternate Simple API indexes, OSV,
  Libraries.io, and future providers supply untrusted JSON, URLs, headers,
  counts, names, and error text. Responses are bounded by the HTTP timeout and
  are decoded only after status handling and shape validation.
* **Archives and artifact metadata:** artifact filenames, sizes, hashes,
  provenance URLs, and archive contents are attacker-controlled. Peta reports
  artifact metadata; it does not extract or execute archives.
* **Terminal and machine output:** package metadata, filenames, URLs, and
  provider failures can reach Rich, text, Markdown, JSON, and snapshots.
  Human output must not interpret control sequences, hyperlinks, or markup;
  machine output must remain valid and structurally faithful.
* **Persistent cache:** response bodies, validators, and timestamps are
  untrusted disk data. Cache misses, malformed entries, permission failures,
  and interrupted writes must degrade to a refetch or an offline error.

Protected assets are user credentials, local files and environment details,
process availability, cache integrity, output integrity, and the correctness
of security-relevant claims such as ``read-only`` and provenance.

Security invariants
-------------------

Every provider must preserve these invariants when it is added or changed:

* Only ``https`` may be requested. Redirects are disabled, so a request cannot
  move to another scheme or origin and credentials cannot be forwarded there.
  Requests have a 10-second timeout and responses are streamed with a 64 MiB
  decoded-body limit. Only gzip is advertised, and peta decodes it itself in
  capped steps rather than letting httpx inflate each wire chunk in one call,
  so a compressed bomb is refused by the step that would cross the limit
  instead of after a 64 KiB chunk has expanded to 64 MiB. Any other content
  encoding is refused, as is data after the end of a gzip stream — zlib would
  otherwise hold every trailing byte, however many arrive — and a gzip stream
  cut off before its end marker, which would otherwise pass a truncated body
  on as whole. The limit is sized against real data: ``grpcio``'s JSON
  document is already 9 MiB.
* No request goes to a host chosen by an untrusted response. Every source
  contacts a fixed service except one: the PEP 740 provenance URL, which the
  index response supplies. It is fetched only when its scheme, host, and port
  match the index's own, which is how PyPI serves it; anything else is
  reported as a failed lookup without a request being made. That comparison
  needs no DNS, so rebinding has nothing to race and a proxy is unaffected.
* Peta does not refuse private-network destinations by address. With the
  origin rule above there is no attacker-chosen destination to refuse, and a
  check that resolves a hostname and then lets httpx resolve it again does not
  help either: a zero-TTL name can pass with a public address and connect to
  a private one, and resolving locally breaks users whose proxy does the
  resolving, or whose DNS answers from ``198.18.0.0/15``. **User-supplied
  index URLs (#111) must not ship without this control**, and it must be
  implemented inside an httpx transport so the address checked is the address
  connected to, and skipped when a proxy is in use.
* Archive inspection never extracts members. If extraction is introduced, it
  must reject absolute paths, ``..`` traversal, symlinks, duplicate members,
  excessive member counts, and cumulative or per-member size limits before
  writing anything.
* JSON objects and arrays are limited to 1,000,000 items each and individual
  metadata strings to 8 MiB. The body limit is what bounds realistic entries;
  the item limit exists for the cheap case it cannot see, a long run of tiny
  values that costs far more as Python objects than as JSON bytes. Nesting is
  limited to 100 levels.
* Nesting, item counts, and string lengths are all measured *before* decoding,
  by one scan of the raw text — decoded from bytes exactly as ``json.loads``
  would decode them, and handed to the parser as that same text. Reading the
  declared charset instead let ``charset=utf-16-le`` over a UTF-8 body show
  the scan harmless text and the parser a bracket bomb. Nesting, because
  ``json.loads`` recurses: an over-nested body raises ``RecursionError`` while
  parsing — 120 KB of brackets is enough — and that is a ``RuntimeError``,
  which the ``except ValueError`` around each decode does not catch. Sizes,
  because the validators only visit fields peta consumes, and not every
  consumed string goes through ``expect_string``: an ignored ``"padding"``
  array, or a long string inside a list, would be fully allocated by
  ``json.loads`` and never measured at all. The scan must itself stay linear —
  it exists to stop a denial of service — so its string pattern lets an
  unterminated literal end at the end of input; otherwise every escaped quote
  restarts the match and a run of them costs quadratic time. Dependency
  traversal is capped at 100 levels; invalid or oversized decoded fields are
  rejected, not coerced, and a refusal on size reports the limit it broke
  rather than claiming the value had the wrong type.
* Untrusted strings are rendered as data. Terminal control characters,
  OSC/hyperlink sequences, Rich markup, and shell metacharacters must never
  become active output. Filenames are never passed to a shell. Human output is
  hardened at one boundary rather than per renderer: the plain-text and
  Markdown formatters are sanitized as whole strings, and the Rich formatters
  per rendered segment, inside :func:`peta.cli.output.console.render`.
  Terminal sanitizing alone is not enough for the plain formats, because it
  keeps the newlines and tabs their own separators need and knows nothing of
  Markdown. So each untrusted field is also neutralized where it is inserted:
  in text output its newlines and tabs fold to spaces, so it cannot forge a
  line or a column; in Markdown it is escaped so it cannot open a link, an
  image, raw HTML, or an autolink — a package named ``![x](https://...)``
  would otherwise load a remote image wherever the output is rendered — and
  code spans get a fence longer than any backtick run inside them. The
  target-environment banner, printed outside the formatters, goes through the
  same boundary: it names paths from ``--path`` and from the target
  interpreter's ``sys.path``. Doing it to finished Rich output instead cannot
  work — peta's own styling is escape sequences too, and cannot be told apart
  from an attacker's.
* Credentials are absent from errors, logs, snapshots, cache keys, cache
  payloads, process arguments, and diagnostics. Redaction is applied where a
  diagnostic is *built* — ``EnrichmentError``, ``OutputMessage``,
  ``PublisherFailure``, ``SourceRecord``, and the fatal human path — rather
  than over rendered output or the envelope as a whole. The distinction
  matters in both directions: a URL peta *requested* can carry peta's API key,
  while a URL a package *declared* is metadata the output contract promises to
  report, and the redaction list holds names as ordinary as ``key``, so
  sweeping every string would silently rewrite a package's homepage.
* Every refusal the transport makes — unsafe scheme, oversized body — is
  raised as an ``httpx.RequestError``.
  Each source maps that onto its own error type; an exception outside that
  hierarchy reaches the CLI unhandled and prints a traceback with no message,
  so a new guard joins the contract or it is not a guard.
* Cache entries are scoped, validated, owned by the entries directory, written
  atomically, and treated as disposable. Only validated successful responses
  are stored; corrupt, stale-format, untrusted, or oversized entries are
  misses. Both the entry file and the body stored in it pass the pre-decode
  scan before they are parsed, since the file-size bound limits bytes rather
  than the objects ``json.loads`` builds; the envelope's scan allows a long
  string, because it carries the whole body as one. Replayed entries never
  pass the transport's size limit, so an entry file larger than
  ``cache.MAX_ENTRY_BYTES`` is a miss before it is read — which also covers
  entries written by versions that had no limit — and an entry whose envelope
  or body is nested deeply enough to overflow the parser is a miss rather than
  a crash. A stored body over the response limit is also a miss when replayed,
  so the transport limit holds for cache hits, stale offline answers, and
  ``304`` revalidations alike.
* Local inspection uses metadata APIs or a fixed subprocess query only. It must
  never import the inspected distribution or invoke its build backend.

Regression contract
--------------------

Security tests are severity-oriented and must remain close to the component
they protect. The existing focused suites provide the baseline:

* ``tests/unit/test_cache.py`` covers credential redaction, malformed entries,
  cache ownership, and atomic/disposable writes.
* ``tests/unit/test_http.py`` covers offline behavior, HTTPS-only requests,
  response-size limits, timeout configuration, redirects-disabled transport,
  and shared transport behavior.
* ``tests/unit/test_local.py`` covers validation and timeout behavior for the
  explicit interpreter inspection boundary, and
  ``TestInspectionNeverRunsPackageCode`` installs a distribution whose module
  and ``setup.py`` would both leave evidence, then asserts that reading its
  metadata leaves none.
* ``tests/unit/test_artifacts.py`` and ``tests/unit/test_output_artifacts.py``
  cover hostile artifact metadata without treating it as executable content.
* ``tests/unit/test_output_*.py`` and ``tests/unit/test_output_snapshots.py``
  are the regression point for control characters, hyperlinks, markup, and
  credential-free human and machine output. ``TestHostileMetadata`` in
  ``tests/unit/test_output_tables.py`` additionally pins the two properties a
  hardening pass tends to break: peta keeps emitting its own color, and the
  table stays aligned. Alignment is a security assertion here, not a cosmetic
  one — a sanitizer that shifts a border is one that mismeasured untrusted
  text. ``tests/unit/test_output_render.py`` asserts the same properties once
  per format at the dispatch point, so a format added without hardening fails
  there rather than in somebody's shell. ``tests/unit/test_validation.py``
  covers collection, string, and nesting-depth limits, and that a limit breach
  is reported as one. ``tests/unit/test_redaction.py`` holds both halves of
  the credential rule together, since fixing either one alone tends to break
  the other. ``TestGuardsReachTheUserAsNetworkErrors`` in
  ``tests/unit/test_http.py`` asserts that every transport refusal still
  arrives as the error type the sources handle.

New adversarial fixtures must cover archive traversal/symlink/duplicate and
resource-bomb cases if archive extraction is introduced; deeply nested JSON and
dependency graphs; unsafe schemes, redirects, and origin changes if redirects
are ever enabled; private-network destinations and DNS rebinding, including a
name that resolves differently between the check and the connection, when
user-supplied index URLs arrive; and credentials in every error, log,
snapshot, cache, and diagnostic path.
Each new provider documents its trust boundary, timeout, size, redirect,
origin, and credential policy here before it is enabled.

Operational non-goals
---------------------

Peta does not replace a package installer, malware scanner, signature verifier,
network firewall, or OS sandbox. Users remain responsible for the interpreter
passed with ``--python``, network policy outside Peta, and deciding whether a
reported artifact should be installed.
