# Security Policy

InterMed is a static analyzer. It reads jars, archives, and logs you point it at;
it never executes mod code, downloads anything, or modifies the target. That
design keeps the attack surface small, but it does not make it zero — InterMed
parses untrusted, often malformed binary input (class files, zip archives, JSON),
and a parser is exactly the kind of code that can be made to misbehave by a
crafted file.

This policy covers what to report, how, and what to expect back. It is written
honestly: this is a `0.1.2-alpha` project with a small maintainer base, so the
guarantees below are best-effort, not an SLA.

## Supported versions

Only the latest `main` and the most recent tagged release receive security
fixes. Pre-`0.1.0` alphas are not patched in place; fixes land in a new release.

## What counts as a vulnerability

In scope:

- A crafted input file (jar, `.mrpack`/`.zip`, class file, mapping, log) that
  causes InterMed to crash, hang, exhaust memory, or read/write outside the
  files it was given.
- Path traversal or zip-slip while reading an archive (writing or reading outside
  the intended extraction scope).
- Any path by which analyzing an untrusted pack leads to code execution.

Out of scope (not vulnerabilities, by design):

- A *finding* being wrong — a false positive or false negative. InterMed reasons
  from evidence and states its limits; analysis accuracy is a correctness issue,
  reported as a normal bug, not a security report.
- High memory or time on a genuinely large pack. The
  [caching reference](docs/reference/caching.md) and `--jobs` cover scale; an
  unbounded blow-up on a *small* crafted input, however, is in scope.
- Vulnerabilities in a *scanned mod*. InterMed reports a mod's dangerous-API
  surface as preflight context (see [security guide](docs/guides/security.md));
  it does not claim a scanned jar is safe, and a malicious scanned mod is not an
  InterMed vulnerability.

## Reporting

Please report privately, not in a public issue:

1. **Preferred:** GitHub's private vulnerability reporting — the *Security* tab →
   *Report a vulnerability*. This keeps the report and discussion private until a
   fix ships.
2. **Fallback:** email the maintainer at `angelinarnewton03@proton.me` with
   `[intermed security]` in the subject.

A useful report includes the InterMed version (`intermed --version`), the
platform, a minimal input file that triggers it (or instructions to build one),
and the observed vs. expected behavior. A crafted-input report is most actionable
with the file attached.

## What to expect

- An acknowledgement within about a week. (Best-effort — one maintainer.)
- An honest assessment of whether it is in scope and how severe it is.
- A fix in a new release, with credit in the release notes unless you ask
  otherwise. Given the project's stage, there is no embargo process beyond
  "private until the fix is out."

## Dependencies

The dependency tree is audited against the RustSec advisory database in CI
(`cargo audit`); see [`.cargo/audit.toml`](.cargo/audit.toml) for the small set
of accepted unmaintained-only advisories. A new advisory against a dependency is
treated as a normal build failure to fix, not a security report against InterMed.
