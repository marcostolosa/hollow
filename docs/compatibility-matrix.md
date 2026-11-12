# Windows compatibility validation matrix

This project must not infer compatibility with a Windows release from a single
successful run. Capture **OS build and UBR**, architecture, virtualization
configuration, payload and loader SHA-256, Git commit, test mode, process exit
code, and the presence or absence of the expected marker.

Suggested evaluation environments:

| OS family | Architecture | Status |
| --- | --- | --- |
| Windows 10 22H2 | AMD64 | Not verified by this PR |
| Windows 11 23H2 | AMD64 | Not verified by this PR |
| Windows 11 24H2 | AMD64 | Repository has mixed historical evidence |
| Windows 11 25H2 | AMD64 | Not verified by this PR |
| Other builds | AMD64 | Not verified by this PR |

## Read-only preflight

- Use `python3 tools/peinfo.py --json <path-to-exe>` to obtain structured PE metadata.
- Run `python3 -m unittest discover -s tests -v` for offline parser tests.
- `hollow.exe --dry-run --payload <path>` validates payload parsing without
  spawning a target or modifying Defender settings.
- The loader's dry-run is **not** a proof of Windows compatibility and currently
  does not validate the host image size.

## Test reporting

For each controlled VM, capture both the successful and failed command logs.
A loader exit code alone is not proof the payload ran: retain an independently
observed marker and process-exit information. Do not merge logs produced by
different binaries or different guest snapshots.

This PR intentionally does not claim EDR bypass, Defender deactivation, or
cross-version injection reliability. Those require separate, reproducible
tests and independent assessment.
