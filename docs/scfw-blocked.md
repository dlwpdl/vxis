# SCFW Blocked Packages

Packages blocked by Supply Chain Firewall due to security advisories.

| Package | Blocked Dependency | Advisory | Impact |
|---------|-------------------|----------|--------|
| weasyprint >=63 | weasyprint itself | GHSA-983w-rhvv-gwmv (High) | PDF report generation unavailable, using HTML export |
| sslyze | cryptography 44.0.3 | GHSA-r6ph-v2qm-q3c2 (High) | Deep TLS analysis unavailable, testssl.sh covers most checks |

## Workarounds

- **weasyprint**: HTML reports can be opened in browser and printed to PDF (Ctrl+P)
- **sslyze**: testssl.sh provides equivalent TLS analysis coverage. sslyze adds deeper cipher suite analysis but is not critical.

## Resolution

Monitor advisories for patched versions:
- weasyprint: check https://github.com/Kozea/WeasyPrint/releases
- cryptography: check https://github.com/pyca/cryptography/releases
