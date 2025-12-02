# Coverage Check Results

## Initial Findings (from first pass)
- Auth bypass via ProofTokenSignIn redirect fragments: v1 allowed redirect URIs with `#...`, enabling token exfiltration through client-side hash pivots; v2 rejects fragments (`snapshots_decompiled/v2/Microsoft.-1bae7604-1834fb48/Microsoft/SharePoint/IdentityModel/ProofTokenSignInPage.cs:317-329`).
- Auth bypass via signout-driven ToolPane access: v1 skipped auth cookie enforcement for requests with signout referrers, allowing anonymous `_layouts/ToolPane.aspx`; v2 re-enables access-deny for that pattern (`snapshots_decompiled/v2/Microsoft.-52195226-3676d482/Microsoft/SharePoint/ApplicationRuntime/SPRequestModule.cs:2708-2735` and sibling assembly).

## New Findings (from coverage check)

### New Vulnerabilities
- No fully confirmed new vulns, but multiple security-motivated BCL changes likely address RCE paths (see CVE-2025-49701 candidates).

### Additional Bypass Routes (for already-found vulnerabilities)
- Vulnerability: ProofToken redirect fragment acceptance (CVE-2025-49706)
  - New bypass routes discovered: kill switch `53020` (`RevertRedirectFixinProofTokenSigninPage`) can disable the fragment block; exploit remains if enabled. Other endpoints that rely on the same redirect validator remain unprotected against fragment-based pivots.
  - Total bypass routes now known: 2 (hash-fragment pivot; admin kill-switch revert).
- Vulnerability: Signout/anonymous heuristics in `SPRequestModule` (CVE-2025-49706)
  - New bypass routes discovered: fix is scoped to `ToolPane.aspx`; other `_layouts` pages still get the anonymous carve-out when referrer is signout/start. An attacker can probe other layout pages for similar anonymous surfaces.
  - Total bypass routes now known: 2 (ToolPane pattern; other signout-scoped pages still exempted).

### CVE-2025-49701 Candidates
- Strong candidates:
  - BCL crypto/ASN overhaul: large additions under `mscorlib-*/System/Security/Cryptography` (HMAC*, SHA*Managed, AsnReader/Decoder, PKCS#12 parsing helpers). Likely fixes for malformed ASN/PKCS inputs leading to memory corruption or code execution when SharePoint parses certificates or tokens.
  - `System/IO/Packaging/Package.cs` and `System/IO/Compression/ZLibNative.cs` changes (mscorlib) plus `CompoundFileDeflateTransform` adjustments suggest fixes for package/ZIP parsing that could be leveraged for RCE via crafted files.
- Possible candidates:
  - `System/IO/Path.cs`, `UnmanagedMemoryStream.cs`, and `Binary/ObjectWriter.cs` tweaks could harden path resolution and serialization, mitigating deserialization or buffer issues reachable through SharePoint upload/feature deployment.

## Unmapped Security Changes
- ProofTokenSignInPage: new kill switch constant `RevertRedirectFixinProofTokenSigninPage` (53020) enabling rollback of the fragment rejection—security-relevant because it can reopen the bypass.
- Extensive BCL crypto/ASN parsing and HMAC refactoring (mscorlib) — security-motivated but exact vuln unclear; likely robustness against malicious certificates/tokens.
- Packaging/compression pipeline changes (`System/IO/Packaging/Package.cs`, `ZLibNative.cs`, `CompoundFileDeflateTransform.cs`) — could address crafted ZIP/OPC inputs; vuln type not confirmed.
- Path/serialization safety tweaks (`System/IO/Path.cs`, `UnmanagedMemoryStream.cs`, `Formatters/Binary/ObjectWriter.cs`) — likely hardening against path or serialization abuse; mapping unresolved.

## Total Coverage
- Files analyzed: 6 (ProofTokenSignInPage; SPRequestModule in two assemblies; mscorlib crypto/ASN modules; mscorlib packaging/compression; mscorlib path/serialization stream code).
- Security-relevant changes identified: 8
- Mapped to vulnerabilities: 2
- Unmapped: 6
- Additional bypass routes discovered: 2
- CVE-2025-49701 candidates identified: 3
