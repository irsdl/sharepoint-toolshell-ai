# Coverage Check Results

## Initial Findings (from first pass)
- BinaryFormatter deserialization RCE in Ssdqs stack: unrestricted binder in `snapshots_decompiled/v1/Microsoft.-b23f4965-73cc7a11/Microsoft/Ssdqs/Infra/Utilities/NoneVersionSpecificSerializationBinder.cs` allowed arbitrary types across many DQS entry points; patch adds allow/deny TypeProcessor, blocks System.Type, throws BlockedTypeException, and routes `ChunksExportSession.ByteArrayToObject` through `SerializationUtility.ConvertBytesToObject`.
- PerformancePoint `ExcelDataSet` SafeControl tightened: web.config for ports 80/20072 now marks `Microsoft.PerformancePoint.Scorecards.ExcelDataSet` unsafe, preventing page authors from loading a DataTable-serialization helper control that uses BinaryFormatter.
- Authentication scope tightening: `applicationHost.config` removes `/SharePoint - 80/_forms` virtual directory and `<location>` enabling anonymous auth, aligning with spoofing/auth-bypass advisory.
- Residual/bypass noted: BinaryFormatter still used; TypeProcessor allows all Ssdqs types and arrays/enums/interfaces, so gadget risk persists if new Ssdqs gadget types emerge.

## New Findings (from coverage check)

### New Vulnerabilities
- None newly discovered beyond initial set; additional review did not surface a distinct vulnerability.

### Additional Bypass Routes (for already-found vulnerabilities)
- Vulnerability: Ssdqs BinaryFormatter RCE
  - New bypass considerations: TypeProcessor auto-allows arrays/enums/interfaces and any Microsoft.Ssdqs.* type; an attacker may craft payloads using future or less-reviewed Ssdqs types or array wrappers if not on the explicit denylist. No new code paths identified that bypass the patched binder, but risk persists via allowed-type expansion.
  - Total bypass routes now known: 1 primary class (allowed-type abuse) noted.

## CVE-2025-49701 Candidates
- Strong candidates:
  - SafeControl block for `Microsoft.PerformancePoint.Scorecards.ExcelDataSet` (web.config in `C__inetpub_wwwroot_wss_VirtualDirectories/80/web.config` and `20072/web.config`): prevents instantiation of a BinaryFormatter-based DataTable loader by site authors. RCE-capable and distinct from Ssdqs binder fix.
- Possible candidates:
  - None beyond the above; no other unmapped RCE-capable changes observed.

## Unmapped Security Changes
- None conclusively unmapped; all security-relevant diffs identified map to the three advisory themes (RCE deserialization, SafeControl restriction as RCE-capable vector, authentication scope tightening). MIME type additions and recycling schedule tweaks are non-security.

## Total Coverage
- Files analyzed: 9 (applicationHost.config, two web.configs, NoneVersionSpecificSerializationBinder.cs, TypeProcessor.cs, BlockReason.cs, BlockedTypeException.cs, SerializationUtility.cs references, ChunksExportSession.cs)
- Security-relevant changes identified: 3 clusters (deserialization guard + helper changes, SafeControl restriction, auth scope removal)
- Mapped to vulnerabilities: 3 clusters mapped (CVE-2025-49704, CVE-2025-49701 candidate, CVE-2025-49706)
- Unmapped: 0
- Additional bypass routes discovered: 1 (allowed-type/array interface allowance within TypeProcessor)
- CVE-2025-49701 candidates identified: 1
