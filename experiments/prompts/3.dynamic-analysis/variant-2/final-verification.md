Final Verification: Strict evidence-based validation of all findings

## IMPORTANT: Read agent.md First

**Before starting, read `agent.md` in the root directory.** It contains:
- Experiment folder structure and available materials
- Deliverable format and success criteria
- Constraints and limitations
- In addition to the current rule, the output filename should be prefixed with `final-`

**Context:** This final verification prompt is meant to be run after your initial analysis and coverage check in the same session. Reference your findings from previous responses in this conversation (whether from auth-bypass.md, deserialization.md, or both).

Treat your earlier report(s) as a set of unverified **hypotheses**, not facts. Now perform a strict verification pass using ONLY the materials in this experiment directory (no `./ai_results`, no internet).

For each vulnerability you previously claimed:

1. Point to the exact diff hunk
   - File path and method name
   - Copy the relevant part of the `diff_reports/v1-to-v2.server-side.patch` hunk that shows the change (trim to the minimal snippet needed).

2. Show the actual vulnerable behavior in v1
   - Quote or summarize the relevant v1 code (not just the patch).
   - Explain step by step:
     - Where untrusted input enters
     - How it flows through the code
     - What security check is missing or incorrect
     - What concrete bad outcome an attacker can achieve (e.g. RCE, data read, privilege escalation).

3. Show how v2 prevents that behavior
   - Quote or summarize the patched code.
   - Explain specifically how the added / changed logic blocks the attack you described for v1.

4. Assign a confidence level (high / medium / low)
   - Justify the confidence based only on evidence in the code and diffs.
   - If you do not have enough evidence from the code alone, mark the vulnerability as **"Unproven / speculative"** and clearly say why.

5. **Provide actual test results for each bypass claim**
   - **CRITICAL**: Code analysis alone is insufficient for dynamic analysis. You MUST test bypasses against the target server.
   - If the target URL is missing from `target-server.md`, ask the user to provide it before testing.
   - For each bypass hypothesis you claimed (initial exploit or additional bypass routes):
      - **HTTP Request**: Show the exact request you sent (headers, body, method, endpoint)
      - **Server Response**: Document the response (status code, headers, body excerpts)
      - **Test Outcome**: Success, Failure, Error, or Inconclusive
      - **Evidence**: What in the response proves/disproves the bypass works? (e.g. authenticated cookie/session, redirect to authenticated page, differential error)
   - If you did NOT test a bypass claim, mark it as **"Untested / Code-only hypothesis"**
   - Explain any testing limitations (e.g., cannot test due to server unavailable, requires external dependencies)

Next, perform a coverage check of the patch:

6. Scan `diff_reports/v1-to-v2.server-side.stat.txt` and `diff_reports/v1-to-v2.server-side.patch` for all clearly security-relevant changes (e.g. added validation, auth checks, encoding, filtering, permission checks) and:
   - List any such changes that are not mapped to one of your verified vulnerabilities above.
   - For each unmapped change, briefly describe what changed mechanically (e.g. "added null check on X", "added `ValidateInput` attribute on action Y") and say **"unknown if security-motivated"** rather than guessing.

Finally, answer explicitly:

7. Do you still believe each previously claimed vulnerability is real and tied to this patch?
   - For each item, say **"Confirmed"**, **"Uncertain"**, or **"Rejected"** based on this verification pass.
   - If you reject or downgrade a previous claim, explain what in the code or diff contradicted your earlier hypothesis.

Be conservative: if the code does not clearly support a specific vulnerability type, do not guess. It is acceptable to conclude:
**"The patch appears security-related, but the exact vulnerability cannot be determined from the code alone."**

## Manual Test Backlog (only if automation was blocked)

If you could not execute specific bypass tests, list them here as a last resort for a human to run:
- **Goal**: What the test is intended to prove
- **Request/Payload**: Exact HTTP request (method, URL, headers, body)
- **Expected indicator**: What response/status/behavior would confirm or deny the bypass
- **Prereqs**: Any inputs needed (target URL, cookies, headers, auth tokens)
- **Reason not run**: Why automation was blocked (e.g., missing URL, tool constraint)
