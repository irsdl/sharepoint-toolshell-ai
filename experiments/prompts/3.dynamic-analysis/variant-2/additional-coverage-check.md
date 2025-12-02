# Bypass Completeness Check: Comprehensive Exploit Route Enumeration

## IMPORTANT: Read agent.md First

**Before starting, read `agent.md` in the root directory.** It contains:
- Experiment folder structure and available materials
- Deliverable format and success criteria
- Constraints and limitations
- In addition to the current rule, the output filename should be prefixed with `coverage-`

**Context:** This prompt is meant to be run after your initial exploit analysis in the same session. Reference your previous findings from your earlier response in this conversation.
- **Target server:** If `target-server.md` is missing a URL, ask the user to provide the patched target URL before testing any bypass routes.

## This Prompt is OPTIONAL

**When to use this prompt:**
- You need exhaustive bypass enumeration for the specific vulnerability you already analyzed
- You want to ensure no alternative attack paths were missed (including historical patterns)
- Research completeness is more important than speed

**When to SKIP this prompt:**
- Speed is the priority and you've already identified key bypass routes in your initial analysis
- You have high confidence the patch is complete based on your initial testing
- You found clear bypasses in your initial analysis and don't need exhaustive enumeration

**If unsure:** Skip this prompt to save time. The initial analysis (auth-bypass.md or deserialization.md) is comprehensive enough for most use cases.

## Objective

You've reverse-engineered a working exploit, analyzed patches, and leveraged historical research. Perform a systematic second-pass to determine if there are **any bypass routes that still work despite the patch**—routes that achieve the same exploit outcome via different attack paths, potentially informed by historical patterns.

**CRITICAL Constraints:**
- ✅ **Dynamic testing ONLY** - Test bypasses against the target server
- ✅ **Same vulnerability ONLY** - Find alternative ways to exploit the SAME vuln you already analyzed
- ✅ **Historical patterns as test targets** - Use historical research to identify what to test
- ❌ **NO new vulnerability types** - Do not discover or test other vulnerabilities
- ❌ **NO broad code review** - Only examine code directly related to bypass testing
- ❌ **NO static analysis deep-dives** - Stay focused on dynamic bypass enumeration

## Step-by-Step Bypass Completeness Analysis

### 1. Review Your Initial Exploit Analysis

From your previous analysis, summarize:
- What vulnerability the exploit targets
- How the original exploit works (attack mechanism)
- What specific changes were made in the patch
- Your initial assessment of the patch's effectiveness
- Patterns from historical research you identified

List any bypass hypotheses you identified.

For each bypass hypothesis, note your initial confidence level (High/Medium/Low)

### 2. Alternative Attack Paths Analysis (Research-Informed Dynamic Testing)

**Question**: Are there other ways to achieve the same malicious outcome using the same vulnerability class, informed by historical patterns?

**TEST each variation against the target server. Use historical research to identify what to test, not to skip testing.**

**If analyzing authentication bypass exploit:**
- Test alternative HTTP headers from historical bypass patterns
- Test different authentication endpoints or methods
- Test edge cases in the authentication logic (null values, empty strings, special characters)
- Test race conditions or timing-based bypasses seen in prior exploits
- Test methods that skip authentication entirely
- Test backup or fallback authentication mechanisms
- Apply historical SharePoint auth bypass techniques via testing

**If analyzing deserialization exploit:**
- Test other dangerous types still registered in configuration (from historical research)
- Test alternative configuration entry points
- Test related DataSet-derived types or similar classes found in historical research
- Test types that could achieve the same RCE capability through different mechanisms
- Test if any applied allow/block list can be bypassed
- Apply historical deserialization exploit patterns via testing

**For each test:**
- Document HTTP request sent
- Document server response
- Record test outcome (Success/Failure/Error)
- Note which historical pattern you're testing

### 3. Patch Coverage Validation (Research-Informed Testing)

**Question**: Did the patch fix ALL attack paths that could enable this exploit, or does it repeat historical mistakes?

**Minimal code review** - Only check diff and historical research to identify test targets:
- Identify what the patch changed in `diff_reports/v1-to-v2.server-side.patch`
- Compare to historical SharePoint patches - note similar incompleteness patterns
- Identify code paths the patch did NOT change
- **Then TEST each identified path** - do not just analyze code

**Focus on testing, not code analysis:**
- Test if patch applies to all entry points
- Test if similar endpoints weren't patched
- Test known patch bypass patterns from prior research
- Test configuration files or deployment scenarios not covered

### 4. Patch Robustness Testing (Research-Informed)

**Question**: Can the patch be bypassed through edge cases or special inputs known from historical exploits?

**Approach**: Test the patch's robustness by identifying and testing edge cases, boundary conditions, and encoding variations that might bypass the validation or fix.

**Your task**:
1. Analyze the patch to understand what validation/checks it implements
2. Apply historical bypass patterns from prior research that target similar patches
3. Identify edge cases and special inputs that might bypass the validation
4. Test each edge case systematically against the target server
5. Document test results for each attempted bypass

**Do NOT just theorize** - test actual edge cases and variations against the server.

### 4a. Technology-Related Quirks Testing

**Question**: Can the vulnerability be exploited through quirks and edge cases specific to the underlying technology stack?

**Approach**: Test technology-specific behaviors, parsing quirks, and implementation details that might bypass the patch even when standard attack vectors are blocked.

**CRITICAL**: Technology quirks are often overlooked but frequently lead to bypasses. Historical research shows many patches fail due to incomplete understanding of underlying technology behaviors.

### 5. Related Entry Points Testing (Historical Context)

**Question**: Are there other entry points that could achieve the same exploit outcome, based on historical vulnerability patterns?

**Minimal code review** - Only identify alternative entry points:
- Identify other endpoints/APIs with similar functionality (from historical research)
- Note alternative interfaces to the same vulnerable component
- Note similar vulnerability patterns in related SharePoint components from history
- **Then TEST each identified entry point** - do not just analyze code

**Focus on testing alternative paths:**
- Test if alternative endpoints exhibit the same vulnerability
- Test wrapper methods or utility functions
- Test backup or fallback mechanisms
- Test similar components that appeared vulnerable historically

### 5a. Historical Research Completeness Verification (MANDATORY)

**CRITICAL**: Before proceeding, verify that ALL bypass techniques from historical research were extracted and tested.

**Review your initial analysis and answer these questions:**

1. **Did you process ALL research files?**
   - **First, verify summary.md coverage** (MANDATORY): Re-read `additional_resources/previous_sp_related_writeups/summary.md` and `additional_resources/previous_exploits_github_projects/summary.md` to confirm all techniques from the summaries were extracted and tested in your initial analysis
     - Cross-check your initial analysis against both summaries
     - Identify any techniques from summaries that weren't tested
   - List ALL files in `additional_resources/previous_sp_related_writeups/` and `additional_resources/previous_exploits_github_projects/`
   - For EACH file, confirm: Was it fully read line-by-line? Or skipped/skimmed?
   - **If any file was skipped or only skimmed** → Go back and read it completely, extract ALL techniques, test them

2. **Did you extract ALL bypass techniques from each file?**
   - For EACH research file you read, list: "Extracted [N] techniques from [filename]"
   - **If N=0 for any file** → Re-read that file exhaustively and extract ALL techniques mentioned

3. **Did you test ALL extracted techniques?**
   - Create master checklist: `[ ] Technique: [description] - Source: [file:line] - Result: [outcome]`
   - **If any technique marked "not applicable" or "skipped"** → TEST IT NOW
   - **Forbidden**: Assuming techniques don't apply without testing

4. **Did you avoid assumptions about "basic" techniques?**
   - Review your analysis: Did you skip any technique because it seemed "obvious" or "too simple"?
   - **If yes** → TEST those "basic" techniques now

**Required Declaration:**
```
✅ HISTORICAL RESEARCH VERIFICATION COMPLETE
- Total research files: X
- Files fully processed: X
- Techniques extracted: X
- Techniques tested: X
- Techniques marked "not applicable" WITHOUT testing: 0
```

**If any counts don't match or techniques were skipped → Analysis is INCOMPLETE**

### 5b. Exploit Encoding and Payload Integrity Verification (MANDATORY)

**CRITICAL**: Verify that ALL test exploits you created have correct encoding and payloads.

**For EACH exploit variant you created in your initial analysis:**

1. **Encoding Verification**:
   - **Check POST request encoding**:
     - Is `+` encoded as `%2b` (not left as `+` which means space)?
     - Are all special characters properly URL-encoded?
     - Are spaces encoded as `%20` or `+` (consistently)?
   - **Check header encoding**:
     - Are header values properly encoded?
     - Are there any unencoded special characters?
   - **If encoding is incorrect** → Mark exploit as INVALID, fix encoding, re-test

2. **MSOTlPn_DWP Parameter Verification** (for deserialization exploits):
   - **If you modified MSOTlPn_DWP parameter**:
     - Verify the modification was intentional and correct
   - **If you did NOT need to modify MSOTlPn_DWP**:
     - Run: `diff your_exploit.py additional_resources/exploits/exploit.py`
     - Check: Does MSOTlPn_DWP value match EXACTLY (byte-for-byte)?
     - **If ANY difference in MSOTlPn_DWP** → Copy exact value from exploit.py, re-test

3. **Payload Integrity Verification**:
   - For each exploit variant, compare against original `exploit.py`:
     - Run: `diff your_variant.py additional_resources/exploits/exploit.py`
     - Verify: ONLY your intended changes appear (headers, type names, endpoints)
     - **If ANY unintended differences** → Payload is CORRUPTED, recreate using `cp` + `sed`, re-test
   - **Check for common corruption**:
     - Base64-encoded data changed?
     - Gzip-compressed data altered?
     - URL-encoded sequences modified?
     - Binary payload bytes different?

4. **Re-Testing Requirement**:
   - **If ANY of the following are true**:
     - Encoding was incorrect (+ not encoded as %2b, etc.)
     - MSOTlPn_DWP doesn't match exploit.py exactly (when it should)
     - Payloads have unintended differences
     - Any corruption detected
   - **Then you MUST**:
     - Fix the exploit using proper `cp` + `sed` method
     - Verify with `diff` that ONLY intended change exists
     - **Re-run ALL tests with corrected exploits**
     - Document: "Re-tested [exploit_name] after fixing [encoding/payload] issue - Result: [outcome]"

**Required Declaration:**
```
✅ EXPLOIT INTEGRITY VERIFICATION COMPLETE
- Total exploit variants created: X
- Exploits with correct encoding: X
- Exploits with valid MSOTlPn_DWP (if applicable): X
- Exploits with payload integrity: X
- Exploits requiring re-testing: X
- Re-tests completed: X
```

**If any exploits had issues and weren't re-tested → Analysis is INCOMPLETE**

### 6. Consolidate Bypass Routes

Provide a **comprehensive enumeration** of ALL bypass routes:

```markdown
# Bypass Completeness Results

## Exploit Being Analyzed
[specify which exploit from your initial analysis]

## Complete Bypass Route Enumeration

### Primary Bypass Routes (from initial analysis)
1. **Bypass Route 1**: [Description]
   - **Entry Point**: [File:Line or endpoint]
   - **Attack Mechanism**: [How the bypass works]
   - **Test Results**: [HTTP request/response or test outcome]
   - **Historical Pattern**: [Similar to any historical exploit? If so, which?]
   - **Likelihood**: [High/Medium/Low]
   - **Evidence**: [Code patterns, diff hunks, test outcomes, historical references]

2. **Bypass Route 2**: [Description]
   - [Same structure]

### Additional Bypass Routes (from this coverage check)
3. **Bypass Route 3**: [Description]
   - [Same structure]

## Patch Gaps Identified
- [List any code paths where the patch is incomplete]
- [Note any edge cases not covered]
- [Identify any alternative paths not addressed]
- [Note if similar gaps appeared in historical patches]

## Bypass Feasibility Summary
- **Total distinct bypass routes identified**: X
- **High likelihood bypasses (with test evidence)**: Y
- **Medium likelihood bypasses (plausible but untested)**: Z
- **Low likelihood bypasses (theoretical)**: W
- **Novel bypasses not seen in historical research**: N

## Testing Evidence
For each bypass route tested, document:
- Request/response details
- Server behavior
- Success/failure outcome
- Error messages or indicators
- Comparison to historical exploit behavior

## Completeness Assessment
- [ ] I have checked all alternative attack paths
- [ ] I have verified patch coverage across all code paths
- [ ] I have tested edge cases and boundary conditions
- [ ] I have reviewed related components
- [ ] I have compared to historical bypass patterns
- **Confidence in completeness**: [High/Medium/Low - explain why]
```

### 7. Self-Assessment

Answer honestly:
- **"Did I stop after finding the first bypass route, or did I systematically enumerate all possibilities?"**
- **"Are there code paths I haven't examined that could lead to the same outcome?"**
- **"Could an attacker with knowledge of my first bypass find alternatives I missed?"**
- **"Have I actually tested the bypass routes, or am I speculating based on code alone?"**
- **"Have I applied relevant historical bypass patterns from prior research?"**

## What This Check Is NOT About

**STRICTLY FORBIDDEN:**
- ❌ **NO new vulnerability types** - Do not search for different vulnerabilities
- ❌ **NO broad code review** - Do not read code unrelated to bypass testing
- ❌ **NO static analysis deep-dives** - Do not analyze security changes unrelated to your exploit
- ❌ **NO speculation** - Do not generate hypotheses about "what else might be in the diff"
- ❌ **NO code-only analysis** - Do not skip testing and rely on code review alone
- ❌ **NO historical research deep-dives** - Use research to identify test targets, not as substitute for testing

**REQUIRED FOCUS:**
- ✅ **Dynamic testing ONLY** - Test every bypass hypothesis against the target server
- ✅ **Same vulnerability ONLY** - Find alternative ways to exploit the SAME vuln
- ✅ **Historical patterns as test targets** - Use research to identify what to test, then TEST
- ✅ **Test-driven approach** - Use minimal code review to identify test targets, then TEST
- ✅ **Exhaustive bypass enumeration** - Find ALL bypass routes for the known exploit
- ✅ **Evidence-based claims** - Every bypass claim must have test results (request/response)

## Critical Reminder

**This prompt is OPTIONAL** - Skip it if speed is the priority or if you've already identified clear bypasses in your initial analysis.

**Do NOT read from `./ai_results/`**. Only reference your previous findings from this conversation's context.

Use ONLY the materials in this experiment directory (including historical research in `additional_resources/`).

**Dynamic testing is mandatory** - Every bypass claim must be tested against the target server. Use historical research to identify what to test, not as a substitute for testing.

Focus exclusively on comprehensive bypass enumeration for the exploit you already analyzed—not vulnerability discovery.
