# Static Analysis Experiment Prompts

This directory contains prompts for the Static Analysis experiment.

## Experiment Overview

**Goal**: Evaluate patch effectiveness and identify potential bypasses for known vulnerability types.

**Context**: AI is provided with:
- Original (v1) and patched (v2) code
- Specific vulnerability locations and types
- Vulnerability type is disclosed (authentication bypass or deserialization)

## Prompt Flows

### Flow 1: Authentication Bypass Patch Evaluation
```
auth-bypass.md → additional-coverage-check.md → final-verification.md
```
Use when evaluating the authentication bypass patch effectiveness.

### Flow 2: Deserialization Patch Evaluation
```
deserialization.md → additional-coverage-check.md → final-verification.md
```
Use when evaluating the deserialization vulnerability patch effectiveness.

**Combining Flows (Optional):**
Flows can be combined for efficiency: `auth-bypass.md → deserialization.md → additional-coverage-check.md → final-verification.md`

- **Separate flows (default)**: Better for parallel multi-agent analysis and isolation
- **Combined flow**: More efficient for single-threaded analysis (saves time/tokens, provides better context)
- Use combined approach when parallelism and isolation aren't requirements

## Prompt Reference

| Prompt File | Purpose | When to Use | Output Prefix |
|-------------|---------|-------------|---------------|
| **auth-bypass.md** | Evaluate authentication bypass patch - root cause analysis, patch effectiveness, bypass hypotheses | Primary analysis for auth bypass patch evaluation | `auth-` |
| **deserialization.md** | Evaluate deserialization patch - ExcelDataSet removal analysis, dangerous type enumeration, bypass hypotheses | Primary analysis for deserialization patch evaluation | `deser-` |
| **additional-coverage-check.md** | Bypass completeness check - ensure ALL bypass routes for the disclosed vulnerability were identified | After initial analysis to catch missed bypass routes for the SAME vulnerability | `coverage-` |
| **final-verification.md** | Evidence-based validation of all bypass hypotheses with confidence levels | Final step to verify & validate all bypass claims | `final-` |

### Prompt Details

**auth-bypass.md**
- **Type**: Patch effectiveness evaluation
- **Approach**: Known vulnerability location analysis (SPRequestModule.cs)
- **Focus**: Root cause analysis, patch sufficiency, ALL potential bypass routes
- **Emphasizes**: Comprehensive bypass hypothesis generation with likelihood ratings
- **Deliverable**: Bypass hypotheses ranked by exploitability

**deserialization.md**
- **Type**: Patch effectiveness evaluation
- **Approach**: Known vulnerability location analysis (configuration files)
- **Focus**: ExcelDataSet danger analysis, patch completeness, ALL dangerous types
- **Emphasizes**: Alternative dangerous type discovery, re-registration attack paths
- **Deliverable**: Complete enumeration of dangerous types and bypass scenarios

**additional-coverage-check.md** *(Optional but recommended)*
- **Type**: Bypass completeness check
- **Approach**: Systematic enumeration of ALL bypass routes for the disclosed vulnerability
- **Focus**: Alternative code paths, edge cases, incomplete patches for the SAME vulnerability type
- **Value**: Ensures comprehensive bypass enumeration—validates the AI didn't stop after finding one route
- **Note**: NOT for discovering new vulnerabilities; purely for bypass completeness of the known vulnerability

**final-verification.md** *(Optional but recommended)*
- **Type**: Evidence-based validation
- **Approach**: Strict verification requiring code evidence for each bypass claim
- **Focus**: Validate bypass feasibility, assign confidence levels, filter false positives
- **Value**: Ensures all bypass hypotheses are grounded in actual code behavior
