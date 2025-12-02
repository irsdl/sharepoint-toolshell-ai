# AI Security Research Experiments

This document describes how to set up isolated environments for testing AI capabilities in vulnerability discovery and exploitation development.

## Overview

We conduct three types of experiments to evaluate AI models' security analysis capabilities:

1. **Diff-Driven Triage** - Can AI find the original vulnerability from patch diffs?
2. **Static Analysis** - Given exact patch locations, can AI evaluate patch quality and find bypasses?
3. **Dynamic Analysis** - Can AI reverse-engineer exploits and develop bypasses?

Each experiment is isolated with its own directory, specific materials, and constraints. Experiments are ordered by increasing information availability, from minimal context (diff-only) to maximum context (working exploits).

## Experiment Summary

### Experiment 1: Diff-Driven Triage (Discovery)
**3 variants** - AI analyzes diffs to discover what vulnerabilities were fixed

| Variant | Context Level | Additional Materials | Prompt Flow |
|---------|--------------|---------------------|-------------|
| 1.1 | Minimal (Cold Start) | None | **Flow 1:** discover-vulnerabilities.md → additional-coverage-check.md → final-verification.md<br>**Flow 2:** discover-v2-vulnerabilities.md → final-verification.md |
| 1.2 | Advisory | Microsoft CSAF files | auth-bypass.md → additional-coverage-check.md → final-verification.md<br>deserialization.md → additional-coverage-check.md → final-verification.md |
| 1.3 | Full | CSAF + Social media + Prior research | auth-bypass.md → [additional-coverage-check.md*] → final-verification.md<br>deserialization.md → [additional-coverage-check.md*] → final-verification.md |

**Notes**:
- Variant 1.1 has two flows: Full discovery (Flow 1) or v2-focused analysis (Flow 2)
- Variants 1.2 and 1.3: Run auth-bypass.md OR deserialization.md (or both in sequence)
- *additional-coverage-check.md is optional for variant-3 if saving tokens is critical (see variant-3 README)

### Experiment 2: Static Analysis (Patch Evaluation)
**Single variant** - AI evaluates patch effectiveness with known vulnerability locations

| Experiment | Prompt Flow | Context |
|---------|-------------|---------|
| 2.1 | auth-bypass.md → additional-coverage-check.md → final-verification.md<br>deserialization.md → additional-coverage-check.md → final-verification.md | Exact patch locations + vulnerability types disclosed |

### Experiment 3: Dynamic Analysis (Exploit Analysis)
**2 variants** - AI reverse-engineers exploits and develops bypasses

| Variant | Context Level | Additional Materials | Prompt Flow |
|---------|--------------|---------------------|-------------|
| 3.1 | Basic | Working exploits | auth-bypass.md → additional-coverage-check.md → final-verification.md<br>deserialization.md → additional-coverage-check.md → final-verification.md |
| 3.2 | Enhanced | Working exploits + Prior research | auth-bypass.md → additional-coverage-check.md → final-verification.md<br>deserialization.md → additional-coverage-check.md → final-verification.md |

## Experiment Guardrails

**Critical Constraints:**
- ⛔ **No internet access** during experiments (enforced via API settings or explicit instructions)
- 📝 Context is added gradually (variants test different information levels)
- 🔒 Each experiment runs in isolation to prevent cross-contamination
- 📊 All prompts are stored in `experiments/prompts/` directory for reproducibility
- 🚫 **Do not read `ai_results/`** - Contains tainted data from previous AI runs that would contaminate fresh analysis

## Running AI Agents with No Context

**⚠️ Critical for True Experiments**: For unbiased results, AI agents must run with no prior context or git access.

### Recommended Approach

1. **Copy experiment to isolated location** (outside this repository):
   ```powershell
   Copy-Item "experiments\1.1.diff-triage-v1" -Destination "C:\isolated-experiments\run-001" -Recurse
   cd C:\isolated-experiments\run-001
   ```

2. **Verify no .git directory** exists in isolated location:
   ```powershell
   if (!(Test-Path ".git")) { Write-Host "✓ Isolated (no git access)" }
   ```

3. **Start AI agent with cleared context**:
   - **Claude**: Run `claude /clear` before starting
   - **ChatGPT/Codex**: Start fresh API session with no system context
   - **Gemini**: Initialize new conversation with no prior messages

4. **Provide the prompt** from `prompt/` directory to begin the experiment

This ensures the AI has no access to repository history, commit messages, or prior conversation context.

## Prompt Approach

Most experiments provide **TWO vulnerability-focused prompts**:

1. **auth-bypass.md** - Focuses on authentication bypass vulnerability analysis (CVE-2025-49704)
   - Vulnerability location: `SPRequestModule.cs`
   - Analysis type varies by experiment (discovery, patch evaluation, or exploit analysis)

2. **deserialization.md** - Focuses on deserialization vulnerability analysis (CVE-2025-49706)
   - Vulnerability location: Configuration files (`cloudweb.config`, `web.config`)
   - Analysis type varies by experiment (discovery, patch evaluation, or exploit analysis)

**Exception: Experiment 1.1 (Minimal Context)**
- Uses a single **discover-vulnerabilities.md** prompt
- AI doesn't know what vulnerability types exist (true cold start)
- Must discover both vulnerabilities from diffs alone without hints

**Why separate prompts (1.2, 1.3, 2.1, 3.1, 3.2)?**
- Allows focused analysis on each vulnerability type
- Prevents confusion between different vulnerability classes
- Enables independent evaluation of AI performance per vulnerability type
- Researchers can run either or both prompts depending on their goals

**Note:** All experiments use the same folder structure and setup commands. The only difference is which prompt file you choose to analyze.

## Multi-Pass Analysis Workflow

To maximize vulnerability discovery and reduce false positives/negatives, experiments support a **3-pass workflow**:

### Pass 1: Initial Analysis
- **Prompt**: `discover-vulnerabilities.md` (Exp 1.1) or `auth-bypass.md`/`deserialization.md` (others)
- **Goal**: Initial vulnerability discovery from available materials
- **Output**: `[agent-name]_result_[timestamp].md`

### Pass 2: Coverage Check (Optional but Recommended)
- **Prompt**: `additional-coverage-check.md`
- **Goal**: Systematic gap analysis to find missed vulnerabilities
- **Key Features**:
  - Enumerates ALL changes affecting confidentiality, integrity, or availability
  - Maps changes to initial findings
  - Identifies UNMAPPED changes (potential missed vulnerabilities)
  - Generates hypotheses for unmapped changes without hints
- **Output**: `coverage-[agent-name]_result_[timestamp].md`

### Pass 3: Final Verification (Optional but Recommended)
- **Prompt**: `final-verification.md`
- **Goal**: Evidence-based validation of ALL findings from passes 1 and 2
- **Key Features**:
  - Requires exact diff hunks and code evidence
  - Assigns confidence levels with justification
  - Confirms/Rejects/Uncertain for each claim
  - Conservative approach: prefers "unknown" over speculation
- **Output**: `final-[agent-name]_result_[timestamp].md`

**Workflow Execution**:
1. Run initial analysis prompt(s)
2. Without clearing context, run `additional-coverage-check.md`
3. Without clearing context, run `final-verification.md`

This multi-pass approach significantly reduces false negatives (missed vulnerabilities) and false positives (incorrect claims).

---

## Experiment 1: Diff-Driven Triage (Find Original Vulnerability)

### Goal
Can AI discover vulnerabilities by analyzing patch diffs between original and patched code?

### Materials Provided (All Variants)
- v1 normalized files and decompiled sources
- v2 normalized files and decompiled sources
- Diff reports (v1-to-v2 patch files and statistics)

### Variants

#### Experiment 1.1: Diff-Triage - Variant 1 (Minimal Context)
**Materials:** Core files + diffs only (no external hints)

##### Setup Commands

```powershell
# Create experiment directory
$ExpDir = "experiments\1.1.diff-triage-v1"
New-Item -ItemType Directory -Path $ExpDir -Force

# Copy v1 normalized files
New-Item -ItemType Directory -Path "$ExpDir\snapshots_norm\v1" -Force
Copy-Item "snapshots_norm\v1\*" -Destination "$ExpDir\snapshots_norm\v1" -Recurse -Force

# Copy v2 normalized files
New-Item -ItemType Directory -Path "$ExpDir\snapshots_norm\v2" -Force
Copy-Item "snapshots_norm\v2\*" -Destination "$ExpDir\snapshots_norm\v2" -Recurse -Force

# Copy v1 decompiled sources
New-Item -ItemType Directory -Path "$ExpDir\snapshots_decompiled\v1" -Force
Copy-Item "snapshots_decompiled\v1\*" -Destination "$ExpDir\snapshots_decompiled\v1" -Recurse -Force

# Copy v2 decompiled sources
New-Item -ItemType Directory -Path "$ExpDir\snapshots_decompiled\v2" -Force
Copy-Item "snapshots_decompiled\v2\*" -Destination "$ExpDir\snapshots_decompiled\v2" -Recurse -Force

# Copy diff reports
New-Item -ItemType Directory -Path "$ExpDir\diff_reports" -Force
Copy-Item "diff_reports\v1-to-v2.server-side.patch" -Destination "$ExpDir\diff_reports\" -Force
Copy-Item "diff_reports\v1-to-v2.server-side.stat.txt" -Destination "$ExpDir\diff_reports\" -Force

# Copy agent.md template
Copy-Item "experiments\templates\agent-diff-triage-v1.md" -Destination "$ExpDir\agent.md" -Force

# Copy prompts (exclude README.md)
New-Item -ItemType Directory -Path "$ExpDir\prompt" -Force
Copy-Item "experiments\prompts\1.diff-triage\variant-1\*" -Destination "$ExpDir\prompt\" -Recurse -Force -Exclude "README.md"

Write-Host "Diff-Driven Triage (Variant 1) experiment setup complete at: $ExpDir"
```

##### Folder Structure

```
experiments/1.1.diff-triage-v1/
├── agent.md                    # Experiment constraints and folder structure
├── prompt/                     # Experiment prompts (copied from experiments/prompts/1.diff-triage/variant-1/)
├── snapshots_norm/
│   ├── v1/                     # v1 normalized files
│   └── v2/                     # v2 normalized files
├── snapshots_decompiled/
│   ├── v1/                     # v1 decompiled C# sources
│   └── v2/                     # v2 decompiled C# sources
└── diff_reports/               # v1-to-v2 patch files
    ├── v1-to-v2.server-side.patch
    └── v1-to-v2.server-side.stat.txt
```

#### Experiment 1.2: Diff-Triage - Variant 2 (Advisory Context)
**Materials:** Core files + diffs + security advisories
- Microsoft CSAF files (`ms_advisories/`)

##### Setup Commands

```powershell
# Create experiment directory
$ExpDir = "experiments\1.2.diff-triage-v2"
New-Item -ItemType Directory -Path $ExpDir -Force

# Copy v1 normalized files
New-Item -ItemType Directory -Path "$ExpDir\snapshots_norm\v1" -Force
Copy-Item "snapshots_norm\v1\*" -Destination "$ExpDir\snapshots_norm\v1" -Recurse -Force

# Copy v2 normalized files
New-Item -ItemType Directory -Path "$ExpDir\snapshots_norm\v2" -Force
Copy-Item "snapshots_norm\v2\*" -Destination "$ExpDir\snapshots_norm\v2" -Recurse -Force

# Copy v1 decompiled sources
New-Item -ItemType Directory -Path "$ExpDir\snapshots_decompiled\v1" -Force
Copy-Item "snapshots_decompiled\v1\*" -Destination "$ExpDir\snapshots_decompiled\v1" -Recurse -Force

# Copy v2 decompiled sources
New-Item -ItemType Directory -Path "$ExpDir\snapshots_decompiled\v2" -Force
Copy-Item "snapshots_decompiled\v2\*" -Destination "$ExpDir\snapshots_decompiled\v2" -Recurse -Force

# Copy diff reports
New-Item -ItemType Directory -Path "$ExpDir\diff_reports" -Force
Copy-Item "diff_reports\v1-to-v2.server-side.patch" -Destination "$ExpDir\diff_reports\" -Force
Copy-Item "diff_reports\v1-to-v2.server-side.stat.txt" -Destination "$ExpDir\diff_reports\" -Force

# Copy CSAF files (Microsoft security advisories)
New-Item -ItemType Directory -Path "$ExpDir\additional_resources\ms_advisories" -Force
Copy-Item "additional_resources\ms_advisories\*" -Destination "$ExpDir\additional_resources\ms_advisories\" -Recurse -Force

# Copy agent.md template
Copy-Item "experiments\templates\agent-diff-triage-v2.md" -Destination "$ExpDir\agent.md" -Force

# Copy prompts (exclude README.md)
New-Item -ItemType Directory -Path "$ExpDir\prompt" -Force
Copy-Item "experiments\prompts\1.diff-triage\variant-2\*" -Destination "$ExpDir\prompt\" -Recurse -Force -Exclude "README.md"

Write-Host "Diff-Driven Triage (Variant 2) experiment setup complete at: $ExpDir"
```

##### Folder Structure

```
experiments/1.2.diff-triage-v2/
├── agent.md                    # Experiment constraints and folder structure
├── prompt/                     # Experiment prompts (copied from experiments/prompts/1.diff-triage/variant-2/)
├── snapshots_norm/
│   ├── v1/                     # v1 normalized files
│   └── v2/                     # v2 normalized files
├── snapshots_decompiled/
│   ├── v1/                     # v1 decompiled C# sources
│   └── v2/                     # v2 decompiled C# sources
├── diff_reports/               # v1-to-v2 patch files
│   ├── v1-to-v2.server-side.patch
│   └── v1-to-v2.server-side.stat.txt
└── additional_resources/
    └── ms_advisories/          # Microsoft CSAF files
```

#### Experiment 1.3: Diff-Triage - Variant 3 (Full Context)
**Materials:** Core files + diffs + security advisories + public research materials
- Microsoft CSAF files (`ms_advisories/`)
- Social media posts (`social_media/`)
- Prior research materials:
  - ZDI Pwn2Own announcement (`zdi_pwn2own_announcement/`)
  - Prior GitHub exploit projects (`previous_exploits_github_projects/`)
  - Prior security writeups (`previous_sp_related_writeups/`)

##### Setup Commands

```powershell
# Create experiment directory
$ExpDir = "experiments\1.3.diff-triage-v3"
New-Item -ItemType Directory -Path $ExpDir -Force

# Copy v1 normalized files
New-Item -ItemType Directory -Path "$ExpDir\snapshots_norm\v1" -Force
Copy-Item "snapshots_norm\v1\*" -Destination "$ExpDir\snapshots_norm\v1" -Recurse -Force

# Copy v2 normalized files
New-Item -ItemType Directory -Path "$ExpDir\snapshots_norm\v2" -Force
Copy-Item "snapshots_norm\v2\*" -Destination "$ExpDir\snapshots_norm\v2" -Recurse -Force

# Copy v1 decompiled sources
New-Item -ItemType Directory -Path "$ExpDir\snapshots_decompiled\v1" -Force
Copy-Item "snapshots_decompiled\v1\*" -Destination "$ExpDir\snapshots_decompiled\v1" -Recurse -Force

# Copy v2 decompiled sources
New-Item -ItemType Directory -Path "$ExpDir\snapshots_decompiled\v2" -Force
Copy-Item "snapshots_decompiled\v2\*" -Destination "$ExpDir\snapshots_decompiled\v2" -Recurse -Force

# Copy diff reports
New-Item -ItemType Directory -Path "$ExpDir\diff_reports" -Force
Copy-Item "diff_reports\v1-to-v2.server-side.patch" -Destination "$ExpDir\diff_reports\" -Force
Copy-Item "diff_reports\v1-to-v2.server-side.stat.txt" -Destination "$ExpDir\diff_reports\" -Force

# Copy CSAF files (Microsoft security advisories)
New-Item -ItemType Directory -Path "$ExpDir\additional_resources\ms_advisories" -Force
Copy-Item "additional_resources\ms_advisories\*" -Destination "$ExpDir\additional_resources\ms_advisories\" -Recurse -Force

# Copy social media posts
New-Item -ItemType Directory -Path "$ExpDir\additional_resources\social_media" -Force
Copy-Item "additional_resources\social_media\*" -Destination "$ExpDir\additional_resources\social_media\" -Recurse -Force

# Copy ZDI announcement
New-Item -ItemType Directory -Path "$ExpDir\additional_resources\zdi_pwn2own_announcement" -Force
Copy-Item "additional_resources\zdi_pwn2own_announcement\*" -Destination "$ExpDir\additional_resources\zdi_pwn2own_announcement\" -Recurse -Force

# Copy prior research
New-Item -ItemType Directory -Path "$ExpDir\additional_resources\previous_exploits_github_projects" -Force
Copy-Item "additional_resources\previous_exploits_github_projects\*" -Destination "$ExpDir\additional_resources\previous_exploits_github_projects" -Recurse -Force

New-Item -ItemType Directory -Path "$ExpDir\additional_resources\previous_sp_related_writeups" -Force
Copy-Item "additional_resources\previous_sp_related_writeups\*" -Destination "$ExpDir\additional_resources\previous_sp_related_writeups" -Recurse -Force

# Copy agent.md template
Copy-Item "experiments\templates\agent-diff-triage-v3.md" -Destination "$ExpDir\agent.md" -Force

# Copy prompts (exclude README.md)
New-Item -ItemType Directory -Path "$ExpDir\prompt" -Force
Copy-Item "experiments\prompts\1.diff-triage\variant-3\*" -Destination "$ExpDir\prompt\" -Recurse -Force -Exclude "README.md"

Write-Host "Diff-Driven Triage (Variant 3) experiment setup complete at: $ExpDir"
```

##### Folder Structure

```
experiments/1.3.diff-triage-v3/
├── agent.md                    # Experiment constraints and folder structure
├── prompt/                     # Experiment prompts (copied from experiments/prompts/1.diff-triage/variant-3/)
├── snapshots_norm/
│   ├── v1/                     # v1 normalized files
│   └── v2/                     # v2 normalized files
├── snapshots_decompiled/
│   ├── v1/                     # v1 decompiled C# sources
│   └── v2/                     # v2 decompiled C# sources
├── diff_reports/               # v1-to-v2 patch files
│   ├── v1-to-v2.server-side.patch
│   └── v1-to-v2.server-side.stat.txt
└── additional_resources/
    ├── ms_advisories/          # Microsoft CSAF files
    ├── social_media/           # Social media posts
    ├── zdi_pwn2own_announcement/  # ZDI Pwn2Own announcement
    ├── previous_exploits_github_projects/  # Prior GitHub exploit projects
    └── previous_sp_related_writeups/       # Prior security writeups
```

### Prompts

**Variant 1.1 (Minimal Context):**
- **discover-vulnerabilities.md**: Single prompt for discovering all vulnerabilities from diffs (no hints about vulnerability types)

**Variants 1.2 and 1.3 (Advisory & Full Context):**
- **auth-bypass.md**: Discover authentication bypass vulnerability from diffs
- **deserialization.md**: Discover deserialization vulnerability from diffs

**Prompt Locations:**
- Variant 1.1: [experiments/prompts/1.diff-triage/variant-1/](experiments/prompts/1.diff-triage/variant-1/)
- Variant 1.2: [experiments/prompts/1.diff-triage/variant-2/](experiments/prompts/1.diff-triage/variant-2/)
- Variant 1.3: [experiments/prompts/1.diff-triage/variant-3/](experiments/prompts/1.diff-triage/variant-3/)

---

## Experiment 2.1: Static Analysis (Patch Evaluation & Bypass Discovery)

### Goal
Evaluate patch effectiveness and identify potential bypasses for known vulnerability types. AI is provided with specific vulnerability locations and types, and must assess whether patches are sufficient or if bypasses exist.

### Key Questions to Answer
1. **Why was the code vulnerable?** (Root cause analysis)
2. **Is the patch sufficient?** (Completeness evaluation)
3. **Are there any bypasses?** (List all hypotheses with likelihood ratings)

### Vulnerability Types Analyzed
This experiment provides **TWO vulnerability-focused prompts**:
- **auth-bypass.md**: Authentication bypass vulnerability in `SPRequestModule.cs`
- **deserialization.md**: Deserialization vulnerability (ExcelDataSet removal from config files)

Run either or both prompts depending on your research goals.

### Materials Provided
- v1 normalized files and decompiled sources
- v2 normalized files and decompiled sources
- Diff reports (v1-to-v2)
- Specific vulnerability locations and types (provided in prompts)

### Setup Commands

```powershell
# Create experiment directory
$ExpDir = "experiments\2.1.static-analysis"
New-Item -ItemType Directory -Path $ExpDir -Force

# Copy v1 normalized files
New-Item -ItemType Directory -Path "$ExpDir\snapshots_norm\v1" -Force
Copy-Item "snapshots_norm\v1\*" -Destination "$ExpDir\snapshots_norm\v1" -Recurse -Force

# Copy v2 normalized files
New-Item -ItemType Directory -Path "$ExpDir\snapshots_norm\v2" -Force
Copy-Item "snapshots_norm\v2\*" -Destination "$ExpDir\snapshots_norm\v2" -Recurse -Force

# Copy v1 decompiled sources
New-Item -ItemType Directory -Path "$ExpDir\snapshots_decompiled\v1" -Force
Copy-Item "snapshots_decompiled\v1\*" -Destination "$ExpDir\snapshots_decompiled\v1" -Recurse -Force

# Copy v2 decompiled sources
New-Item -ItemType Directory -Path "$ExpDir\snapshots_decompiled\v2" -Force
Copy-Item "snapshots_decompiled\v2\*" -Destination "$ExpDir\snapshots_decompiled\v2" -Recurse -Force

# Copy agent.md template
Copy-Item "experiments\templates\agent-static-analysis.md" -Destination "$ExpDir\agent.md" -Force

# Copy diff reports
New-Item -ItemType Directory -Path "$ExpDir\diff_reports" -Force
Copy-Item "diff_reports\v1-to-v2.server-side.patch" -Destination "$ExpDir\diff_reports\" -Force
Copy-Item "diff_reports\v1-to-v2.server-side.stat.txt" -Destination "$ExpDir\diff_reports\" -Force

# Copy prompts (exclude README.md)
New-Item -ItemType Directory -Path "$ExpDir\prompt" -Force
Copy-Item "experiments\prompts\2.static-analysis\*" -Destination "$ExpDir\prompt\" -Recurse -Force -Exclude "README.md"

Write-Host "Static Analysis experiment setup complete at: $ExpDir"
```

### Folder Structure

```
experiments/2.1.static-analysis/
├── agent.md                    # Experiment constraints and folder structure
├── prompt/                     # Experiment prompts (copied from experiments/prompts/2.static-analysis/)
├── diff_reports/               # Patch diffs (v1 to v2)
│   ├── v1-to-v2.server-side.patch
│   └── v1-to-v2.server-side.stat.txt
├── snapshots_norm/
│   ├── v1/                     # v1 normalized files
│   └── v2/                     # v2 normalized files
└── snapshots_decompiled/
    ├── v1/                     # v1 decompiled C# sources
    └── v2/                     # v2 decompiled C# sources
```

### Prompts
- **auth-bypass.md**: Authentication bypass vulnerability patch evaluation
- **deserialization.md**: Deserialization vulnerability (ExcelDataSet) patch evaluation

Both prompts are available at: [experiments/prompts/2.static-analysis/](experiments/prompts/2.static-analysis/)

---

## Experiment 3: Dynamic Analysis (Known Exploit)

### Goal
Provide AI with a working exploit and patched code—can it identify new bypasses or understand the vulnerability?

### Materials Provided (All Variants)
- v1 normalized files and decompiled sources
- v2 normalized files and decompiled sources
- Working exploits (HTTP requests or code)
- Patched target server URL for testing

### Variants

#### Experiment 3.1: Dynamic Analysis - Variant 1 (Basic Context)
**Materials:** Core files + exploits only (no historical research)

##### Setup Commands

```powershell
# Create experiment directory
$ExpDir = "experiments\3.1.dynamic-analysis-v1"
New-Item -ItemType Directory -Path $ExpDir -Force

# Copy v1 normalized files
New-Item -ItemType Directory -Path "$ExpDir\snapshots_norm\v1" -Force
Copy-Item "snapshots_norm\v1\*" -Destination "$ExpDir\snapshots_norm\v1" -Recurse -Force

# Copy v2 normalized files
New-Item -ItemType Directory -Path "$ExpDir\snapshots_norm\v2" -Force
Copy-Item "snapshots_norm\v2\*" -Destination "$ExpDir\snapshots_norm\v2" -Recurse -Force

# Copy v1 decompiled sources
New-Item -ItemType Directory -Path "$ExpDir\snapshots_decompiled\v1" -Force
Copy-Item "snapshots_decompiled\v1\*" -Destination "$ExpDir\snapshots_decompiled\v1" -Recurse -Force

# Copy v2 decompiled sources
New-Item -ItemType Directory -Path "$ExpDir\snapshots_decompiled\v2" -Force
Copy-Item "snapshots_decompiled\v2\*" -Destination "$ExpDir\snapshots_decompiled\v2" -Recurse -Force

# Copy exploits
New-Item -ItemType Directory -Path "$ExpDir\additional_resources\exploits" -Force
Copy-Item "additional_resources\exploits\*" -Destination "$ExpDir\additional_resources\exploits" -Recurse -Force

# Create target URL placeholder file
@"
# Patched Target Server

URL: [To be provided during experiment]

This file contains the target server endpoint for testing exploits.
"@ | Out-File -FilePath "$ExpDir\target-server.md" -Encoding UTF8

# Copy agent.md template
Copy-Item "experiments\templates\agent-dynamic-analysis-v1.md" -Destination "$ExpDir\agent.md" -Force

# Copy diff reports
New-Item -ItemType Directory -Path "$ExpDir\diff_reports" -Force
Copy-Item "diff_reports\v1-to-v2.server-side.patch" -Destination "$ExpDir\diff_reports\" -Force
Copy-Item "diff_reports\v1-to-v2.server-side.stat.txt" -Destination "$ExpDir\diff_reports\" -Force

# Copy prompts (exclude README.md)
New-Item -ItemType Directory -Path "$ExpDir\prompt" -Force
Copy-Item "experiments\prompts\3.dynamic-analysis\variant-1\*" -Destination "$ExpDir\prompt\" -Recurse -Force -Exclude "README.md"

Write-Host "Dynamic Analysis (Variant 1) experiment setup complete at: $ExpDir"
```

##### Folder Structure

```
experiments/3.1.dynamic-analysis-v1/
├── agent.md                    # Experiment constraints and folder structure
├── prompt/                     # Experiment prompts (copied from experiments/prompts/3.dynamic-analysis/variant-1/)
├── diff_reports/               # Patch diffs (v1 to v2)
│   ├── v1-to-v2.server-side.patch
│   └── v1-to-v2.server-side.stat.txt
├── snapshots_norm/
│   ├── v1/                     # v1 normalized files
│   └── v2/                     # v2 normalized files
├── snapshots_decompiled/
│   ├── v1/                     # v1 decompiled C# sources
│   └── v2/                     # v2 decompiled C# sources
├── additional_resources/
│   └── exploits/               # Working exploits
└── target-server.md            # Target URL for testing
```

#### Experiment 3.2: Dynamic Analysis - Variant 2 (Enhanced Context)
**Materials:** Core files + exploits + prior research materials
- Prior GitHub exploit projects (`previous_exploits_github_projects/`)
- Prior security writeups (`previous_sp_related_writeups/`)

##### Setup Commands

```powershell
# Create experiment directory
$ExpDir = "experiments\3.2.dynamic-analysis-v2"
New-Item -ItemType Directory -Path $ExpDir -Force

# Copy v1 normalized files
New-Item -ItemType Directory -Path "$ExpDir\snapshots_norm\v1" -Force
Copy-Item "snapshots_norm\v1\*" -Destination "$ExpDir\snapshots_norm\v1" -Recurse -Force

# Copy v2 normalized files
New-Item -ItemType Directory -Path "$ExpDir\snapshots_norm\v2" -Force
Copy-Item "snapshots_norm\v2\*" -Destination "$ExpDir\snapshots_norm\v2" -Recurse -Force

# Copy v1 decompiled sources
New-Item -ItemType Directory -Path "$ExpDir\snapshots_decompiled\v1" -Force
Copy-Item "snapshots_decompiled\v1\*" -Destination "$ExpDir\snapshots_decompiled\v1" -Recurse -Force

# Copy v2 decompiled sources
New-Item -ItemType Directory -Path "$ExpDir\snapshots_decompiled\v2" -Force
Copy-Item "snapshots_decompiled\v2\*" -Destination "$ExpDir\snapshots_decompiled\v2" -Recurse -Force

# Copy exploits
New-Item -ItemType Directory -Path "$ExpDir\additional_resources\exploits" -Force
Copy-Item "additional_resources\exploits\*" -Destination "$ExpDir\additional_resources\exploits" -Recurse -Force

# Copy previous research materials
New-Item -ItemType Directory -Path "$ExpDir\additional_resources\previous_exploits_github_projects" -Force
Copy-Item "additional_resources\previous_exploits_github_projects\*" -Destination "$ExpDir\additional_resources\previous_exploits_github_projects" -Recurse -Force

New-Item -ItemType Directory -Path "$ExpDir\additional_resources\previous_sp_related_writeups" -Force
Copy-Item "additional_resources\previous_sp_related_writeups\*" -Destination "$ExpDir\additional_resources\previous_sp_related_writeups" -Recurse -Force

# Create target URL placeholder file
@"
# Patched Target Server

URL: [To be provided during experiment]

This file contains the target server endpoint for testing exploits.
"@ | Out-File -FilePath "$ExpDir\target-server.md" -Encoding UTF8

# Copy agent.md template
Copy-Item "experiments\templates\agent-dynamic-analysis-v2.md" -Destination "$ExpDir\agent.md" -Force

# Copy diff reports
New-Item -ItemType Directory -Path "$ExpDir\diff_reports" -Force
Copy-Item "diff_reports\v1-to-v2.server-side.patch" -Destination "$ExpDir\diff_reports\" -Force
Copy-Item "diff_reports\v1-to-v2.server-side.stat.txt" -Destination "$ExpDir\diff_reports\" -Force

# Copy prompts (exclude README.md)
New-Item -ItemType Directory -Path "$ExpDir\prompt" -Force
Copy-Item "experiments\prompts\3.dynamic-analysis\variant-2\*" -Destination "$ExpDir\prompt\" -Recurse -Force -Exclude "README.md"

Write-Host "Dynamic Analysis (Variant 2) experiment setup complete at: $ExpDir"
```

##### Folder Structure

```
experiments/3.2.dynamic-analysis-v2/
├── agent.md                    # Experiment constraints and folder structure
├── prompt/                     # Experiment prompts (copied from experiments/prompts/3.dynamic-analysis/variant-2/)
├── diff_reports/               # Patch diffs (v1 to v2)
│   ├── v1-to-v2.server-side.patch
│   └── v1-to-v2.server-side.stat.txt
├── snapshots_norm/
│   ├── v1/                     # v1 normalized files
│   └── v2/                     # v2 normalized files
├── snapshots_decompiled/
│   ├── v1/                     # v1 decompiled C# sources
│   └── v2/                     # v2 decompiled C# sources
├── additional_resources/
│   ├── exploits/               # Working exploits
│   ├── previous_exploits_github_projects/  # Prior GitHub exploit projects
│   └── previous_sp_related_writeups/       # Prior security writeups
└── target-server.md            # Target URL for testing
```

### Prompts

Each variant includes two vulnerability-focused prompts:
- **auth-bypass.md**: Authentication bypass exploit analysis
- **deserialization.md**: Deserialization exploit analysis

**Prompt Locations:**
- Variant 1: [experiments/prompts/3.dynamic-analysis/variant-1/](experiments/prompts/3.dynamic-analysis/variant-1/)
- Variant 2: [experiments/prompts/3.dynamic-analysis/variant-2/](experiments/prompts/3.dynamic-analysis/variant-2/)

---

## Running an Experiment

### Step 1: Set Up the Environment
1. Open PowerShell in the repository root
2. Copy and run the setup commands for your chosen experiment
3. Verify the experiment directory structure was created correctly

### Step 2: Configure AI Settings
- **Disable internet access** (via API settings or explicit instructions)
- Set model parameters (temperature, max tokens, etc.)
- Configure logging/recording

### Step 3: Load Initial Prompt
1. Navigate to the appropriate prompts directory
2. Use the initial prompt for that experiment variant
3. Provide the AI with the `agent.md` file from the experiment directory

### Step 4: Conduct Analysis

**Single-Pass (Basic)**:
- Provide the initial prompt to the AI
- Record the AI's response
- Save output as `[agent-name]_result_[timestamp].md`

**Multi-Pass (Recommended for Maximum Accuracy)**:
1. **Pass 1**: Provide initial prompt (e.g., `discover-vulnerabilities.md`)
   - Record response
   - Save as `[agent-name]_result_[timestamp].md`

2. **Pass 2**: In same session, provide `additional-coverage-check.md`
   - AI references previous findings from conversation context
   - Identifies gaps and unmapped changes
   - Save as `coverage-[agent-name]_result_[timestamp].md`

3. **Pass 3**: In same session, provide `final-verification.md`
   - AI verifies findings from both passes with evidence
   - Confirms/Rejects/Uncertain for each claim
   - Save as `final-[agent-name]_result_[timestamp].md`

**Important**: Do NOT clear context between passes. Each pass builds on previous findings.

### Step 5: Document Results
Store experiment results separately from this repository for analysis and comparison.

---

## Prompts Directory Structure

All experiment prompts are organized under `experiments/prompts/`:

```
experiments/prompts/
├── 1.diff-triage/
│   ├── variant-1/
│   │   ├── discover-vulnerabilities.md      # Initial discovery (minimal context)
│   │   ├── additional-coverage-check.md     # Pass 2: Gap analysis
│   │   ├── final-verification.md            # Pass 3: Evidence validation
│   │   └── README.md
│   ├── variant-2/
│   │   ├── auth-bypass.md                   # Initial: Auth bypass (advisory context)
│   │   ├── deserialization.md               # Initial: Deserialization (advisory context)
│   │   ├── additional-coverage-check.md     # Pass 2: Gap analysis
│   │   ├── final-verification.md            # Pass 3: Evidence validation
│   │   └── README.md
│   └── variant-3/
│       ├── auth-bypass.md                   # Initial: Auth bypass (full context)
│       ├── deserialization.md               # Initial: Deserialization (full context)
│       ├── additional-coverage-check.md     # Pass 2: Gap analysis
│       ├── final-verification.md            # Pass 3: Evidence validation
│       └── README.md
├── 2.static-analysis/
│   ├── auth-bypass.md                       # Initial: Auth bypass patch evaluation
│   ├── deserialization.md                   # Initial: Deserialization patch evaluation
│   ├── additional-coverage-check.md         # Pass 2: Gap analysis
│   ├── final-verification.md                # Pass 3: Evidence validation
│   └── README.md
└── 3.dynamic-analysis/
    ├── variant-1/
    │   ├── auth-bypass.md                   # Initial: Auth bypass exploit (basic)
    │   ├── deserialization.md               # Initial: Deserialization exploit (basic)
    │   ├── additional-coverage-check.md     # Pass 2: Gap analysis
    │   ├── final-verification.md            # Pass 3: Evidence validation
    │   └── README.md
    └── variant-2/
        ├── auth-bypass.md                   # Initial: Auth bypass exploit (enhanced)
        ├── deserialization.md               # Initial: Deserialization exploit (enhanced)
        ├── additional-coverage-check.md     # Pass 2: Gap analysis
        ├── final-verification.md            # Pass 3: Evidence validation
        └── README.md
```

**Prompt Types**:
- **Initial prompts**: First-pass vulnerability discovery/analysis
- **additional-coverage-check.md**: Systematic gap analysis (same for all experiments)
- **final-verification.md**: Evidence-based verification (same for all experiments)

---

## AI Results Storage

**Directory**: `ai_results/` (or `experiments/ai_results/`)

This directory stores outputs from AI experiment runs, including:
- AI analysis transcripts
- Generated exploit code
- Vulnerability assessments
- Research findings

**⚠️ Important**:
- This directory is **excluded from git** (see `.gitignore`)
- AI agents should **never read** from `ai_results/` during experiments to prevent contamination
- Results stored here are "tainted" data that would bias fresh analysis
- Store results separately for comparison and evaluation

## Notes

- Each experiment directory is **self-contained**—all necessary files are copied locally
- The `agent.md` file in each experiment enforces the no-internet constraint
- Experiments can be recreated by anyone using the PowerShell commands in this document
- Results should be analyzed separately and not committed to this repository
- Keep `snapshots_norm/` and `snapshots_decompiled/` immutable—experiments work from copies
