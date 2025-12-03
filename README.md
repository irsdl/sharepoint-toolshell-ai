# AI-Assisted Security Research: SharePoint Patch Analysis

**Research Goal:** Evaluate AI capabilities in discovering n-day vulnerabilities through patch diffing and exploit development, without internet access to known CVEs or public exploits.

**Presentation:** NDC Manchester Conference - "ToolShell Patch Bypass and the AI That Might Have Seen It Coming"

## Overview

This repository supports a controlled experiment comparing AI models' ability to:
1. **Discover bypass techniques** for incomplete patches
2. **Develop exploits** organically without accessing public disclosure
3. **Identify vulnerabilities** from patch diffs (auth bypass + deserialization RCE)

## Cloning This Repository

Clone with submodules to get ILSpy binaries and prior exploit repositories:
```bash
git clone --recurse-submodules https://github.com/irsdl/sp-toolshell-ai-research.git
```

## Experiment Design
See [experiments/](experiments/) for the details.

## Development Methodology: Vibe Coding

This pipeline was developed using AI-assisted **vibe coding** where Claude Code served as the development partner. When working with AI in this repository, start with:

> Read [agent.md](agent.md) in the repo root and follow it for the rest of this session.

See [agent.md](agent.md) for project structure, development rules, and execution guidance.

## Repository Structure

```
sp-toolshell-ai-research/
├── snapshots_raw/              🗄️ Raw server captures (excluded from git)
│   ├── v1/                     # Original (unpatched)
│   ├── v2/                     # First patch
│   └── v3/                     # Second patch
│
├── snapshots_norm/             📝 Normalized configs for diffing
│   ├── v1/                     # Original (unpatched)
│   ├── v2/                     # First patch
│   └── v3/                     # Second patch
│
├── snapshots_decompiled/       💎 Decompiled C# sources
│   ├── v1/                     # Original (unpatched)
│   ├── v2/                     # First patch
│   ├── v3/                     # Second patch
│   └── path-mappings.csv       # Maps short names → original paths
│
├── diff_reports/               📊 Generated patch files
│   ├── v1-to-v2.content.patch         # Web files only
│   ├── v1-to-v2.content.stat.txt
│   ├── v1-to-v2.decompiled.patch      # C# code only
│   ├── v1-to-v2.decompiled.stat.txt
│   ├── v1-to-v2.server-side.patch     # Combined C# + web + configs
│   ├── v1-to-v2.server-side.stat.txt
│   ├── v2-to-v3.content.patch         # Web files only
│   ├── v2-to-v3.content.stat.txt
│   ├── v2-to-v3.decompiled.patch      # C# code only
│   ├── v2-to-v3.decompiled.stat.txt
│   ├── v2-to-v3.server-side.patch     # Combined C# + web + configs
│   └── v2-to-v3.server-side.stat.txt
│
├── artifacts/                  🔨 Build artifacts (excluded from git)
│   ├── file-hashes/            # SHA256 hashes and change detection
│   └── path-mappings/          # Decompiled folder → original path maps
│
├── additional_resources/       📚 Research materials
│   ├── ms_advisories/          # Microsoft CSAF files
│   ├── previous_exploits_github_projects/  # Prior GitHub projects (git submodules)
│   ├── previous_sp_related_writeups/       # Prior research (HTML + assets)
│   ├── social_media/           # Social media posts
│   ├── zdi_pwn2own_announcement/  # ZDI Pwn2Own announcement
│   └── exploits/               # Exploits (HTTP requests or code)
│
├── additional_resources_text/  📄 Markdown conversions of HTML research
│   └── previous_sp_related_writeups/  # Clean markdown versions
│
├── experiments/                🧪 Isolated experiment environments
│   ├── README.md               # Experiment setup guide
│   ├── templates/              # Agent.md templates for experiments
│   ├── prompts/                # Experiment prompts (organized by type)
│   │   ├── 1.diff-triage/
│   │   ├── 2.static-analysis/
│   │   └── 3.dynamic-analysis/
│   ├── 1.1.diff-triage/            # Populated by setup commands (excluded from git)
│   ├── 1.2.diff-triage/            # Populated by setup commands (excluded from git)
│   ├── 1.3.diff-triage/            # Populated by setup commands (excluded from git)
│   ├── 2.1.static-analysis/        # Populated by setup commands (excluded from git)
│   ├── 3.1.dynamic-analysis/       # Populated by setup commands (excluded from git)
│   ├── 3.2.dynamic-analysis/       # Populated by setup commands (excluded from git)
│   └── ai_results/             🤖 AI experiment outputs
│
├── tools/                      🛠️ Automation pipeline
│   ├── snapshot/               # Server capture scripts
│   ├── normalize/              # Config sanitization
│   ├── decompile/              # ILSpy automation + binaries
│   ├── hashing/                # File categorization & change detection
│   ├── diff/                   # Patch generation
│   └── cleanup/                # HTML to Markdown conversion
│
├── .gitmodules                 📦 Git submodules configuration
├── .gitignore                  🚫 Excludes copyrighted/large files
├── readme.md                   📖 Project overview
├── agent.md                    🤖 AI assistant instructions
└── run-pipeline.ps1            ▶️ Main orchestrator
```

### Maintaining Additional Resources

Convert HTML articles to Markdown for RAG pipelines:
```powershell
python tools/cleanup/html_to_markdown.py --source additional_resources --output additional_resources_text
```

## Understanding Diff File Types & Generation

### File Types

| Type | Contents | Size | Use When |
|------|----------|------|----------|
| **`.content.patch`** | Web files (ASPX, ASMX, SVC, CSHTML, HTML, JS, CSS), static resources | 78-170 MB | Analyzing web-facing attack surfaces |
| **`.decompiled.patch`** | Decompiled .NET assemblies only | 21-52 MB | Focusing on server-side C# logic |
| **`.server-side.patch`** | Combined: C# + web files + configs | 16-42 MB | Comprehensive view of both C# and web |
| **`.stat.txt`** | Statistics: file counts, lines added/removed | - | Identifying high-impact changes |

### Generation Commands

Generate patches:
```powershell
powershell -File tools/diff/make-diff-server-side.ps1 -FromDir snapshots_norm/v1 -ToDir snapshots_norm/v2
powershell -File tools/diff/make-diff-server-side.ps1 -FromDir snapshots_norm/v2 -ToDir snapshots_norm/v3
```

## AI Interaction Setup

### Platform Selection Matrix
| AI Model | Interface | Config | Cost Estimate |
|----------|-----------|--------|---------------|
| GPT-4 Turbo | OpenAI API | Disable functions, browsing | $10-30/session |
| Claude Sonnet 4.5 | Claude Code IDE | No MCP web tools | $5-15/session |
| Gemini 2.0 Flash | Google AI Studio | API mode | $3-10/session |
| DeepSeek V3 | Direct API | Default settings | $2-5/session |

### Preparation Checklist
- [ ] Generate all diffs (`diff_reports/*.patch`)
- [ ] Prepare isolated lab server access (curl endpoints documented)
- [ ] Create phase-gated prompt templates (cold/advisory/context)
- [ ] Disable web search for all AI interfaces
- [ ] Set up logging/recording for each AI session
- [ ] Pre-stage Microsoft advisory and historical vuln docs

---

## Data Pipeline (Technical)

### Prerequisites
- **PowerShell 5.1+** (use `powershell` command) or **7+** (use `pwsh` command)
- **Git**, **~5GB disk space** per version, **ILSpy CLI** (bundled)

### Quick Start

```powershell
powershell -File tools/validate-environment.ps1     # Validate environment
powershell -File run-pipeline.ps1                   # Run pipeline (use -Force to re-run)
```

### Manual Execution (Step-by-Step)

**Prerequisites:** Ensure `snapshots_norm/` and `snapshots_decompiled/` directories are populated with version directories (v1, v2, v3).

```powershell
# Note: Use 'powershell' for PS 5.1 or 'pwsh' for PS 7+

# Generate server-side combined diffs (C# + web files + config)
powershell -File tools/diff/make-diff-server-side.ps1 -FromDir snapshots_norm/v1 -ToDir snapshots_norm/v2
powershell -File tools/diff/make-diff-server-side.ps1 -FromDir snapshots_norm/v2 -ToDir snapshots_norm/v3
```

**Review outputs:**
- Server-side patches: `diff_reports/v*-to-v*.server-side.patch` (C# + web files + config)
- Statistics: `diff_reports/*.stat.txt`

**Important Git Workflow:**
- **Commit changes** to scripts/tools after modifications (allows easy rollback)
- Use descriptive commit messages explaining what changed and why
- Commit before regenerating large files (diffs, decompiled code) to track changes separately
- See [agent.md](agent.md) Rule #1 for complete git workflow requirements

---

## Snapshot Collection (Manual Step)

Snapshots have already been captured and normalized in the `snapshots_norm/` and `snapshots_decompiled/` directories:

- **v1/** - Original (unpatched vulnerable baseline)
- **v2/** - First patch (incomplete, bypassable)
- **v3/** - Second patch (final complete patch)

The snapshots contain:
- **snapshots_norm/** - Normalized configuration files, web files, and scripts (all files, including duplicates)
- **snapshots_decompiled/** - Decompiled C# source code from .NET assemblies (optimized when using pipeline - see below)

### Important: Duplicate Assemblies

⚠️ The same DLL may be decompiled multiple times if it exists in multiple locations (decompilation is path-based). Use `path-mappings.csv` to map decompiled folders to original paths.

---

## Running Experiments

This repository supports three types of controlled AI security experiments:

1. **Static Analysis** - Testing AI when we know exactly where patches were applied
2. **Dynamic Analysis** - Providing AI with working exploits and patched code
3. **Diff-Driven Triage** - Can AI discover vulnerabilities from patch diffs alone?

Each experiment type has multiple variants with progressively more context (from zero-knowledge to full historical research access).

### Detailed Experiment Setup

See **[experiments/](experiments/)** for:
- Complete experiment descriptions and objectives
- PowerShell setup commands for each experiment variant
- Folder structure requirements
- Agent constraint files (no internet access enforcement)
- Success criteria and evaluation metrics

### Prompts Repository

All experiment prompts are stored in the `experiments/prompts/` directory, organized by experiment type:
- `experiments/prompts/1.diff-triage/variant-1/`, `variant-2/`, and `variant-3/`
- `experiments/prompts/2.static-analysis/`
- `experiments/prompts/3.dynamic-analysis/variant-1/` and `variant-2/`

This ensures reproducibility and allows researchers to replicate experiments exactly.

---

## Presentation Deliverables

1. **Comparative Analysis**: Success rates, time/cost efficiency, exploit quality scoring
2. **Key Findings**: AI strengths in patch diffing vs. exploit dev, impact of progressive disclosure
3. **Recommendations**: Patch velocity criticality, AI-assisted defensive code review potential

---

## Notes

- Keep `snapshots_norm` and `snapshots_decompiled` immutable; re-run pipeline steps as needed
- Mark repo **PRIVATE** - contains security-sensitive material
- Tag snapshots: `git tag v{1,2,3}-baseline`
- Per-command stderr logs are emitted to `logs/` (git-ignored). Each diff script creates timestamped files only when git reports warnings/errors—check there if a stage behaves unexpectedly.

## Troubleshooting

### ILSpy Installation
If `ilspycmd.exe` is missing:
1. Download ILSpy CLI from [GitHub Releases](https://github.com/icsharpcode/ILSpy/releases)
2. Look for `ilspycmd-*-net8.0.zip` (e.g., v9.1.0.7988)
3. Extract to `tools/decompile/ILSpyCmd/`
4. Verify `ilspycmd.exe` exists in that directory

### Common Issues
- **Environment validation fails:** Run `powershell -File tools/validate-environment.ps1` for detailed diagnostics
- **No versions detected:** Ensure directories in `snapshots_norm/` are named v1, v2, v3, etc.
- **Pipeline hangs:** Decompilation is CPU-intensive; adjust `-MaxParallel` in decompile-all.ps1
- **Diff too large:** This is expected for full SharePoint patches; AI context limits may require filtering
- **Robocopy errors:** Normalization uses Windows robocopy; exit codes 0-7 are success

### Verification
After running pipeline, verify outputs:
```powershell
# Check decompilation summary
Get-Content snapshots_decompiled/decompile-summary-*.txt

# List generated diffs
Get-ChildItem diff_reports/

# Count generated patches
(Get-ChildItem diff_reports -Filter *.patch).Count
```

### PowerShell Version Check
Check version: `$PSVersionTable.PSVersion` (Desktop = 5.1, Core = 7+)
