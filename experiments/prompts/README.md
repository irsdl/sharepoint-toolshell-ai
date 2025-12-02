# Experiment Prompts

This directory contains all prompts used in AI security research experiments.

## Organization

Prompts are organized by experiment type and variant:

```
prompts/
├── 1.diff-triage/          Prompts for diff-driven vulnerability discovery
│   ├── variant-1/          No hints (cold start - single discovery prompt)
│   ├── variant-2/          With CSAF advisories (2 prompts)
│   └── variant-3/          Full context (2 prompts)
├── 2.static-analysis/      Prompts for patch evaluation (2 prompts)
└── 3.dynamic-analysis/     Prompts for exploit analysis
    ├── variant-1/          Without previous research (2 prompts)
    └── variant-2/          With previous research (2 prompts)
```

## Naming Convention

**Most experiments** include **two vulnerability-focused prompts**:
- `auth-bypass.md` - Analysis focused on authentication bypass vulnerability (CVE-2025-49704)
- `deserialization.md` - Analysis focused on deserialization vulnerability (CVE-2025-49706)

**Exception: Experiment 1.1 (Diff-Triage Variant 1 - Minimal Context)**:
- `discover-vulnerabilities.md` - Single unified prompt for discovering all vulnerabilities without hints
- AI doesn't know what vulnerability types exist (true cold start)

This approach allows:
- Focused analysis on each vulnerability type (when vulnerability is disclosed)
- True discovery capability testing (variant 1.1 with no hints)
- Independent evaluation of AI performance per vulnerability
- Flexibility to run either or both prompts depending on research goals

## Usage

1. Copy the appropriate prompt from this directory
2. Provide it to your AI model along with the experiment materials
3. Ensure the AI has read the `agent.md` file from the experiment directory
4. Record all responses for analysis

## Reproducibility

All prompts are version-controlled to ensure experiments can be replicated exactly. When creating new prompts:
- Use clear, unambiguous language
- Specify constraints (e.g., "do not use internet")
- Include success criteria
- Document any materials that should be provided alongside the prompt

See [experiments/](../) for complete experiment setup instructions.
