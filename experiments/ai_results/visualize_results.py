#!/usr/bin/env python3
"""
Visualize AI experiment results by experiment type.
Generates charts showing success rates for vulnerability discovery and bypass findings.
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path

# Set style
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (14, 10)
plt.rcParams['font.size'] = 10

def load_data():
    """Load and prepare the analytics CSV."""
    csv_path = Path(__file__).parent / 'basic_analytics.csv'
    df = pd.read_csv(csv_path)
    return df

def calculate_success_rates(df):
    """Calculate success rates by experiment type and model."""

    # For experiment 1.1, separate into v1 (original) and v2 (revised prompt) variants
    # based on the "Experiment Number" column (e.g., "1" vs "1-v2")
    # Also separate by AI model for comparison

    results = []
    experiments = df['Experiment'].unique()

    for exp in sorted(experiments):
        exp_data = df[df['Experiment'] == exp]

        # Check if this experiment has both v1 and v2 variants (1.1.diff-triage only)
        has_v1 = any(not str(num).endswith('-v2') for num in exp_data['Experiment Number'])
        has_v2 = any(str(num).endswith('-v2') for num in exp_data['Experiment Number'])

        if has_v1 and has_v2:
            # Split into two separate variants, then by model
            for variant_suffix, filter_func in [('(v1)', lambda x: not str(x).endswith('-v2')),
                                                  ('(v2)', lambda x: str(x).endswith('-v2'))]:
                variant_data = exp_data[exp_data['Experiment Number'].apply(filter_func)]

                if len(variant_data) == 0:
                    continue

                # For each variant, split by model
                for model in sorted(variant_data['Model'].dropna().unique()):
                    model_data = variant_data[variant_data['Model'] == model]

                    if len(model_data) == 0:
                        continue

                    # Calculate rates for this variant + model combination
                    # Count unique test numbers (not rows) to handle separate auth/deser rows per test
                    auth_bypass_found = model_data[model_data['Found Auth Bypass?'] == 'Yes']['Experiment Number'].nunique()
                    auth_bypass_total = model_data[model_data['Found Auth Bypass?'].notna() & (model_data['Found Auth Bypass?'] != 'N/A')]['Experiment Number'].nunique()

                    deser_found = model_data[model_data['Found Deserialization?'] == 'Yes']['Experiment Number'].nunique()
                    deser_total = model_data[model_data['Found Deserialization?'].notna() & (model_data['Found Deserialization?'] != 'N/A')]['Experiment Number'].nunique()

                    auth_patch_bypass = model_data[model_data['Auth-Bypass Patch > Found Bypass?'] == 'Yes']['Experiment Number'].nunique()
                    auth_patch_total = model_data[model_data['Auth-Bypass Patch > Found Bypass?'].notna() & (model_data['Auth-Bypass Patch > Found Bypass?'] != 'N/A')]['Experiment Number'].nunique()

                    deser_patch_bypass = model_data[model_data['Deserialization Patch > Found Bypass?'] == 'Yes']['Experiment Number'].nunique()
                    deser_patch_total = model_data[model_data['Deserialization Patch > Found Bypass?'].notna() & (model_data['Deserialization Patch > Found Bypass?'] != 'N/A')]['Experiment Number'].nunique()

                    results.append({
                        'Experiment': f"{exp} {variant_suffix}",
                        'Model': model,
                        'Auth Bypass Discovery': (auth_bypass_found / auth_bypass_total * 100) if auth_bypass_total > 0 else 0,
                        'Auth Bypass Discovery (n)': f"{auth_bypass_found}/{auth_bypass_total}",
                        'Deserialization Discovery': (deser_found / deser_total * 100) if deser_total > 0 else 0,
                        'Deserialization Discovery (n)': f"{deser_found}/{deser_total}",
                        'Auth Patch Bypass': (auth_patch_bypass / auth_patch_total * 100) if auth_patch_total > 0 else 0,
                        'Auth Patch Bypass (n)': f"{auth_patch_bypass}/{auth_patch_total}",
                        'Deser Patch Bypass': (deser_patch_bypass / deser_patch_total * 100) if deser_patch_total > 0 else 0,
                        'Deser Patch Bypass (n)': f"{deser_patch_bypass}/{deser_patch_total}",
                    })
        else:
            # No variant split needed - but still split by model
            for model in sorted(exp_data['Model'].dropna().unique()):
                model_data = exp_data[exp_data['Model'] == model]

                if len(model_data) == 0:
                    continue

                # Count unique test numbers (not rows) to handle separate auth/deser rows per test
                auth_bypass_found = model_data[model_data['Found Auth Bypass?'] == 'Yes']['Experiment Number'].nunique()
                auth_bypass_total = model_data[model_data['Found Auth Bypass?'].notna() & (model_data['Found Auth Bypass?'] != 'N/A')]['Experiment Number'].nunique()

                deser_found = model_data[model_data['Found Deserialization?'] == 'Yes']['Experiment Number'].nunique()
                deser_total = model_data[model_data['Found Deserialization?'].notna() & (model_data['Found Deserialization?'] != 'N/A')]['Experiment Number'].nunique()

                auth_patch_bypass = model_data[model_data['Auth-Bypass Patch > Found Bypass?'] == 'Yes']['Experiment Number'].nunique()
                auth_patch_total = model_data[model_data['Auth-Bypass Patch > Found Bypass?'].notna() & (model_data['Auth-Bypass Patch > Found Bypass?'] != 'N/A')]['Experiment Number'].nunique()

                deser_patch_bypass = model_data[model_data['Deserialization Patch > Found Bypass?'] == 'Yes']['Experiment Number'].nunique()
                deser_patch_total = model_data[model_data['Deserialization Patch > Found Bypass?'].notna() & (model_data['Deserialization Patch > Found Bypass?'] != 'N/A')]['Experiment Number'].nunique()

                results.append({
                    'Experiment': exp,
                    'Model': model,
                    'Auth Bypass Discovery': (auth_bypass_found / auth_bypass_total * 100) if auth_bypass_total > 0 else 0,
                    'Auth Bypass Discovery (n)': f"{auth_bypass_found}/{auth_bypass_total}",
                    'Deserialization Discovery': (deser_found / deser_total * 100) if deser_total > 0 else 0,
                    'Deserialization Discovery (n)': f"{deser_found}/{deser_total}",
                    'Auth Patch Bypass': (auth_patch_bypass / auth_patch_total * 100) if auth_patch_total > 0 else 0,
                    'Auth Patch Bypass (n)': f"{auth_patch_bypass}/{auth_patch_total}",
                    'Deser Patch Bypass': (deser_patch_bypass / deser_patch_total * 100) if deser_patch_total > 0 else 0,
                    'Deser Patch Bypass (n)': f"{deser_patch_bypass}/{deser_patch_total}",
                })

    return pd.DataFrame(results)

def create_grouped_bar_chart(results_df, output_path):
    """Create a grouped bar chart showing all metrics by experiment and model."""

    fig, ax = plt.subplots(figsize=(20, 10))

    # Create labels combining experiment and model
    results_df = results_df.copy()
    results_df['Label'] = results_df['Experiment'] + '\n' + results_df['Model']

    labels = results_df['Label']
    x = range(len(labels))
    width = 0.2

    metrics = [
        ('Auth Bypass Discovery', '#2E86AB'),
        ('Deserialization Discovery', '#A23B72'),
        ('Auth Patch Bypass', '#F18F01'),
        ('Deser Patch Bypass', '#C73E1D')
    ]

    # Create bars
    for i, (metric, color) in enumerate(metrics):
        offset = width * (i - 1.5)
        values = results_df[metric]
        bars = ax.bar([p + offset for p in x], values, width, label=metric, color=color, alpha=0.8)

        # Add value labels on bars (show all values including 0%)
        for j, (bar, val) in enumerate(zip(bars, values)):
            count = results_df[f"{metric} (n)"].iloc[j]
            y_pos = max(bar.get_height() + 1, 2)  # Ensure 0% labels are visible above x-axis
            ax.text(bar.get_x() + bar.get_width()/2, y_pos,
                   f'{val:.0f}%\n({count})',
                   ha='center', va='bottom', fontsize=7, fontweight='bold')

    # Customize
    ax.set_xlabel('Experiment Type / Model', fontsize=12, fontweight='bold')
    ax.set_ylabel('Success Rate (%)', fontsize=12, fontweight='bold')
    ax.set_title('AI Security Research: Success Rates by Experiment Type and Model',
                 fontsize=14, fontweight='bold', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=9)
    ax.set_ylim(0, 105)
    ax.legend(loc='upper left', framealpha=0.9)
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Saved grouped bar chart: {output_path}")
    plt.close()

def create_heatmap(results_df, output_path):
    """Create a heatmap showing success rates by experiment and model."""

    fig, ax = plt.subplots(figsize=(16, 8))

    # Create labels combining experiment and model
    results_df = results_df.copy()
    results_df['Label'] = results_df['Experiment'] + '\n' + results_df['Model']

    # Prepare data for heatmap
    heatmap_data = results_df[['Label', 'Auth Bypass Discovery',
                                'Deserialization Discovery', 'Auth Patch Bypass',
                                'Deser Patch Bypass']].set_index('Label')

    # Rename columns for display
    heatmap_data.columns = ['Auth\nDiscovery', 'Deser\nDiscovery',
                            'Auth Patch\nBypass', 'Deser Patch\nBypass']

    # Create heatmap
    sns.heatmap(heatmap_data.T, annot=True, fmt='.0f', cmap='RdYlGn',
                vmin=0, vmax=100, cbar_kws={'label': 'Success Rate (%)'},
                linewidths=0.5, ax=ax, annot_kws={'fontsize': 8})

    ax.set_title('AI Security Research: Success Rate Heatmap by Experiment Type and Model',
                 fontsize=14, fontweight='bold', pad=20)
    ax.set_xlabel('Experiment Type / Model', fontsize=12, fontweight='bold')
    ax.set_ylabel('Metric', fontsize=12, fontweight='bold')
    ax.tick_params(axis='x', labelsize=9)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Saved heatmap: {output_path}")
    plt.close()

def create_discovery_chart(results_df, output_path):
    """Create chart showing vulnerability discovery in patched code rates (Experiment 1 only)."""

    # Filter to only Experiment 1.x (diff-triage variants)
    discovery_df = results_df[results_df['Experiment'].str.startswith('1.')]

    if discovery_df.empty:
        print("No discovery experiments found, skipping discovery chart")
        return

    fig, ax = plt.subplots(figsize=(16, 6))

    # Create labels combining experiment and model
    discovery_df = discovery_df.copy()
    discovery_df['Label'] = discovery_df['Experiment'] + '\n' + discovery_df['Model']

    labels = discovery_df['Label']
    x = range(len(labels))
    width = 0.35

    auth_disc = discovery_df['Auth Bypass Discovery']
    deser_disc = discovery_df['Deserialization Discovery']

    bars1 = ax.bar([p - width/2 for p in x], auth_disc, width,
                   label='Auth Bypass in Patched Code', color='#2E86AB', alpha=0.8)
    bars2 = ax.bar([p + width/2 for p in x], deser_disc, width,
                   label='Deserialization in Patched Code', color='#A23B72', alpha=0.8)

    # Add labels (show all values including 0%)
    for bars, data, counts in [(bars1, auth_disc, discovery_df['Auth Bypass Discovery (n)']),
                                (bars2, deser_disc, discovery_df['Deserialization Discovery (n)'])]:
        for bar, val, count in zip(bars, data, counts):
            y_pos = max(bar.get_height() + 1, 2)  # Ensure 0% labels are visible above x-axis
            ax.text(bar.get_x() + bar.get_width()/2, y_pos,
                   f'{val:.0f}%\n({count})', ha='center', va='bottom',
                   fontsize=8, fontweight='bold')

    ax.set_xlabel('Experiment Variant / Model', fontsize=11, fontweight='bold')
    ax.set_ylabel('Discovery Rate (%)', fontsize=11, fontweight='bold')
    ax.set_title('Discovery of Vulnerabilities in Patched Code from Patch Diffs\n(Comparing AI Models)',
                 fontsize=12, fontweight='bold', pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=9)
    ax.set_ylim(0, 105)
    ax.legend(loc='upper right')
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Saved discovery chart: {output_path}")
    plt.close()

def create_discovery_chart_11_only(results_df, output_path):
    """Create chart showing vulnerability discovery for experiment 1.1 only (for slides)."""

    # Filter to only Experiment 1.1 variants
    discovery_df = results_df[results_df['Experiment'].str.match(r'^1\.1\.')]

    if discovery_df.empty:
        print("No 1.1 experiments found, skipping 1.1-only discovery chart")
        return

    fig, ax = plt.subplots(figsize=(12, 6))

    # Create labels combining experiment and model
    discovery_df = discovery_df.copy()
    discovery_df['Label'] = discovery_df['Experiment'] + '\n' + discovery_df['Model']

    labels = discovery_df['Label']
    x = range(len(labels))
    width = 0.35

    auth_disc = discovery_df['Auth Bypass Discovery']
    deser_disc = discovery_df['Deserialization Discovery']

    bars1 = ax.bar([p - width/2 for p in x], auth_disc, width,
                   label='Auth Bypass in Patched Code', color='#2E86AB', alpha=0.8)
    bars2 = ax.bar([p + width/2 for p in x], deser_disc, width,
                   label='Deserialization in Patched Code', color='#A23B72', alpha=0.8)

    # Add labels (show all values including 0%)
    for bars, data, counts in [(bars1, auth_disc, discovery_df['Auth Bypass Discovery (n)']),
                                (bars2, deser_disc, discovery_df['Deserialization Discovery (n)'])]:
        for bar, val, count in zip(bars, data, counts):
            y_pos = max(bar.get_height() + 1, 2)  # Ensure 0% labels are visible above x-axis
            ax.text(bar.get_x() + bar.get_width()/2, y_pos,
                   f'{val:.0f}%\n({count})', ha='center', va='bottom',
                   fontsize=9, fontweight='bold')

    ax.set_xlabel('Experiment Variant / Model', fontsize=12, fontweight='bold')
    ax.set_ylabel('Discovery Rate (%)', fontsize=12, fontweight='bold')
    ax.set_title('Experiment 1.1: Discovery from Patch Diffs (No Context)\n(Comparing AI Models)',
                 fontsize=13, fontweight='bold', pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=10)
    ax.set_ylim(0, 105)
    ax.legend(loc='upper right', fontsize=10)
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Saved 1.1-only discovery chart: {output_path}")
    plt.close()

def create_discovery_chart_12_13(results_df, output_path):
    """Create chart showing vulnerability discovery for experiments 1.2 and 1.3 (for slides)."""

    # Filter to experiments 1.2 and 1.3
    discovery_df = results_df[results_df['Experiment'].str.match(r'^1\.[23]\.')]

    if discovery_df.empty:
        print("No 1.2/1.3 experiments found, skipping 1.2-1.3 discovery chart")
        return

    fig, ax = plt.subplots(figsize=(14, 6))

    # Create labels combining experiment and model
    discovery_df = discovery_df.copy()
    discovery_df['Label'] = discovery_df['Experiment'] + '\n' + discovery_df['Model']

    labels = discovery_df['Label']
    x = range(len(labels))
    width = 0.35

    auth_disc = discovery_df['Auth Bypass Discovery']
    deser_disc = discovery_df['Deserialization Discovery']

    bars1 = ax.bar([p - width/2 for p in x], auth_disc, width,
                   label='Auth Bypass in Patched Code', color='#2E86AB', alpha=0.8)
    bars2 = ax.bar([p + width/2 for p in x], deser_disc, width,
                   label='Deserialization in Patched Code', color='#A23B72', alpha=0.8)

    # Add labels (show all values including 0%)
    for bars, data, counts in [(bars1, auth_disc, discovery_df['Auth Bypass Discovery (n)']),
                                (bars2, deser_disc, discovery_df['Deserialization Discovery (n)'])]:
        for bar, val, count in zip(bars, data, counts):
            y_pos = max(bar.get_height() + 1, 2)  # Ensure 0% labels are visible above x-axis
            ax.text(bar.get_x() + bar.get_width()/2, y_pos,
                   f'{val:.0f}%\n({count})', ha='center', va='bottom',
                   fontsize=9, fontweight='bold')

    ax.set_xlabel('Experiment Variant / Model', fontsize=12, fontweight='bold')
    ax.set_ylabel('Discovery Rate (%)', fontsize=12, fontweight='bold')
    ax.set_title('Experiments 1.2 & 1.3: Discovery from Patch Diffs with Context\n(1.2: Advisory Context | 1.3: Full Historical Context)',
                 fontsize=13, fontweight='bold', pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=10)
    ax.set_ylim(0, 105)
    ax.legend(loc='upper right', fontsize=10)
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Saved 1.2-1.3 discovery chart: {output_path}")
    plt.close()

def create_bypass_chart(results_df, output_path):
    """Create chart showing patch bypass discovery rates (Experiments 2 & 3 only)."""

    # Filter to only Experiments 2.x and 3.x (static/dynamic analysis)
    bypass_df = results_df[results_df['Experiment'].str.match(r'^[23]\.')]

    if bypass_df.empty:
        print("No bypass experiments found, skipping bypass chart")
        return

    fig, ax = plt.subplots(figsize=(14, 6))

    # Create labels combining experiment and model
    bypass_df = bypass_df.copy()
    bypass_df['Label'] = bypass_df['Experiment'] + '\n' + bypass_df['Model']

    labels = bypass_df['Label']
    x = range(len(labels))
    width = 0.35

    auth_bypass = bypass_df['Auth Patch Bypass']
    deser_bypass = bypass_df['Deser Patch Bypass']

    bars1 = ax.bar([p - width/2 for p in x], auth_bypass, width,
                   label='Auth Patch Bypass', color='#F18F01', alpha=0.8)
    bars2 = ax.bar([p + width/2 for p in x], deser_bypass, width,
                   label='Deser Patch Bypass', color='#C73E1D', alpha=0.8)

    # Add labels (show all values including 0%)
    for bars, data, counts in [(bars1, auth_bypass, bypass_df['Auth Patch Bypass (n)']),
                                (bars2, deser_bypass, bypass_df['Deser Patch Bypass (n)'])]:
        for bar, val, count in zip(bars, data, counts):
            y_pos = max(bar.get_height() + 1, 2)  # Ensure 0% labels are visible above x-axis
            ax.text(bar.get_x() + bar.get_width()/2, y_pos,
                   f'{val:.0f}%\n({count})', ha='center', va='bottom',
                   fontsize=8, fontweight='bold')

    ax.set_xlabel('Experiment Type / Model', fontsize=11, fontweight='bold')
    ax.set_ylabel('Bypass Discovery Rate (%)', fontsize=11, fontweight='bold')
    ax.set_title('Patch Bypass Discovery (Experiments 2: Static, 3: Dynamic Analysis)\n(Comparing AI Models)',
                 fontsize=12, fontweight='bold', pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=9)
    ax.set_ylim(0, 105)
    ax.legend(loc='upper right')
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Saved bypass chart: {output_path}")
    plt.close()

def create_bypass_chart_2_only(results_df, output_path):
    """Create chart showing patch bypass discovery for experiment 2.1 only (for slides)."""

    # Filter to only Experiment 2.1 (static analysis)
    bypass_df = results_df[results_df['Experiment'].str.match(r'^2\.1\.')]

    if bypass_df.empty:
        print("No 2.1 experiments found, skipping 2.1-only bypass chart")
        return

    fig, ax = plt.subplots(figsize=(12, 6))

    # Create labels combining experiment and model
    bypass_df = bypass_df.copy()
    bypass_df['Label'] = bypass_df['Experiment'] + '\n' + bypass_df['Model']

    labels = bypass_df['Label']
    x = range(len(labels))
    width = 0.35

    auth_bypass = bypass_df['Auth Patch Bypass']
    deser_bypass = bypass_df['Deser Patch Bypass']

    bars1 = ax.bar([p - width/2 for p in x], auth_bypass, width,
                   label='Auth Patch Bypass', color='#F18F01', alpha=0.8)
    bars2 = ax.bar([p + width/2 for p in x], deser_bypass, width,
                   label='Deser Patch Bypass', color='#C73E1D', alpha=0.8)

    # Add labels (show all values including 0%)
    for bars, data, counts in [(bars1, auth_bypass, bypass_df['Auth Patch Bypass (n)']),
                                (bars2, deser_bypass, bypass_df['Deser Patch Bypass (n)'])]:
        for bar, val, count in zip(bars, data, counts):
            y_pos = max(bar.get_height() + 1, 2)  # Ensure 0% labels are visible above x-axis
            ax.text(bar.get_x() + bar.get_width()/2, y_pos,
                   f'{val:.0f}%\n({count})', ha='center', va='bottom',
                   fontsize=9, fontweight='bold')

    ax.set_xlabel('Experiment / Model', fontsize=12, fontweight='bold')
    ax.set_ylabel('Bypass Discovery Rate (%)', fontsize=12, fontweight='bold')
    ax.set_title('Experiment 2.1: Patch Bypass Discovery via Static Analysis\n(Comparing AI Models)',
                 fontsize=13, fontweight='bold', pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=10)
    ax.set_ylim(0, 105)
    ax.legend(loc='upper right', fontsize=10)
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Saved 2.1-only bypass chart: {output_path}")
    plt.close()

def create_bypass_chart_3_combined(results_df, output_path):
    """Create chart showing patch bypass discovery for experiments 3.1 and 3.2 (for slides)."""

    # Filter to experiments 3.1 and 3.2 (dynamic analysis)
    bypass_df = results_df[results_df['Experiment'].str.match(r'^3\.[12]\.')]

    if bypass_df.empty:
        print("No 3.1/3.2 experiments found, skipping 3.1-3.2 bypass chart")
        return

    fig, ax = plt.subplots(figsize=(14, 6))

    # Create labels combining experiment and model
    bypass_df = bypass_df.copy()
    bypass_df['Label'] = bypass_df['Experiment'] + '\n' + bypass_df['Model']

    labels = bypass_df['Label']
    x = range(len(labels))
    width = 0.35

    auth_bypass = bypass_df['Auth Patch Bypass']
    deser_bypass = bypass_df['Deser Patch Bypass']

    bars1 = ax.bar([p - width/2 for p in x], auth_bypass, width,
                   label='Auth Patch Bypass', color='#F18F01', alpha=0.8)
    bars2 = ax.bar([p + width/2 for p in x], deser_bypass, width,
                   label='Deser Patch Bypass', color='#C73E1D', alpha=0.8)

    # Add labels (show all values including 0%)
    for bars, data, counts in [(bars1, auth_bypass, bypass_df['Auth Patch Bypass (n)']),
                                (bars2, deser_bypass, bypass_df['Deser Patch Bypass (n)'])]:
        for bar, val, count in zip(bars, data, counts):
            y_pos = max(bar.get_height() + 1, 2)  # Ensure 0% labels are visible above x-axis
            ax.text(bar.get_x() + bar.get_width()/2, y_pos,
                   f'{val:.0f}%\n({count})', ha='center', va='bottom',
                   fontsize=9, fontweight='bold')

    ax.set_xlabel('Experiment / Model', fontsize=12, fontweight='bold')
    ax.set_ylabel('Bypass Discovery Rate (%)', fontsize=12, fontweight='bold')
    ax.set_title('Experiments 3.1 & 3.2: Patch Bypass Discovery via Dynamic Testing\n(3.1: First Patch | 3.2: Second Patch)',
                 fontsize=13, fontweight='bold', pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=10)
    ax.set_ylim(0, 105)
    ax.legend(loc='upper right', fontsize=10)
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Saved 3.1-3.2 bypass chart: {output_path}")
    plt.close()

def create_model_comparison(df, output_path):
    """Create chart comparing models across all experiments."""

    fig, axes = plt.subplots(2, 2, figsize=(16, 12))

    metrics = [
        ('Found Auth Bypass?', 'Auth Bypass Discovery', axes[0, 0]),
        ('Found Deserialization?', 'Deserialization Discovery', axes[0, 1]),
        ('Auth-Bypass Patch > Found Bypass?', 'Auth Patch Bypass Discovery', axes[1, 0]),
        ('Deserialization Patch > Found Bypass?', 'Deser Patch Bypass Discovery', axes[1, 1])
    ]

    for metric_col, title, ax in metrics:
        # Calculate success rates by model
        model_data = []
        for model in df['Model'].unique():
            if pd.isna(model):
                continue
            model_df = df[df['Model'] == model]
            success = (model_df[metric_col] == 'Yes').sum()
            total = (model_df[metric_col] != 'N/A').sum()
            if total > 0:
                model_data.append({
                    'Model': model,
                    'Rate': success / total * 100,
                    'Count': f"{success}/{total}"
                })

        if model_data:
            model_df_chart = pd.DataFrame(model_data).sort_values('Rate', ascending=False)

            bars = ax.barh(model_df_chart['Model'], model_df_chart['Rate'],
                          color='steelblue', alpha=0.7)

            # Add labels
            for i, (bar, rate, count) in enumerate(zip(bars, model_df_chart['Rate'],
                                                       model_df_chart['Count'])):
                ax.text(rate + 1, i, f'{rate:.0f}% ({count})',
                       va='center', fontsize=9, fontweight='bold')

            ax.set_xlabel('Success Rate (%)', fontsize=10, fontweight='bold')
            ax.set_title(title, fontsize=11, fontweight='bold')
            ax.set_xlim(0, 105)
            ax.grid(axis='x', alpha=0.3)

    plt.suptitle('AI Model Performance Comparison Across All Experiments',
                 fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Saved model comparison: {output_path}")
    plt.close()

def print_summary_table(results_df):
    """Print a summary table to console."""
    print("\n" + "="*120)
    print("AI SECURITY RESEARCH - SUCCESS RATES BY EXPERIMENT TYPE AND MODEL")
    print("="*120)
    print(f"\n{'Experiment':<30} {'Model':<20} {'Auth Disc':<15} {'Deser Disc':<15} {'Auth Bypass':<15} {'Deser Bypass':<15}")
    print("-"*120)

    for _, row in results_df.iterrows():
        print(f"{row['Experiment']:<30} "
              f"{row['Model']:<20} "
              f"{row['Auth Bypass Discovery']:.0f}% ({row['Auth Bypass Discovery (n)']:<8}) "
              f"{row['Deserialization Discovery']:.0f}% ({row['Deserialization Discovery (n)']:<8}) "
              f"{row['Auth Patch Bypass']:.0f}% ({row['Auth Patch Bypass (n)']:<8}) "
              f"{row['Deser Patch Bypass']:.0f}% ({row['Deser Patch Bypass (n)']:<8})")

    print("="*120 + "\n")

def main():
    """Generate all visualizations."""
    print("Loading data...")
    df = load_data()

    print("Calculating success rates...")
    results_df = calculate_success_rates(df)

    # Print summary
    print_summary_table(results_df)

    # Generate charts
    output_dir = Path(__file__).parent

    print("\nGenerating visualizations...")
    create_grouped_bar_chart(results_df, output_dir / 'chart_grouped_success_rates.png')
    create_heatmap(results_df, output_dir / 'chart_heatmap.png')
    create_discovery_chart(results_df, output_dir / 'chart_discovery_only.png')
    create_discovery_chart_11_only(results_df, output_dir / 'chart_discovery_11_only.png')
    create_discovery_chart_12_13(results_df, output_dir / 'chart_discovery_12_13.png')
    create_bypass_chart(results_df, output_dir / 'chart_bypass_only.png')
    create_bypass_chart_2_only(results_df, output_dir / 'chart_bypass_2_only.png')
    create_bypass_chart_3_combined(results_df, output_dir / 'chart_bypass_3_combined.png')
    create_model_comparison(df, output_dir / 'chart_model_comparison.png')

    print("\nAll visualizations generated successfully!")
    print(f"Charts saved to: {output_dir}")

if __name__ == '__main__':
    main()
