import json
import matplotlib.pyplot as plt
import numpy as np
import os

MEASUREMENT_FILE = "runtimes.json"
CRITERION_DIR = "../target/criterion"

# Maps criterion group name -> (scheme, group) in runtimes.json
CRITERION_GROUPS = {
    "signing":          ("airbb", "signing"),
    "blind_signing":    ("airbb", "blind_signing"),
    "present":          ("airbb", "present"),
    "verify_present":   ("airbb", "verify_present"),
    "bbs_signing":      ("bbs",   "signing"),
    "bbs_blind_signing":("bbs",   "blind_signing"),
    "bbs_present":      ("bbs",   "present"),
    "bbs_verify_present":("bbs",  "verify_present"),
}

def update_runtimes_from_criterion():
    with open(MEASUREMENT_FILE) as f:
        data = json.load(f)

    for crit_group, (scheme, group) in CRITERION_GROUPS.items():
        group_dir = os.path.join(CRITERION_DIR, crit_group)
        if not os.path.isdir(group_dir):
            print(f"skipping {crit_group}: no criterion data found")
            continue
        for attr in os.listdir(group_dir):
            estimates_path = os.path.join(group_dir, attr, "new", "estimates.json")
            if not os.path.isfile(estimates_path):
                continue
            with open(estimates_path) as f:
                est = json.load(f)
            ns = est["mean"]["point_estimate"]
            ms = round(ns / 1_000_000, 3)
            data[scheme][group][attr] = ms

    with open(MEASUREMENT_FILE, "w") as f:
        json.dump(data, f, indent=2)
    print(f"updated {MEASUREMENT_FILE}")


COLOR_PALETTE = ['#88CCEE','#CC6677','#DDCC77','#117733', '#332288','#AA4499','#44AA99', '#999933']
COLOR_AIRBB = '#88CCEE'  # blue  — our scheme
COLOR_BBS   = '#CC6677'  # red   — BBS

ATTR_COUNTS = [1, 10, 25, 50, 100]


def get_measurements(scheme, group):
    with open(MEASUREMENT_FILE) as f:
        data = json.load(f)
    group_data = data.get(scheme, {}).get(group, {})
    measurements = []
    for n in ATTR_COUNTS:
        measurements.append(group_data[str(n)])
    return measurements

def set_plot_theme():
    plt.rc('text', usetex=True)
    plt.rc('font', family='serif', size=15)
    plt.rc('figure', figsize=(5.5, 4))
    plt.rc('text.latex', preamble=r'\usepackage{mathptmx}')


def _plot_line(ax, measurements, color, linestyle, label):
    ax.plot(
        ATTR_COUNTS, measurements,
        color=color, linestyle=linestyle,
        marker='o', markersize=4, linewidth=1.5,
        label=label,
    )

# ---------------------------------------------------------------------------
# Figure: Signing
# ---------------------------------------------------------------------------

def plot_signing():
    airbb_signing = get_measurements("airbb", "signing")
    airbb_blind   = get_measurements("airbb", "blind_signing")
    bbs_signing   = get_measurements("bbs", "signing")
    bbs_blind     = get_measurements("bbs", "blind_signing")

    set_plot_theme()
    fig, ax = plt.subplots(figsize=(5.5, 4.075))

    _plot_line(ax, airbb_signing, COLOR_AIRBB, '-',  r'AirBB issuance')
    _plot_line(ax, airbb_blind,   COLOR_AIRBB, '--', r'AirBB blind issuance')
    _plot_line(ax, bbs_signing,   COLOR_BBS,   '-',  r'BBS issuance')
    _plot_line(ax, bbs_blind,     COLOR_BBS,   '--', r'BBS blind issuance')

    ax.set_xlabel('Number of attributes')
    ax.set_ylabel('Time (ms)')
    # ax.set_xscale('log')
    # ax.set_yscale('log')
    # ax.set_xticks(range(0, 101, 25))  # 0, 5, 10, 15, ..., 100
    ax.set_ylim(top=5)
    ax.legend(fontsize=11, loc='upper left')
    ax.grid(True, which='both', linestyle=':', linewidth=0.5, alpha=0.7)

    fig.tight_layout()
    out = os.path.join(os.path.dirname(__file__), 'issuance.pdf')
    fig.savefig(out)

def plot_presenting():
    airbb_present = get_measurements("airbb", "present")
    airbb_verify_present  = get_measurements("airbb", "verify_present")
    bbs_present   = get_measurements("bbs", "present")
    bbs_verify_present     = get_measurements("bbs", "verify_present")

    set_plot_theme()
    fig, ax = plt.subplots(figsize=(5.5, 4.075))

    _plot_line(ax, airbb_present, COLOR_AIRBB, '-',  r'AirBB present')
    _plot_line(ax, airbb_verify_present,   COLOR_AIRBB, '--', r'AirBB verify')
    _plot_line(ax, bbs_present,   COLOR_BBS,   '-',  r'BBS present')
    _plot_line(ax, bbs_verify_present,     COLOR_BBS,   '--', r'BBS verify')

    ax.set_xlabel('Number of attributes')
    ax.set_ylabel('Time (ms)')
    # ax.set_xscale('log')
    # ax.set_yscale('log')
    # ax.set_xticks(range(0, 101, 25))  # 0, 5, 10, 15, ..., 100
    ax.set_ylim(top=5)
    ax.legend(fontsize=11)
    ax.grid(True, which='both', linestyle=':', linewidth=0.5, alpha=0.7)

    fig.tight_layout()
    out = os.path.join(os.path.dirname(__file__), 'presentation.pdf')
    fig.savefig(out)


# ---------------------------------------------------------------------------

if __name__ == '__main__':
    # update_runtimes_from_criterion()
    plot_signing()
    plot_presenting()
