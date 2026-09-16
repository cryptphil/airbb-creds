import matplotlib.pyplot as plt
import numpy as np
import os


def set_plot_theme():
    plt.rc('text', usetex=True)
    plt.rc('font', family='serif', size=15)
    plt.rc('figure', figsize=(5.5,4))
    plt.rc('text.latex', preamble=r'\usepackage{mathptmx}')

COLOR_AIRBB = 'blue'    # our scheme
COLOR_BBS   = 'red'    # BBS
COLOR_PS   = 'green'   # PS
COLOR_MONI = 'purple'  # MoniPoly
COLOR_SPS  = 'orange'  # SPS

# Proof size formulas for each scheme, as a function of the number of
# disclosed/hidden attributes n. Sizes are in bytes.

# Sizes of field elements and group elements in bytes.
fel = 32
g1el = 48
g2el = 96

def proof_size_bbs(n):
    return 2*g1el + (3+ n)*fel

def proof_size_ps(n):
    return 2*g1el + (2 + n)*fel

def proof_size_hoeteck(n):
    return 2*g1el + (2+ n)*fel

def proof_size_monipoly(n):
    # Constant in n: a commitment plus a fixed-size proof, independent of
    # the number of attributes.
    return np.full_like(n, 3*g1el + g2el + fel + 8*fel)

def proof_size_sps(n):
    return np.full_like(n, 3*g1el + g2el + 5*fel)

def proof_size_bb(n):
    return np.full_like(n, 3*g1el + g2el)

# Range of attribute counts relevant for identity-type attribute credentials.
attributes = np.arange(1, 51)

sizes_1 = proof_size_bbs(attributes)
sizes_2 = proof_size_ps(attributes)
sizes_3 = proof_size_monipoly(attributes)
sizes_4 = proof_size_sps(attributes)
sizes_5 = proof_size_bb(attributes)

set_plot_theme()

plt.plot(attributes, sizes_1, color=COLOR_BBS, label="BBS")
plt.plot(attributes, sizes_2, color=COLOR_PS, label="PS")
plt.plot(attributes, sizes_3, color=COLOR_MONI, label="MoniPoly")
plt.plot(attributes, sizes_4, color=COLOR_SPS, label="SPS")
plt.plot(attributes, sizes_5, color=COLOR_AIRBB, label="AirBB")

plt.xlabel("Number of hidden attributes")
plt.ylabel("Presentation size (bytes)")
plt.legend()
plt.grid(True)

plt.tight_layout()
out = os.path.join(os.path.dirname(__file__), 'proof_size_comparison.pdf')
plt.savefig(out)