"""Draws the pipeline architecture figure (blue/black only) -> results/fig_architecture.png"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

plt.rcParams["font.family"] = "serif"
BLUE, LIGHT, BLACK = "#1f3a93", "#dce6f5", "#000000"
fig, ax = plt.subplots(figsize=(7.2, 3.6))
ax.set_xlim(0, 100); ax.set_ylim(0, 52); ax.axis("off")

def box(x, y, w, h, text, defense=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.4,rounding_size=1.2",
                 fc=BLUE if defense else LIGHT, ec=BLACK, lw=1))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=7.2,
            color="white" if defense else BLACK)

def arrow(x1, y1, x2, y2):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1), arrowprops=dict(arrowstyle="->", color=BLACK, lw=1))

# row 1
box(1, 36, 17, 11, "Attacker plants\npoisoned document\n(web page, PDF, wiki)")
box(25, 36, 17, 11, "Knowledge base\n(TF-IDF index)")
box(49, 36, 17, 11, "Retriever\n(top-3 chunks)")
box(73, 36, 17, 11, "User question")
arrow(18.5, 41.5, 24.5, 41.5); arrow(42.5, 41.5, 48.5, 41.5); arrow(72.5, 41.5, 66.5, 41.5)
# row 2
box(1, 12, 17, 11, "D1 Detector\n(risk score, decode\nbase64, Hindi)", True)
box(21, 12, 17, 11, "D2 Sanitizer\n(strip hidden text,\nblacklist, links)", True)
box(41, 12, 17, 11, "D3 Spotlighting\n(random markers,\ndatamarking)", True)
box(61, 12, 17, 11, "LLM\n(simulated,\nobeys some injections)")
box(81, 12, 17, 11, "D4 Output guard\n(secret, link,\nimage checks)", True)
arrow(57.5, 36, 9.5, 23.5)   # retriever to D1
arrow(18.5, 17.5, 20.5, 17.5); arrow(38.5, 17.5, 40.5, 17.5); arrow(58.5, 17.5, 60.5, 17.5); arrow(78.5, 17.5, 80.5, 17.5)
arrow(81.5, 36, 69.5, 23.5)  # question to LLM
ax.text(89.5, 5, "Final answer\nto the user", ha="center", fontsize=7.5)
arrow(89.5, 11.5, 89.5, 8.5)
ax.text(50, 1.5, "Dark blue boxes = defense layers added by us", ha="center", fontsize=7.5, style="italic")
fig.tight_layout(); fig.savefig("results/fig_architecture.png", dpi=200); plt.close(fig)
