import os
import sys
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR

TEMPLATE_PATH = r"D:\sih26155\SIH2026-IDEA-Presentation-Format.pptx"
OUTPUT_PATH = r"D:\sih26155\SIH2026_SENTRY_GRID_SUBMISSION.pptx"
ARCH_IMG = r"D:\sih26155\assets\sentrygrid_architecture_visual.jpg"
UI_IMG = r"D:\sih26155\assets\sentrygrid_dashboard_ui.jpg"

prs = Presentation(TEMPLATE_PATH)

# 1. Delete Slide 7
if len(prs.slides) > 6:
    rId = prs.slides._sldIdLst[6].rId
    prs.part.drop_rel(rId)
    del prs.slides._sldIdLst[6]
    print("Deleted Slide 7.")

# Color constants
COLOR_NAVY = RGBColor(10, 37, 64)       # Deep professional navy
COLOR_BLUE = RGBColor(0, 102, 204)      # Tech accent blue
COLOR_DARK = RGBColor(30, 41, 59)       # Slate dark text
COLOR_MUTED = RGBColor(100, 116, 139)   # Slate gray
COLOR_GREEN = RGBColor(16, 149, 103)    # Emerald green accent
COLOR_RED = RGBColor(220, 38, 38)       # Red accent

def format_title(shape, text):
    tf = shape.text_frame
    tf.word_wrap = True
    tf.text = text
    p = tf.paragraphs[0]
    p.font.name = "Arial"
    p.font.size = Pt(28)
    p.font.bold = True
    p.font.color.rgb = COLOR_NAVY

def clear_text_frame(tf):
    for i in range(len(tf.paragraphs)-1, -1, -1):
        p = tf.paragraphs[i]
        p.text = ""

print("Helper functions ready.")
