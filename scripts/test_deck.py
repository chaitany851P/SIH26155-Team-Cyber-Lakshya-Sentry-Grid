import os
import sys
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN

TEMPLATE_PATH = r"D:\sih26155\SIH2026-IDEA-Presentation-Format.pptx"
OUTPUT_PATH = r"D:\sih26155\SIH2026_SENTRY_GRID_SUBMISSION.pptx"
ARCH_IMG = r"D:\sih26155\assets\sentrygrid_architecture_visual.jpg"
UI_IMG = r"D:\sih26155\assets\sentrygrid_dashboard_ui.jpg"

prs = Presentation(TEMPLATE_PATH)
print(f"Loaded template with {len(prs.slides)} slides.")

# Slide 7 is the instructions slide. We need to delete it.
# In python-pptx, deleting a slide:
# rId = prs.slides._sldIdLst[6].rId
# prs.part.drop_rel(rId)
# del prs.slides._sldIdLst[6]
if len(prs.slides) > 6:
    rId = prs.slides._sldIdLst[6].rId
    prs.part.drop_rel(rId)
    del prs.slides._sldIdLst[6]
    print("Deleted Slide 7 (Instructions slide).")

print(f"Remaining slides: {len(prs.slides)}")
prs.save(OUTPUT_PATH)
print("Saved temporary test file.")
