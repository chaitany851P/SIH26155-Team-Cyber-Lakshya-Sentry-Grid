import os
import sys
import win32com.client

pptx_path = os.path.abspath(r"D:\sih26155\SIH2026_SENTRY_GRID_SUBMISSION.pptx")
pdf_path = os.path.abspath(r"D:\sih26155\SIH2026_SENTRY_GRID_SUBMISSION.pdf")

print(f"Opening {pptx_path}...")
ppt = win32com.client.Dispatch("PowerPoint.Application")
try:
    # 17 = ppSaveAsPDF or 32 = ppSaveAsPDF in different office versions, 32 is standard
    deck = ppt.Presentations.Open(pptx_path, WithWindow=False)
    deck.SaveAs(pdf_path, 32)
    deck.Close()
    print(f"Successfully exported PDF to: {pdf_path}")
    print(f"PDF Size: {os.path.getsize(pdf_path)} bytes")
except Exception as e:
    print(f"Export failed: {e}")
finally:
    ppt.Quit()
