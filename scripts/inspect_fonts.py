from pptx import Presentation

prs = Presentation(r"D:\sih26155\SIH2026-IDEA-Presentation-Format.pptx")
for idx, slide in enumerate(prs.slides):
    print(f"\n--- Slide {idx+1} ---")
    for s_idx, shape in enumerate(slide.shapes):
        if shape.has_text_frame:
            for p_idx, p in enumerate(shape.text_frame.paragraphs):
                runs_info = [(r.text[:25], r.font.name, r.font.size.pt if r.font.size else "auto", r.font.bold) for r in p.runs]
                if p.text.strip():
                    print(f"  [Shp {s_idx}] {p.text.strip()[:40]} | Runs: {runs_info}")
