import os
from pptx import Presentation

pptx_path = r"D:\sih26155\SIH2026-IDEA-Presentation-Format.pptx"
prs = Presentation(pptx_path)

for i, slide in enumerate(prs.slides):
    print(f"\n==================== SLIDE {i+1} ====================")
    for idx, shape in enumerate(slide.shapes):
        has_tf = shape.has_text_frame
        paras = []
        if has_tf:
            paras = [p.text.strip() for p in shape.text_frame.paragraphs if p.text.strip()]
        print(f"Shape {idx}: ID={shape.shape_id}, Name='{shape.name}', Type={shape.shape_type}")
        print(f"   Pos: left={shape.left.inches:.2f}\", top={shape.top.inches:.2f}\", w={shape.width.inches:.2f}\", h={shape.height.inches:.2f}\"")
        if paras:
            print(f"   Text: {paras}")
