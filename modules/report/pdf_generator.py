from __future__ import annotations

import re
from pathlib import Path

from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageTemplate,
    Paragraph,
    Spacer,
    PageBreak,
)
from reportlab.lib.colors import HexColor


def _register_font() -> tuple[str, str]:
    """
    Use a Unicode-capable font when available.
    Falls back to ReportLab's built-in Helvetica.
    """

    candidates = [
        # Linux
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",

        # Windows
        r"C:\Windows\Fonts\arial.ttf",

        # ReportLab bundled font
        str(
            Path(__import__("reportlab").__file__).parent
            / "fonts"
            / "Vera.ttf"
        ),
    ]

    bold_candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        r"C:\Windows\Fonts\arialbd.ttf",
        str(
            Path(__import__("reportlab").__file__).parent
            / "fonts"
            / "VeraBd.ttf"
        ),
    ]

    regular = None
    bold = None

    for path in candidates:
        if Path(path).is_file():
            regular = path
            break

    for path in bold_candidates:
        if Path(path).is_file():
            bold = path
            break

    if regular and bold:
        pdfmetrics.registerFont(
            TTFont("DFIRRegular", regular)
        )
        pdfmetrics.registerFont(
            TTFont("DFIRBold", bold)
        )
        return "DFIRRegular", "DFIRBold"

    return "Helvetica", "Helvetica-Bold"


def _escape(text: str, font_regular: str = "DFIRRegular") -> str:
    """
    Escape text for ReportLab Paragraph markup.
    """
    text = (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )

    # Basic Markdown emphasis.
    text = re.sub(
        r"\*\*(.+?)\*\*",
        r"<b>\1</b>",
        text,
    )

    text = re.sub(
        r"`(.+?)`",
        rf'<font name="{font_regular}">\1</font>',
        text,
    )

    return text


def _markdown_to_story(
    markdown_text: str,
    styles,
):
    story = []

    lines = markdown_text.splitlines()

    paragraph_buffer: list[str] = []

    def flush_paragraph():
        if not paragraph_buffer:
            return

        text = " ".join(
            x.strip()
            for x in paragraph_buffer
            if x.strip()
        )

        if text:
            story.append(
                Paragraph(
                    _escape(text),
                    styles["Body"],
                )
            )
            story.append(
                Spacer(1, 4 * mm)
            )

        paragraph_buffer.clear()

    for raw_line in lines:

        line = raw_line.strip()

        # ----------------------------------------------------------
        # Empty line
        # ----------------------------------------------------------
        if not line:
            flush_paragraph()
            continue

        # ----------------------------------------------------------
        # Horizontal rule
        # ----------------------------------------------------------
        if re.fullmatch(
            r"[-*_]{3,}",
            line,
        ):
            flush_paragraph()

            story.append(
                Spacer(1, 2 * mm)
            )
            continue

        # ----------------------------------------------------------
        # Headings
        # ----------------------------------------------------------
        heading = re.match(
            r"^(#{1,4})\s+(.+)$",
            line,
        )

        if heading:

            flush_paragraph()

            level = len(
                heading.group(1)
            )

            text = _escape(
                heading.group(2)
            )

            style_name = {
                1: "H1",
                2: "H2",
                3: "H3",
                4: "H4",
            }.get(
                level,
                "H4",
            )

            story.append(
                Paragraph(
                    text,
                    styles[style_name],
                )
            )

            continue

        # ----------------------------------------------------------
        # Bullet list
        # ----------------------------------------------------------
        bullet = re.match(
            r"^[-*+]\s+(.+)$",
            line,
        )

        if bullet:

            flush_paragraph()

            story.append(
                Paragraph(
                    "• " +
                    _escape(
                        bullet.group(1)
                    ),
                    styles["DFIRBullet"],
                )
            )

            continue

        # ----------------------------------------------------------
        # Numbered list
        # ----------------------------------------------------------
        numbered = re.match(
            r"^\d+\.\s+(.+)$",
            line,
        )

        if numbered:

            flush_paragraph()

            story.append(
                Paragraph(
                    _escape(line),
                    styles["DFIRBullet"],
                )
            )

            continue

        # ----------------------------------------------------------
        # Markdown table separator
        # ----------------------------------------------------------
        if re.fullmatch(
            r"\|?[\s:|-]+\|?",
            line,
        ):
            continue

        # ----------------------------------------------------------
        # Markdown table row
        # ----------------------------------------------------------
        if "|" in line:

            flush_paragraph()

            cells = [
                cell.strip()
                for cell in line.strip("|").split("|")
            ]

            text = "   |   ".join(
                cells
            )

            story.append(
                Paragraph(
                    _escape(text),
                    styles["TableRow"],
                )
            )

            continue

        # ----------------------------------------------------------
        # Normal paragraph
        # ----------------------------------------------------------
        paragraph_buffer.append(
            line
        )

    flush_paragraph()

    return story


def generate_pdf(
    markdown_path: str | Path,
    pdf_path: str | Path,
) -> int:

    markdown_path = Path(
        markdown_path
    )

    pdf_path = Path(
        pdf_path
    )

    pdf_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    font_regular, font_bold = (
        _register_font()
    )

    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="DFIRBullet",
            parent=styles["BodyText"],
            fontName=font_regular,
            fontSize=10.5,
            leading=14,
            leftIndent=7 * mm,
            firstLineIndent=-4 * mm,
            spaceAfter=1.5 * mm,
        )
    )

    styles.add(
        ParagraphStyle(
            name="H1",
            parent=styles["Heading1"],
            fontName=font_bold,
            fontSize=18,
            leading=22,
            spaceBefore=8 * mm,
            spaceAfter=5 * mm,
            textColor=HexColor("#17233A"),
        )
    )

    styles.add(
        ParagraphStyle(
            name="H2",
            parent=styles["Heading2"],
            fontName=font_bold,
            fontSize=14,
            leading=18,
            spaceBefore=6 * mm,
            spaceAfter=3 * mm,
            textColor=HexColor("#234A87"),
        )
    )

    styles.add(
        ParagraphStyle(
            name="H3",
            parent=styles["Heading3"],
            fontName=font_bold,
            fontSize=12,
            leading=16,
            spaceBefore=5 * mm,
            spaceAfter=2 * mm,
            textColor=HexColor("#315B91"),
        )
    )

    styles.add(
        ParagraphStyle(
            name="H4",
            parent=styles["Heading4"],
            fontName=font_bold,
            fontSize=11,
            leading=14,
            spaceBefore=4 * mm,
            spaceAfter=2 * mm,
        )
    )



    styles.add(
        ParagraphStyle(
            name="TableRow",
            parent=styles["BodyText"],
            fontName=font_regular,
            fontSize=9,
            leading=12,
            leftIndent=3 * mm,
            spaceAfter=1.5 * mm,
        )
    )

    styles.add(
        ParagraphStyle(
            name="DFIRTitle",
            parent=styles["Title"],
            fontName=font_bold,
            fontSize=22,
            leading=27,
            alignment=TA_CENTER,
            textColor=HexColor("#17233A"),
            spaceAfter=10 * mm,
        )
    )

    markdown = markdown_path.read_text(
        encoding="utf-8"
    )

    story = []

    story.append(
        Paragraph(
            "DFIR-AI — Rapport d'investigation",
            styles["DFIRTitle"],
        )
    )

    story.append(
        Paragraph(
            "Rapport généré automatiquement à partir "
            "des preuves forensiques analysées.",
            styles["Body"],
        )
    )

    story.append(
        Spacer(1, 5 * mm)
    )

    story.extend(
        _markdown_to_story(
            markdown,
            styles,
        )
    )

    # --------------------------------------------------------------
    # Page numbering
    # --------------------------------------------------------------
    def draw_page_number(canvas, doc):
        canvas.saveState()

        canvas.setFont(
            font_regular,
            8,
        )

        canvas.setFillColor(
            HexColor("#6B7280")
        )

        canvas.drawCentredString(
            A4[0] / 2,
            12 * mm,
            f"Page {doc.page}",
        )

        canvas.restoreState()

    frame = Frame(
        20 * mm,
        18 * mm,
        A4[0] - 40 * mm,
        A4[1] - 36 * mm,
        id="normal",
    )

    document = BaseDocTemplate(
        str(pdf_path),
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="DFIR-AI Report",
        author="DFIR-AI",
    )

    document.addPageTemplates(
        [
            PageTemplate(
                id="DFIR",
                frames=[frame],
                onPage=draw_page_number,
            )
        ]
    )

    document.build(
        story
    )

    # Determine actual generated page count.
    try:
        from pypdf import PdfReader

        return len(
            PdfReader(
                str(pdf_path)
            ).pages
        )

    except Exception:
        return 0