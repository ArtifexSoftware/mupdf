#!/usr/bin/env python3
"""
Generate a small multi-version PDF for testing pdf_select_version().

Creates a PDF with 3 versions via incremental updates:
  - Version 2 (oldest): 1 page  ("Page 1 - Version 1")
  - Version 1:          2 pages ("Page 1 - Version 1", "Page 2 - Version 2")
  - Version 0 (latest): 3 pages (adds "Page 3 - Version 3")

Usage: python3 create-multi-version-pdf.py [output.pdf]
"""

import sys

def make_page_stream(page_num, version_num):
    """Create a simple content stream that draws text on a page."""
    text = f"Page {page_num} - Version {version_num}"
    return (
        f"BT\n"
        f"/F1 24 Tf\n"
        f"72 720 Td\n"
        f"({text}) Tj\n"
        f"ET\n"
    ).encode()

def write_obj(f, num, gen, data):
    """Write a PDF object and return its file offset."""
    offset = f.tell()
    f.write(f"{num} {gen} obj\n".encode())
    f.write(data)
    f.write(b"\nendobj\n")
    return offset

def write_stream_obj(f, num, gen, dictionary, stream_data):
    """Write a PDF stream object and return its file offset."""
    offset = f.tell()
    length = len(stream_data)
    f.write(f"{num} {gen} obj\n".encode())
    f.write(f"<< {dictionary} /Length {length} >>\n".encode())
    f.write(b"stream\n")
    f.write(stream_data)
    f.write(b"\nendstream\n")
    f.write(b"endobj\n")
    return offset

def write_xref_and_trailer(f, offsets, size, root_num, prev=None):
    """Write xref table and trailer, return startxref offset."""
    xref_offset = f.tell()
    f.write(b"xref\n")

    # Group consecutive object numbers into subsections
    nums = sorted(offsets.keys())
    groups = []
    for n in nums:
        if groups and n == groups[-1][-1] + 1:
            groups[-1].append(n)
        else:
            groups.append([n])

    for group in groups:
        f.write(f"{group[0]} {len(group)}\n".encode())
        for n in group:
            f.write(f"{offsets[n]:010d} 00000 n \n".encode())

    f.write(b"trailer\n")
    trailer = f"<< /Size {size} /Root {root_num} 0 R"
    if prev is not None:
        trailer += f" /Prev {prev}"
    trailer += " >>\n"
    f.write(trailer.encode())
    f.write(b"startxref\n")
    f.write(f"{xref_offset}\n".encode())
    f.write(b"%%EOF\n")
    return xref_offset


def main():
    output = sys.argv[1] if len(sys.argv) > 1 else "multi-version.pdf"

    with open(output, "wb") as f:
        # ============================================================
        # BASE VERSION (version 2 / oldest): 1 page
        # ============================================================
        # Object layout:
        #   1 = Catalog
        #   2 = Pages
        #   3 = Page 1
        #   4 = Page 1 content stream
        #   5 = Font resource (Helvetica)
        f.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

        offsets = {}

        # Obj 5: Font
        offsets[5] = write_obj(f, 5, 0,
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

        # Obj 4: Page 1 content stream
        stream1 = make_page_stream(1, 1)
        offsets[4] = write_stream_obj(f, 4, 0, "", stream1)

        # Obj 3: Page 1
        offsets[3] = write_obj(f, 3, 0,
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>")

        # Obj 2: Pages (1 page)
        offsets[2] = write_obj(f, 2, 0,
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")

        # Obj 1: Catalog
        offsets[1] = write_obj(f, 1, 0,
            b"<< /Type /Catalog /Pages 2 0 R >>")

        prev_xref = write_xref_and_trailer(f, offsets, 6, 1)

        # ============================================================
        # INCREMENTAL UPDATE 1 (version 1): add page 2
        # ============================================================
        # New objects:
        #   6 = Page 2
        #   7 = Page 2 content stream
        # Updated objects:
        #   2 = Pages (now 2 kids, count=2)
        offsets2 = {}

        stream2 = make_page_stream(2, 2)
        offsets2[7] = write_stream_obj(f, 7, 0, "", stream2)

        offsets2[6] = write_obj(f, 6, 0,
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Contents 7 0 R /Resources << /Font << /F1 5 0 R >> >> >>")

        # Updated Pages with 2 kids
        offsets2[2] = write_obj(f, 2, 0,
            b"<< /Type /Pages /Kids [3 0 R 6 0 R] /Count 2 >>")

        prev_xref = write_xref_and_trailer(f, offsets2, 8, 1, prev=prev_xref)

        # ============================================================
        # INCREMENTAL UPDATE 2 (version 0 / latest): add page 3
        # ============================================================
        # New objects:
        #   8 = Page 3
        #   9 = Page 3 content stream
        # Updated objects:
        #   2 = Pages (now 3 kids, count=3)
        offsets3 = {}

        stream3 = make_page_stream(3, 3)
        offsets3[9] = write_stream_obj(f, 9, 0, "", stream3)

        offsets3[8] = write_obj(f, 8, 0,
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Contents 9 0 R /Resources << /Font << /F1 5 0 R >> >> >>")

        # Updated Pages with 3 kids
        offsets3[2] = write_obj(f, 2, 0,
            b"<< /Type /Pages /Kids [3 0 R 6 0 R 8 0 R] /Count 3 >>")

        write_xref_and_trailer(f, offsets3, 10, 1, prev=prev_xref)

    print(f"Created {output} with 3 versions (3 pages, 2 pages, 1 page)")


if __name__ == "__main__":
    main()
