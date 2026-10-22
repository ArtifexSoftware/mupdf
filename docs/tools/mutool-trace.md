% MUTOOL-TRACE(1) | MuPDF tool manual
% MuPDF is Copyright 2004-2026 Artifex Software
% June 3, 2026

# mutool trace

## NAME
mutool-trace - trace device calls made when rendering a document

## SYNOPSIS

> **mutool trace** [*options*] *file* [*pages*]

## DESCRIPTION

The trace command prints a trace of all the device calls needed to
render the pages from the given document.

## OPTIONS

The options are:

**-p** *password*
: Use the specified password if the file is encrypted.

**-b** *box*
: Use named page box (**MediaBox**, **CropBox**, **BleedBox**, **TrimBox**, or **ArtBox**).

**-W** *width*
: Page width in points for EPUB layout.

**-H** *height*
: Page height in points for EPUB layout.

**-S** *size*
: Font size in points for EPUB layout.

**-U** *filename*
: User CSS stylesheet for EPUB layout.

**-X**
: Disable document styles for EPUB layout.

**-d**
: Use display list.

*file*
: Input file name. The file can be any of the supported input formats.

*pages*
: Comma-separated list of page numbers and ranges (for example:
1,5,10-15,20-N), where the character N denotes the last page. If no
pages are specified, then all pages will be included.

The trace takes the form of an XML document, with the root element being
the document, its children each page, and one page child element for
each device call on that page.

## An example trace

``` xml
<document filename="hello.pdf">
<page number="1" mediabox="0 0 595 842">
<fill_path winding="nonzero" colorspace="DeviceRGB" color="1 0 0" transform="1 0 0 -1 0 842">
<moveto x="50" y="50"/>
<lineto x="100" y="200"/>
<lineto x="200" y="50"/>
</fill_path>
<fill_text colorspace="DeviceRGB" color="0" transform="1 0 0 -1 0 842">
<span font="Times-Roman" wmode="0" trm="100 0 0 100">
<g unicode="H" glyph="H" x="50" y="500" />
<g unicode="e" glyph="e" x="122.2" y="500" />
<g unicode="l" glyph="l" x="166.6" y="500" />
<g unicode="l" glyph="l" x="194.4" y="500" />
<g unicode="o" glyph="o" x="222.2" y="500" />
<g unicode="!" glyph="exclam" x="272.2" y="500" />
</span>
</fill_text>
</page>
</document>
```
