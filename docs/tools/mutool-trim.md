% MUTOOL-TRIM(1) | MuPDF tool manual
% MuPDF is Copyright 2004-2026 Artifex Software
% June 3, 2026

# mutool trim

## NAME
mutool-trim - remove PDF page contents inside/outside a box

## SYNOPSIS

> **mutool trim** [*options*] *input.pdf*

## DESCRIPTION

This command makes a modified version of a PDF with content
that falls inside or outside of various "boxes" removed.

See [mutool pages](/tools/mutool-pages.md) for how to list out the boxes used on a page.

## OPTIONS

The options are:

**-b** *box*
: Which page box to trim to (**MediaBox** (default), **CropBox**, **BleedBox**, **TrimBox**, or **ArtBox**).

**-f**
: Fallback to mediabox if specified box not available.

**-m** *margin*
: Add the same margins to all sides of the box, where *margin* is positive for
inwards, and negative for outwards.

**-m** *vertical-margin,horizontal-margin*
: Add the specified vertical and horizontal margins, where *vertical-margin*
and *horizontal-margin* is positive for inwards, and negative for outwards.

**-m** *top-margin,right-margin,bottom-margin,left-margin*
: Add the specified margins for top, right, bottom and left sides of the box,
where the margins are positive for inwards, and negative for outwards.

**-e**
: Exclude contents of box, rather than include them.

**-o** *filename*
: Output file.

## Examples

Trim a document by trimming the MediaBox elements with a margin of 200
points inwards:

	mutool trim -b mediabox -m 200 -o out.pdf in.pdf

Trim a document by trimming the MediaBox elements with a margin of 20
points from the top & bottom (vertical) and 30 points from the left &
right (horizontal):

	mutool trim -b mediabox -m 20,30 -o out.pdf in.pdf

Trim a document by trimming the MediaBox elements to a box offset 10
points from the top & right, 50 points from the bottom and 20 points in
from the left:

	mutool trim -b mediabox -m 10,10,50,20 -o out.pdf in.pdf

Exclude the contents of the ArtBox element:

	mutool trim -b artbox -e -o out.pdf in.pdf

## SEE ALSO
[**mutool-pages**(1)](mutool-pages.md)
