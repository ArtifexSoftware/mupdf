% MUTOOL-PAGES(1) | MuPDF tool manual
% MuPDF is Copyright 2004-2026 Artifex Software
% June 3, 2026

# mutool pages

## NAME
mutool-pages - show information about pages

## SYNOPSIS

> **mutool pages** [*options*] *input.pdf* [*pages*]

## DESCRIPTION

The pages command dumps information about the size and rotation
of pages in the document. Each page box (MediaBox, CropBox, etc.)
is listed, as is the UserUnit if present.

## OPTIONS

The options are:

**-p** *password*
: Use the specified password if the file is encrypted.

*input.pdf*
: Input file name. Must be a PDF file.

*pages*
: Comma-separated list of page numbers and ranges (for example:
1,5,10-15,20-N), where the character N denotes the last page. If no
pages are specified, then all pages will be included.
