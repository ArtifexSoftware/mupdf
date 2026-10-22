% MUTOOL-MERGE(1) | MuPDF tool manual
% MuPDF is Copyright 2004-2026 Artifex Software
% June 3, 2026

# mutool merge

## NAME
mutool-merge - merge several documents into a new document

## SYNOPSIS
> **mutool merge** [**-o** *output.pdf*] [**-O** *options*] (*input.pdf* [*pages*] )+

## DESCRIPTION

The merge command is used to pick out pages from two or more files and
merge them into a new PDF output file.

## OPTIONS

The options are:

**-o** *output.pdf*
: The output filename. Defaults to "out.pdf" if not supplied.

**-O** *options*
: Comma-separated list of output options, see [PDF write options](/reference/common/pdf-write-options).

*input.pdf*
: The first document.

*pages*
: Comma-separated list of page numbers and ranges (for example:
1,5,10-15,20-N), where the character N denotes the last page. If no
pages are specified, then all pages will be included.

You may add as many additional input file and page-list pairs as required to merge multiple documents.

## SEE ALSO
[**mutool-pdfwrite-options**(1)](../reference/common/pdf-write-options.md)
