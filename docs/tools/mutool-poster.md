% MUTOOL-POSTER(1) | MuPDF tool manual
% MuPDF is Copyright 2004-2026 Artifex Software
% June 3, 2026

# mutool poster

## NAME
mutool-poster - divide a large poster into pieces

## SYNOPSIS

> **mutool poster** [*options*] *input.pdf* [*output.pdf*]

## DESCRIPTION

The poster command splits each page from the input file into tiles, and puts
each tile on a page of its own in the output file. It's useful for printing a
large page onto smaller pieces of paper that can then be glued together to
create a large poster.

## OPTIONS

The options are:

**-p** *password*
: Use the specified password if the file is encrypted.

**-m** *margin*
: Set the margin (overlap) between pages in points or percent.

**-x** *x-factor*
: How many horizontal columns to divide each page into.

**-y** *y-factor*
: How many vertical rows to divide each page into.

**-r**
: Split horizontally from right to left (default splits from left to right).

*input.pdf*
: The input PDF document.

*output.pdf*
: The output filename. Defaults to "out.pdf" if omitted.
The output file will have x-factor times y-factor number of pages for each page
in the input file.
