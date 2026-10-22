% MUTOOL-RECOLOR(1) | MuPDF tool manual
% MuPDF is Copyright 2004-2026 Artifex Software
% June 3, 2026

# mutool recolor

## NAME

mutool-recolor - change colorspace for objects in a PDF

## SYNOPSIS

> **mutool recolor** [*options*] *file*

## DESCRIPTION

Change the color space used in a PDF to a desired one. This command can,
for example, change a color PDF to be all grayscale.

## OPTIONS

The options are:

**-c** *colorspace*
: The desired colorspace used in the output document: **gray** (default),
**rgb** or **cmyk**.

**-o** *output file*
: Use the specified filename for the output PDF file with altered colorspaces.
If not set the default output filename is "out.pdf".

**-r**
: Remove any output intents present in the input file.

*file*
: Input file name. The input must be a PDF file.
