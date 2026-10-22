% MUTOOL-EXTRACT(1) | MuPDF tool manual
% MuPDF is Copyright 2004-2026 Artifex Software
% June 3, 2026

# mutool extract

## NAME
mutool-extract - extract images and fonts from a PDF

## SYNOPSIS

> **mutool extract** [*options*] *input.pdf* [*object number* *...*]

## DESCRIPTION

The extract command extracts images, fonts and embedded files from a PDF file.
If no object numbers are specified, all images, fonts and embedded files will
be extracted. All files are saved to the current directory.

## OPTIONS

The options are:

**-p** *password*
: Use the specified password if the file is encrypted.

**-r**
: Convert images to RGB when extracting them.

**-a**
: Embed SMasks as alpha channel.

**-N**
: Do not use ICC color conversions.

*input.pdf*
: Input file name. Must be a PDF file.

[*object numbers*]
: An array of object ids to extract from. If no object numbers are given
on the command line, all images and fonts will be extracted from the
file.
