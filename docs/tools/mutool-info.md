% MUTOOL-INFO(1) | MuPDF tool manual
% MuPDF is Copyright 2004-2026 Artifex Software
% June 3, 2026

# mutool info

## NAME
mutool-info - shows fonts/images/etc on each page in a PDF

## SYNOPSIS
> **mutool info** [*options*] *file* [*pages*]

## DESCRIPTION

The info command lists the resources used on each page in a PDF file. For each
page the page's object number is shown, and then detailed information about the
desired resource types. The default is to list all resource types, but if one
or more flags are given, only the specified types will be shown.

## OPTIONS

The options are:

**-p** *password*
: Use the specified password if the file is encrypted.

**-F**
: List fonts.

**-I**
: List images.

**-M**
: List dimensions.

**-P**
: List patterns.

**-S**
: List shadings.

**-X**
: List form and postscript XObjects.

**-Z**
: List ZUGFeRD info.

*file*
: The input file.

[*pages*]
: Comma-separated list of page numbers and ranges (for example:
1,5,10-15,20-N), where the character N denotes the last page. If no
pages are specified, then all pages will be included.
