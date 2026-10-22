% MUTOOL-BAKE(1) | MuPDF tool manual
% MuPDF is Copyright 2004-2026 Artifex Software
% June 3, 2026

# mutool bake

## NAME
mutool-bake - bake forms into PDF content

## SYNOPSIS

> **mutool bake** [*options*] *input.pdf* [*output.pdf*]

## DESCRIPTION

The bake command bakes PDF forms into static content.

## OPTIONS

The options are:

**-A**
: Do not bake annotations into page contents.

**-F**
: Do not bake form fields widgets into page contents.

**-O** *options*
: Comma-separated list of options for output format,
: see [PDF write options](/reference/common/pdf-write-options). If none are given **garbage** is used by default.

**-u** (**View**|**Print**)
: Set the PDF usage mode used to determine visibility of annotations.
: Defaults to "View".

*input.pdf*
: Name of input PDF file.

*output.pdf*
: Name of output PDF file. If none is given "out.pdf" is used by default.

Normally annotations and form field widgets are separate content streams
that get drawn on top of the page contents. This command bakes
annotations and/or widgets into the page contents, making them
inseparable. After baking in annotations and widgets they are just
visual representations of what the original annotation/widget looked
like, their properties can no longer be edited since they no longer
exist as proper annotation/widgets.

## SEE ALSO
[**mutool-pdfwrite-options**(1)](../reference/common/pdf-write-options.md)
