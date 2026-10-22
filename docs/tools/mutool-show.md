% MUTOOL-SHOW(1) | MuPDF tool manual
% MuPDF is Copyright 2004-2026 Artifex Software
% June 3, 2026

# mutool show

## NAME
mutool-show - pretty-print PDF objects from a PDF file

## SYNOPSIS

> **mutool show** [*options*] *input.pdf* *...*

## DESCRIPTION

The show command will print the specified PDF objects and streams to
stdout. Streams are decoded and non-printable characters are
represented with a period by default.

## OPTIONS

The options are:

**-p** *password*
: Use the specified password if the file is encrypted.

**-o** *output*
: The output file name instead of using stdout. Should be a plain text file format.

**-e**
: Leave stream contents in their original form.

**-b**
: Print only stream contents, as raw binary data.

**-g**
: Print only object (ignoring any stream contents), one line per object, suitable for grep.

**-r**
: Force repair before showing any objects.

**-L**
: Show object labels (how to reach an object from the root object)

**--external-access**
: Allow access to current directory containing file for external resources.

*input.pdf*
: Input file name. Must be a PDF file.

Specify what to show by using one of the following keywords, or a path to an object:

**trailer**
: Print the trailer dictionary.

**xref**
: Print the cross reference table.

**pages**
: List the object numbers for every page.

**grep**
: Print all the objects in the file in a compact one-line format suitable
for piping to grep.

**outline**
: Print the outline (also known as "table of contents" or "bookmarks").

**js**
: Print document level Javascript.

**form**
: Print form objects.

a path
: A path starts with either an object number, a property in the trailer
dictionary, or the keyword **trailer** or **pages**. Separate elements with
a period **.** or slash **/**. Select a page object by using pages/N where N
is the page number. The first page is number 1.

**\***
: You can use **\*** as a wildcard to iterate over all array indices or
dictionary properties in an object.

## Examples

Find the number of pages in a document:

	mutool show input.pdf trailer/Root/Pages/Count

Print the content stream data of the first page:

	mutool show -b input.pdf pages/1/Contents

Print the names of all the font resources on all the pages:

	mutool show input.pdf pages/*/Resources/Font/*/BaseFont

Show all JPEG compressed stream objects:

	mutool show input.pdf grep | grep '/Filter/DCTDecode'
