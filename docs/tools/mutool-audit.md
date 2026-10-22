% MUTOOL-AUDIT(1) | MuPDF tool manual
% MuPDF is Copyright 2004-2026 Artifex Software
% June 3, 2026

# mutool audit

## NAME
mutool-audit - report operator and space use

## DESCRIPTION

The audit command prints a report of operator and space usage for a
PDF file.

## SYNOPSIS

> **mutool audit** [*options*] *file*

## OPTIONS

The options are:

**-o** *output-file*
: Use the specified filename for the produced HTML report.

**file**
: Input file name. The input must be a PDF file.

The report takes the form of an HTML document. The report assumes a fair
degree of familiarity with the PDF format.

The first section of the file gives figures for the proportions of the
file that are objects vs the overheads for storing those objects, for
both objects inside and outside of ObjStms. It also lists the size of as
a percentage of the whole file.

The second section of the file gives figures for the usage of the
different objects within the file. The classification of objects is
simplistic, but works in most cases.

The final section of the file gives figures for the frequency of use of
different graphical operators within operator streams. These figures
should be taken as being indicative, rather than 100% accurate.
