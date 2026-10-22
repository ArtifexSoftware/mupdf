% MUTOOL-GREP(1) | MuPDF tool manual
% MuPDF is Copyright 2004-2026 Artifex Software
% June 3, 2026

# mutool grep

## NAME
mutool-grep - search text in a document

## SYNOPSIS

> **mutool grep** [*options*] *pattern* *file* [*file2* *...*]

## DESCRIPTION

The grep command searches for text in a document and prints each matching line.

## OPTIONS

The options are:

*pattern*
: A regular expression or string to search for.

*file*
: Document to search in.

**-p** *password*
: Use the specified password if the file is encrypted.

**-F**
: The pattern is a fixed string.

**-a**
: Ignore diacritics and accents (treat ä and a as the same).

**-i**
: Ignore case (treat A and a as the same).

**-H**
: Print filename for each match.

**-n**
: Print page number for each match.

**-S** *search-options*
: Comma-separated list of search options, see [search options](/reference/common/search-options).

**-O** *stext-options*
: Comma-separated list of structured text options, see [structured text options](/reference/common/stext-options).

**-b**
: Search backwards, starting from the end.

**-[** *start-mark*
: Insert mark at the start of each match when printing results.

**-]** *end-mark*
: Insert mark at the end of each match when printing results.

**-v**
: Show verbose search debugging feedback.

**-q**
: Hide all warnings and error messages. Use at your own risk!

## SEE ALSO
[**mutool-search-options**(1)](../reference/common/search-options.md),
[**mutool-stext-options**(1)](../reference/common/stext-options.md)
