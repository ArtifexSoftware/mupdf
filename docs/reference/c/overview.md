# Introduction

This is the MuPDF C API guide for developers. In this document we will guide
you through the public and stable bits of the MuPDF library. This is intended
to both provide an introduction to new developers wanting to use low level
features of MuPDF, and as a reference guide to the public interface.

We will be explaining the basics, enough to get you started on a single
threaded application. There are more functions and data structures used
internally, and there are also ways to use MuPDF from multiple threads, but
those are beyond the scope of this document.

The functions and structures documented in this document are what we consider
stable APIs. They will rarely change, and if they do, any such changes will be
noted in the "api-changes" document along with instructions for how to update
your code.

The MuPDF fitz library is the core C API for rendering and manipulating PDF,
XPS, EPUB, and other document formats. The public API is exposed through the
`include/mupdf/fitz/` header files, all of which are collected under the
umbrella header `mupdf/fitz.h`.

If you wonder where the prefix "fz" and name Fitz come from, MuPDF originally
started out as a prototype of a new rendering library architecture for
Ghostscript. It was to be a fusion of libart and Ghostscript. History turned
out differently, and the project mutated into a standalone PDF renderer now
called MuPDF. The "fz" prefix for the graphics library and core modules remains
to this day.

## Components

The library is organised into functional groups:

[Core](core.md)
: The core contains the runtime context, exception handling, and various string
manipulation, math, hash table, binary tree, and other useful functions.
: There's also several [useful utilities ](core-extra.md) that are normally
not needed when using the library, but may be of use anyway.

[Data](data.md)
: Structures and functions for buffers of data, reading
and writing to streams, compression, decompression, encryption,
and file archives.

[Graphics](graphics.md)
: Graphic resource objects like colors, color spaces, vector paths, fonts,
shadings, images, bitmaps, halftoning.

[Device interface](device.md)
: Devices are how graphic content is processed in MuPDF. There are devices
that render to graphics, convert to plain text, analyze page contents,
and record operations in display lists for playback.

[Document](document.md)
: Documents, pages, links, outlines, bookmarks, structured text, all that fun stuff.

[Layout](layout.md)
: Formatting and styling HTML documents using CSS.

Parsers
: Parsing PDF, XPS, SVG, HTML, EPUB, and other file formats.

[Writers](writers.md)
: Converting parsed graphics and/or structured text into other document formats.

[PDF](pdf.js)
: Filling forms, creating and editing annotations, applying redactions, filtering contents.
