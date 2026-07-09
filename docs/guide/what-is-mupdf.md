# What is MuPDF?

MuPDF is an open-source software library for working with a wide range of document formats.
Typical tasks include:
rendering,
converting to other formats,
extracting resources,
extracting plain text,
filling out forms,
adding annotations,
redacting sensitive information,
reordering and removing pages,
and much more.

## Formats

As you can tell by the name, we support reading PDF files. But that's not all!
We also handle XPS and various E-book formats.
There is also limited support for reading Office format documents.

- PDF
- XPS and OpenXPS
- EPUB (DRM-free 2.0, limited support for 3.0)
- Mobipocket (MOBI)
- FictionBook 2 (FB2)
- ComicBook (CBZ and CBT)
- Images (TIFF, JPEG, PNG, etc)
- SVG (a limited subset only)
- Markdown (MD)

## Command Line Tools

The command line tools are all gathered into one umbrella command: [`mutool`](../tools/mutool.rst).
This swiss army knife has a lot of sub-commands for performing different
tasks on PDF documents.

### Rendering & Conversion

MuPDF can be used to render pages to images; or to convert a document into a multitude of other formats.
This is an entirely visual conversion; metadata and other non-visible content will NOT be preserved.

These two tools provide this functionality. They both use the same conversion under the hood, but provide
separate sets of command line options to fit different use cases.

[`mutool draw`](../tools/mutool-draw.rst)
: Render or convert a document into various image formats, with lots of fine-grained control over the rendering.

[`mutool convert`](../tools/mutool-convert.rst)
: Batch convert a document into another document format. Easy to use, with only a few options.

See [document writer options](../reference/common/document-writer-options.md) and
[PDF write options](../reference/common/pdf-write-options.md) to learn how to
control the conversion behavior.

### Extraction

[`mutool draw`](../tools/mutool-draw.rst) can also be used to extract detailed textual information in XML or JSON format:

	mutool draw [-O stext-options] -o output.stext input.pdf
	mutool draw [-O stext-options] -o output.stext.json input.pdf

See [stext-options](../reference/common/stext-options.md) for a description of the available structured text extraction options.

PDF files often have images, fonts, and other embedded files. These can be extracted with [`mutool extract`](../tools/mutool-extract.rst).

### PDF Manipulation

MuPDF has a large toolset for manipulating PDF files on the command line.

[`mutool show`](../tools/mutool-show.rst)
: A tool for displaying the internal objects in a PDF file, useful for inspecting the file structure and to debug problematic files.

[`mutool clean`](../tools/mutool-clean.rst)
: Rewrite a PDF file. Used to fix broken files; or to make a PDF file human editable.

[`mutool create`](../tools/mutool-create.rst)
: Assemble a new PDF file from a text file with graphics commands.

[`mutool merge`](../tools/mutool-merge.rst)
: Merge pages from multiple input files into a new PDF.

[`mutool poster`](../tools/mutool-poster.rst)
: Split large pages of a PDF file into smaller pieces that can be printed on a smaller
paper size. These can then be assembled into a large poster after printing.

[`mutool run`](../tools/mutool-run.rst)
: Run Javascript programs using the MuPDF library with [`mutool run`](../tools/mutool-run.rst).
See the library section below for ways to use MuPDF from other programming languages.

## Viewers

### Desktop

For Linux, Windows and MacOS there are two viewer applications. The main viewer [`mupdf-gl`](../tools/mupdf-gl.rst)
has many features such as a table of contents sidebar, full unicode search, annotation editing, and redaction.
On systems where this viewer cannot be built, the older legacy viewers (mupdf-x11, mupdf-win32) are still supported.

### Android

Android currently has two different viewers with varying degrees of complexity:

[MuPDF viewer](https://play.google.com/store/apps/details?id=com.artifex.mupdf.viewer.app)
A high performance PDF viewer with a smooth and polished interface.

[MuPDF mini](https://play.google.com/store/apps/details?id=com.artifex.mupdf.mini.app)
An example of how to create a PDF viewer with the least amount of code.

### Web browser

There's also a commercial license (trial available) only [MuPDF WebViewer](https://webviewer.mupdf.com/?utm_source=rtd-mupdf&utm_medium=referral&utm_content=page-link&utm_campaign=docs) product. Here is a [demo](https://webviewer.mupdf.com/demo/?utm_source=rtd-mupdf&utm_medium=referral&utm_content=page-link&utm_campaign=docs) of it.

### Third party viewers

A non-exhaustive list of other non-affiliated open source projects that use MuPDF for viewing:

- [SumatraPDF](https://www.sumatrapdfreader.org/download-free-pdf-viewer) for Windows
- [Zathura](https://pwmt.org/projects/zathura/) for Linux
- [llpp](https://repo.or.cz/llpp.git)

## Library

The MuPDF library exposes all the functionality we support, so that
applications built on top of the MuPDF library can do everything the
tools described above can.

### C

The MuPDF library is written in portable C. To learn more about the C interface, read the [MuPDF Explored](../cookbook/mupdf-explored.md) book.

### Javascript

Write Node or browser applications with the mupdf.js Javascript bindings.

There is a library available to use MuPDF from Javascript and Typescript, powered by WebAssembly.
You can use this library to build applications that run in a web browser, or that run server side
using Node. The Javascript library is available as a [module on NPM](https://www.npmjs.com/package/mupdf).

The MuPDF.js library provides the same interface as the `mutool run` scripting tool.

### Java

Use the MuPDF Java library to write applications in Java or to build an Android application.

The Java classes provide an interface very similar to the Javascript library.

If you want to build an application for Android, you can either base it off one
of the existing viewers or build a new app from scratch using the MuPDF library
directly.

### Python

The popular [PyMuPDF library](https://pymupdf.io/?utm_source=rtd-mupdf&utm_medium=referral&utm_content=page-link&utm_campaign=docs) makes it trivial to use MuPDF from Python for extraction, conversion, and rendering alike.
