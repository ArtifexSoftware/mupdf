% MUTOOL-CLEAN(1) | MuPDF tool manual
% MuPDF is Copyright 2004-2026 Artifex Software
% June 3, 2026

# mutool clean

## NAME
mutool-clean - rewrite and repair PDF files

## SYNOPSIS

> **mutool clean** [*options*] *input.pdf* [*output.pdf*] [*pages*]

## DESCRIPTION

The `clean` command pretty prints and rewrites the syntax of a PDF file.
It can be used to repair broken files, expand compressed streams, filter
out a range of pages, etc.

If no output file is specified, it will write the cleaned PDF to "out.pdf"
in the current directory.

## OPTIONS

The options are:

**-p** *password*
: Use the specified password if the file is encrypted.

**-g**
: Garbage collect unused objects.

**-gg**
: In addition to **-g** renumber all objects and compact the cross reference table.

**-ggg**
: In addition to **-gg** merge duplicate objects.

**-gggg**
: In addition to **-ggg** merge duplicate streams.

**-l**
: Linearize PDF to create a "Web Optimized" output file. (No longer supported!)

**-D**
: Save file without encryption.

**-E** *encryption*
: Save file with new encryption (**rc4-40**, **rc4-128**, **aes-128**, or **aes-256**).

**-O** *owner-password*
: Owner password (only if encrypting). This password is required to edit the output file.

**-U** *user-password*
: User password (only if encrypting). This password is required to view the output file.

**-P** *permission*
: Permission flags (only if encrypting). These permissions apply when the output file is viewed.

**-a**
: ASCII hex encode binary streams. Used in conjunction with **-d**, **-i** and **-f** to
ensure that althrough the images and/or fonts are compressed, the resulting file can still
be viewed and edited with a text editor.

**-d**
: Decompress streams. This will make the output file larger, but provides easy access
for reading and editing the contents with a text editor.

**-z**
: Deflate uncompressed streams. If combined with **-d**, any decompressed streams will
be recompressed. If combined with **-a**, the streams will also be hex-encoded after
compression.

**-e** *effort*
: Effort spent compressing the output file. 0 is default amount, otherwise
a percentage of the maximum effort, 1 for minimum and 100 for maximum
effort.

**-f**
: Compress font streams. When used in conjunction with **-d**, leaves fonts
compressed while everything else is decompressed.

**-i**
: Compress image streams. When used in conjunection with **-d**, leaves images
compressed while everything else is decompressed.

**-c**
: Pretty-print graphics commands in content streams.

**-s**
: Sanitize graphics commands in content streams, this means removing invalid or
redundant commands and reordering commands.

**-t**
: Compact PDF object syntax. This saves space.

**-tt**
: Use indented PDF object syntax which is more readable.

**-L**
: Print comments containing labels showing how each object can be reached from the Root.

**-v**
: Transform all text into vector graphics commands.

**-A**
: Create appearance streams for annotations that are missing appearance streams.

**-AA**
: Recreate appearance streams for all annotations.

**-m**
: Preserve metadata.

**-S**
: Subset fonts if possible. (EXPERIMENTAL!)

**-Z**
: Use object streams cross reference streams for extra compression.

**--**((**color**|**gray**)(|**-lossy**|**-lossless**)|**bitonal**)**-image-subsample-method**=*method*
: Set the subsampling method (**average**, or **bicubic**) for the desired
image types, for example color-lossy and bitonal-lossless.

**--**((**color**|**gray**)(|**-lossy**|**-lossless**)|**bitonal**)**-image-subsample-dpi**=*dpi*
: Set the resolution at which to subsample.

**--**((**color**|**gray**)(|**-lossy**|**-lossless**)|**bitonal**)**-image-recompress-method**=*quality*
: Set the recompression quality to either of **never**, **same**, **lossless**,
**jpeg**, **j2k**, **fax**, or **jbig2**.

**--recompress-images-when**=(**smaller**|**always**)
: Recompress images when the rewritten images by the subsampling- or
recompression methods above are **smaller** (default) or **always**
recompress them.

**--structure**=(**keep**|**drop**)
: Keep or drop the structure tree.

**--external-access**
: Allow access to current directory containing file for external resources.

*input.pdf*
: Input file name. Must be a PDF file.

*output.pdf*
: The output file. Must be a PDF file.
: If no output file is specified, it will write the cleaned PDF to
"out.pdf" in the current directory.

*pages*
: Comma-separated list of page numbers and ranges (for example:
1,5,10-15,20-N), where the character N denotes the last page. If no
pages are specified, then all pages will be included.
