---
title: MUTOOL-PDF-OPTIONS(1)
header: MuPDF tool manual
author: MuPDF is Copyright 2004-2026 Artifex Software
date: June 3, 2026
name: MuPDF PDF writer options
seealso:
- "**mutool-docwriter-options**(1)"
- "**mutool-option-strings**(1)"
- "**mutool-search-options**(1)"
- "**mutool-stext-options**(1)"
- "**mutool-tablehunt-options**(1)"
---

# PDF Write Options

These are the common options to functions that write PDF files.

The options are specified using an <a href="option-strings.html">option string</a> of key-value pairs.

**decompress**
: Decompress all streams (except compress-fonts/images).

**compress**
: Compress all streams. Bi-level images are compressed with CCITT Fax and generic data is compressed with flate.

**compress=flate**
: Compress streams with Flate (default).

**compress=brotli**
: Compress streams with Brotli (WARNING: this is a proposed PDF feature).

**compress-fonts**
: Compress embedded fonts.

**compress-images**
: Compress images.

**compress-effort**=*percentage*
: Effort spent compressing, **0** is default, **100** is max effort.

**ascii**
: ASCII hex encode binary streams.

**pretty**
: Pretty-print objects with indentation.

**labels**
: Print object labels.

**linearize**
: Optimize document for progressive loading in web browsers (no longer supported!).

**clean**
: Pretty-print graphics commands in content streams.

**sanitize**
: Sanitize graphics commands in content streams.

**garbage**
: Garbage collect unused objects.

**garbage=compact**
: Garbage collect unused objects, and compact cross reference table.

**garbage=deduplicate**
: Garbage collect unused objects, compact cross reference tables, and remove duplicate objects.

**incremental**
: Write changes as incremental update.

**objstms**
: Use object streams and cross reference streams.

**appearance**=(**yes**|**all**)
: Synthesize just missing, or all, annotation/widget appearance streams.

**continue-on-error**
: Continue saving the document even if there is an error.

**decrypt**
: This option is deprecated: instead of decrypt use **encrypt=none**.

**encrypt**=(**none**|**keep**|**rc4-40**|**rc4-128**|**aes-128**|**aes-256**)
: Write encrypted document (default **keep**).

**permissions**=*number*
: Document permissions to grant when encrypting.

**user-password**=*password*
: Password required to read document.

**owner-password**=*password*
: Password required to edit document.

**regenerate-id**=(**yes**|**no**)
: Regenerate document id (default **yes**).

**reproducible**=(**yes**|**no**)
: Attempt to make writes reproducible (default **no**).
