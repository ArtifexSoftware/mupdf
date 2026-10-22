---
title: MUTOOL-DOCWRITER-OPTIONS(1)
header: MuPDF tool manual
author: MuPDF is Copyright 2004-2026 Artifex Software
date: June 3, 2026
name: MuPDF document writer options
seealso:
- "**mutool-option-strings**(1)"
- "**mutool-pdfwrite-options**(1)"
- "**mutool-stext-options**(1)"
---

# Document Writer Options

The options are specified using an <a href="option-strings.html">option string</a> of key-value pairs.

## Supported output formats

Raster formats:
: `cbz`, `png`, `pnm`, `pgm`, `ppm`, `pam`, `pbm`, `pkm`

Print-raster formats:
: `pcl`, `pclm`, `ps`, `pwg`

Vector formats:
: `pdf`, `svg`

Text formats:
: `html`, `xhtml`, `text`, `stext`

## Raster output options

**rotate**=*N*
: Rotate rendered pages N degrees counterclockwise.

**resolution**=*N*
: Set both X and Y resolution in pixels per inch.

**x-resolution**=*N*
: X resolution of rendered pages in pixels per inch.

**y-resolution**=*N*
: Y resolution of rendered pages in pixels per inch.

**width**=*N*
: Render pages to fit N pixels wide (ignore resolution option).

**height**=*N*
: Render pages to fit N pixels tall (ignore resolution option).

**colorspace**=(**gray**|**rgb**|**cmyk**)
: Render using specified colorspace.

**alpha**
: Render pages with alpha channel and transparent background.

**graphics**=(**aa***N*|**cop**|**app**)
: Set the rasterizer to use for graphics.
	- **aa***N* Antialias with *N* bits (0 to 8).
	- **cop** Center of pixel.
	- **app** Any part of pixel.

**text**=(**aa***N*|**cop**|**app**)
: Set the rasterizer to use for text.
	- **aa***N* Antialias with *N* bits (0 to 8).
	- **cop** Center of pixel.
	- **app** Any part of pixel.

## PCL output options

**colorspace**=(**mono**|**rgb**)
: Render page as 1-bit black and white or in full color.

**preset**=*value*
: The valid presets are:
	- **generic**
	- **ljet4**
	- **dj500**
	- **fs600**
	- **lj**
	- **lj2**
	- **lj3**
	- **lj3d**
	- **lj4**
	- **lj4pl**
	- **lj4d**
	- **lp2563b**
	- **oce9050**

**spacing**=(**0**|**1**|**2**|**3**)
: Set vertical spacing to:
	- **0** none
	- **1** PCL 3 (`<ESC>*p+\<n\>Y`)
	- **2** PCL 4 (`<ESC>*b\<n\>Y`)
	- **3** PCL 5 spacing (`<ESC>*b\<n\>Y` and clear seed row)

**mode2**
: Enable mode 2 graphics compression.

**mode3**
: Enable mode 3 graphics compression.

**eog_reset**
: End of graphics (`<ESC>*rB)` resets all parameters.

**has_duplex**
: Duplex supported (`<ESC>&l\<duplex\>S`).

**has_papersize**
: Papersize setting supported (`<ESC>&l\<sizecode\>A`).

**has_copies**
: Number of copies supported (`<ESC>&l\<copies\>X`).

**is_ljet4pjl**
: Disable/Enable HP 4PJL model-specific output.

**is_oce9050**
: Disable/Enable Oce 9050 model-specific output.

## PCLm output option

**compression**=(**none**|**flate**)
: No compression (default), or enable flate compression.

**strip-height**=*N*
: Strip height (default 16).

## PDF output options

See <a href="pdf-write-options.html">PDF Write Options</a>.

## PWG output options

**media_class**=*string*
: Set the media\_class field.

**media_color**=*string*
: Set the media\_color field.

**media_type**=*string*
: Set the media\_type field.

**output_type**=*string*
: Set the output\_type field.

**rendering_intent**=*string*
: Set the rendering\_intent field.

**page_size_name**=*string*
: Set the page\_size\_name field.

**advance_distance**=*int*
: Set the advance\_distance field.

**advance_media**=*int*
: Set the advance\_media field.

**collate**=*int*
: Set the collate field.

**cut_media**=*int*
: Set the cut\_media field.

**duplex**=*int*
: Set the duplex field.

**insert_sheet**=*int*
: Set the insert\_sheet field.

**jog**=*int*
: Set the jog field.

**leading_edge**=*int*
: Set the leading\_edge field.

**manual_feed**=*int*
: Set the manual\_feed field.

**media_position**=*int*
: Set the media\_position field.

**media_weight**=*int*
: Set the media\_weight field.

**mirror_print**=*int*
: Set the mirror\_print field.

**negative_print**=*int*
: Set the negative\_print field.

**num_copies**=*int*
: Set the num\_copies field.

**orientation**=*int*
: Set the orientation field.

**output_face_up**=*int*
: Set the output\_face\_up field.

**page_size_x**=*int*
: Set the page\_size\_x field.

**page_size_y**=*int*
: Set the page\_size\_y field.

**separations**=*int*
: Set the separations field.

**tray_switch**=*int*
: Set the tray\_switch field.

**tumble**=*int*
: Set the tumble field.

**media_type_num**=*int*
: Set the media\_type\_num field.

**compression**=*int*
: Set the compression field.

**row_count**=*int*
: Set the row\_count field.

**row_feed**=*int*
: Set the row\_feed field.

**row_step**=*int*
: Set the row\_step field.

## SVG output options

**text**=(**text**|**path**)
: Control how text is rendered in SVG output.
	- **text** Text is emitted as `<text>` elements.
	- **path** Text is emitted as `<path>` elements.
: Using `<text>` elements means that fonts are not accurately rendered, but the
text can be easily changed in the SVG output. While using `<path>` elements
means that fonts are accurately rendered, but the text cannot be easily
changed.

**no-reuse-images**
: Do not reuse images using `<symbol>` definitions.

## Text output options

See <a href="stext-options.html">Structured Text Options</a>.
