Document Writer Options
=======================

Raster output options:
-------------------------------------------------

- ``rotate=N`` Rotate rendered pages N degrees counterclockwise.
- ``resolution=N`` Set both X and Y resolution in pixels per inch.
- ``x-resolution=N`` X resolution of rendered pages in pixels per inch.
- ``y-resolution=N`` Y resolution of rendered pages in pixels per inch.
- ``width=N`` Render pages to fit N pixels wide (ignore resolution option).
- ``height=N`` Render pages to fit N pixels tall (ignore resolution option).
- ``colorspace=(gray|rgb|cmyk)`` Render using specified colorspace.
- ``alpha`` Render pages with alpha channel and transparent background.

- ``graphics=(aaN|cop|app)`` Set the rasterizer to use for graphics.
	- ``aaN`` Antialias with N bits (0 to 8).
	- ``cop`` Center of pixel.
	- ``app`` Any part of pixel.

- ``text=(aaN|cop|app)`` Set the rasterizer to use for text.
	- ``aaN`` Antialias with N bits (0 to 8).
	- ``cop`` Center of pixel.
	- ``app`` Any part of pixel.

PCL output options:
-------------------------------------------------
- ``colorspace=mono`` Render 1-bit black and white page.
- ``colorspace=rgb`` Render full color page.
- ``preset=generic|ljet4|dj500|fs600|lj|lj2|lj3|lj3d|lj4|lj4pl|lj4d|lp2563b|oce9050``.
- ``spacing=0`` No vertical spacing capability.
- ``spacing=1`` PCL 3 spacing (<ESC>*p+<n>Y).
- ``spacing=2`` PCL 4 spacing (<ESC>*b<n>Y).
- ``spacing=3`` PCL 5 spacing (<ESC>*b<n>Y and clear seed row).
- ``mode2`` Enable mode 2 graphics compression.
- ``mode3`` Enable mode 3 graphics compression.
- ``eog_reset`` End of graphics (<ESC>*rB) resets all parameters.
- ``has_duplex`` Duplex supported (<ESC>&l<duplex>S).
- ``has_papersize`` Papersize setting supported (<ESC>&l<sizecode>A).
- ``has_copies`` Number of copies supported (<ESC>&l<copies>X).
- ``is_ljet4pjl`` Disable/Enable HP 4PJL model-specific output.
- ``is_oce9050`` Disable/Enable Oce 9050 model-specific output.

PCLm output options:
-------------------------------------------------
- ``compression=none`` No compression (default).
- ``compression=flate`` Flate compression.
- ``strip-height=N`` Strip height (default 16).

PDF output options:
-------------------------------------------------

See :doc:`/reference/common/pdf-write-options`.

PWG output options:
-------------------------------------------------
- ``media_class=<string>`` Set the media_class field.
- ``media_color=<string>`` Set the media_color field.
- ``media_type=<string>`` Set the media_type field.
- ``output_type=<string>`` Set the output_type field.
- ``rendering_intent=<string>`` Set the rendering_intent field.
- ``page_size_name=<string>`` Set the page_size_name field.
- ``advance_distance=<int>`` Set the advance_distance field.
- ``advance_media=<int>`` Set the advance_media field.
- ``collate=<int>`` Set the collate field.
- ``cut_media=<int>`` Set the cut_media field.
- ``duplex=<int>`` Set the duplex field.
- ``insert_sheet=<int>`` Set the insert_sheet field.
- ``jog=<int>`` Set the jog field.
- ``leading_edge=<int>`` Set the leading_edge field.
- ``manual_feed=<int>`` Set the manual_feed field.
- ``media_position=<int>`` Set the media_position field.
- ``media_weight=<int>`` Set the media_weight field.
- ``mirror_print=<int>`` Set the mirror_print field.
- ``negative_print=<int>`` Set the negative_print field.
- ``num_copies=<int>`` Set the num_copies field.
- ``orientation=<int>`` Set the orientation field.
- ``output_face_up=<int>`` Set the output_face_up field.
- ``page_size_x=<int>`` Set the page_size_x field.
- ``page_size_y=<int>`` Set the page_size_y field.
- ``separations=<int>`` Set the separations field.
- ``tray_switch=<int>`` Set the tray_switch field.
- ``tumble=<int>`` Set the tumble field.
- ``media_type_num=<int>`` Set the media_type_num field.
- ``compression=<int>`` Set the compression field.
- ``row_count=<int>`` Set the row_count field.
- ``row_feed=<int>`` Set the row_feed field.
- ``row_step=<int>`` Set the row_step field.

SVG output options:
-------------------------------------------------
- ``text=text`` Emit text as <text> elements (inaccurate fonts).
- ``text=path`` Emit text as <path> elements (accurate fonts).
- ``no-reuse-images`` Do not reuse images using <symbol> definitions.

Text output options:
-------------------------------------------------

See :doc:`/reference/common/stext-options`.
