Structured Text Options
=======================

- ``preserve-images`` keep images in output
- ``preserve-ligatures`` do not expand ligatures into constituent characters
- ``preserve-spans`` do not merge spans on the same line
- ``preserve-whitespace`` do not convert all whitespace into space characters
- ``inhibit-spaces`` don't add spaces between gaps in the text
- ``paragraph-break`` break blocks at paragraph boundaries
- ``dehyphenate`` attempt to join up hyphenated words
- ``ignore-actualtext`` do not apply ActualText replacements
- ``use-cid-for-unknown-unicode`` use character code if unicode mapping fails
- ``use-gid-for-unknown-unicode`` use glyph index if unicode mapping fails
- ``accurate-bboxes`` calculate char bboxes from the outlines
- ``accurate-ascenders`` calculate ascender/descender from font glyphs
- ``accurate-side-bearings`` expand character bboxes to completely include width of glyphs
- ``collect-styles`` attempt to detect text features (fake bold, strikeout, underlined etc)
- ``clip`` do not include text that is completely clipped
- ``clip-rect=x0:y0:x1:y1`` specify clipping rectangle within which to collect content
- ``structured`` collect structure markup
- ``vectors`` include vector bboxes in output
- ``segment`` attempt to segment the page
- ``table-hunt`` hunt for tables within a (segmented) page
