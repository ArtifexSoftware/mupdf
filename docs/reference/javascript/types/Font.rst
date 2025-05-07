.. default-domain:: js

.. highlight:: javascript

Font
====

Font objects can be created from TrueType, OpenType,
Type1 or CFF fonts. In PDF there are also special
Type3 fonts.

Constructors
------------

.. class:: Font(name[, data, index])

	Create a new font. Either from a built-in font name, or a buffer or a file name.

	The built-in standard PDF fonts are:

	- ``"Times-Roman"``
	- ``"Times-Italic"``
	- ``"Times-Bold"``
	- ``"Times-BoldItalic"``
	- ``"Helvetica"``
	- ``"Helvetica-Oblique"``
	- ``"Helvetica-Bold"``
	- ``"Helvetica-BoldOblique"``
	- ``"Courier"``
	- ``"Courier-Oblique"``
	- ``"Courier-Bold"``
	- ``"Courier-BoldOblique"``
	- ``"Symbol"``
	- ``"ZapfDingbats"``

	The built-in CJK fonts are referenced by language code: ``"zh-Hant"``, ``"zh-Hans"``, ``"ja"``, ``"ko"``.

	:param string name: Font name or file name.
	:param Buffer | AnyBuffer data: The font data if loaded from a buffer.
	:arg number index: Subfont index (only used for TTC fonts).
	:returns: `Font`

	.. code-block::

		var font1 = new mupdf.Font("Times-Roman")
		var font2 = new mupdf.Font("ko")
                var font3 = new mupdf.Font("Comic Sans", "/usr/share/fonts/truetype/msttcorefonts/Comic_Sans_MS.ttf")
                var font4 = new mupdf.Font("Comic Sans", "/usr/share/fonts/truetype/msttcorefonts/Comic_Sans_MS.ttf", 1)
		var font5 = new mupdf.Font("Freight Sans", fs.readFileSync("DroidSansFallbackFull.ttf"))

Instance methods
----------------

.. method:: Font.prototype.getName()

	Get the font name.

	:returns: string

	.. code-block::

		var name = font.getName()

.. method:: Font.prototype.encodeCharacter(unicode)

	Get the glyph index for a unicode character. Glyph ``0`` is returned if the font does not have a glyph for the character.

	:param number unicode: The unicode character.
	:returns: number.

	.. code-block::

		var index = font.encodeCharacter(0x42)

.. method:: Font.prototype.advanceGlyph(glyph[ , wmode])

	Return advance width for a glyph in either horizontal or vertical writing mode.

	:param number glyph: The glyph as unicode character.
	:param number wmode: ``0`` for horizontal writing, and ``1`` for vertical writing, defaults to horizontal.

	:returns: number

	.. code-block::

		var width = font.advanceGlyph(0x42)

.. method:: Font.prototype.isBold()

	Returns ``true`` if font is bold.

	:returns: boolean

	.. code-block::

		var isBold = font.isBold()

.. method:: Font.prototype.isItalic()

	Returns ``true`` if font is italic.

	:returns: boolean

	.. code-block::

		var isItalic = font.isItalic()

.. method:: Font.prototype.isMono()

	Returns ``true`` if font is monospaced.

	:returns: boolean

	.. code-block::

		var isMono = font.isMono()

.. method:: Font.prototype.isSerif()

	Returns ``true`` if font is serif.

	:returns: boolean

	.. code-block::

		var isSerif = font.isSerif()
