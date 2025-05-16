.. default-domain:: js

.. highlight:: javascript

Functions
=========

.. function:: mupdf.setUserCSS(stylesheet, useDocumentStyles)

	Set a style sheet to apply to all reflowable documents.

	:param string stylesheet: The CSS text to use.
	:param boolean useDocumentStyles:
		Whether to respect the document's own style sheet.

.. function:: mupdf.installLoadFontFunction(callback)

	Install a handler to load system (or missing) fonts.

	The callback function will be called with four arguments:

	.. code-block::

		callback(fontName, scriptName, isBold, isItalic)

	The callback should return either a `Font` object for the requested
	font, or ``null`` if an exact match cannot be found (so that the font
	loading machinery can keep looking through the chain of fallback
	fonts).

.. method:: mupdf.enableICC()

	Enable ICC-profiles based operation.

.. method:: mupdf.disableICC()

	Disable ICC-profiles based operation.

.. TODO move readFile() below to mutool-run.rst?

.. method:: readFile(filename)

	|mutool_only|

	Read the contents from a file of the given name. Throws an
	exception if the file does not exist.

	:returns: `Buffer`
