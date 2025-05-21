.. default-domain:: js

.. highlight:: javascript

StructuredText
===================

StructuredText objects hold text from a page that has been analyzed and grouped
into blocks, lines and spans.

Constructors
------------

.. class:: StructuredText

	|no_new|

To obtain a StructuredText instance use `Page.prototype.toStructuredText()`.

Instance methods
----------------

.. method:: StructuredText.prototype.search(needle, maxHits)

	Search the text for all instances of needle, and return an array with all matches found on the page.

	Each match in the result is an array containing one or more Quads that cover the matching text.

	:param string needle: The text to search for.
	:param number maxHits: Maximum number of hits to return. Default 500.

	:returns: Array of Array of `Quad`

	.. code-block::

		var result = sText.search("Hello World!")

.. method:: StructuredText.prototype.highlight(p, q, maxHits)

	Return an array of `Quad` used to highlight a selection defined by the start and end points.

	:param Point p: Start point.
	:param Point q: End point.
	:param number maxHits: The maximum number of hits to return. Default 500.

	:returns: Array of `Quad`

	.. code-block::

		var result = sText.highlight([100, 100], [200, 100])

.. method:: StructuredText.prototype.copy(p, q)

	Return the text from the selection defined by the start and end points.

	:param Point p: Start point.
	:param Point q: End point.

	:returns: string

	.. code-block::

		var result = sText.copy([100, 100], [200, 100])

.. method:: StructuredText.prototype.walk(walker)

	:param StructuredTextWalker walker: Callback object.

	Walk through the blocks (images or text blocks) of the structured text.
	For each text block walk over its lines of text, and for each line each
	of its characters. For each block, line or character the walker will
	have a method called.

	.. code-block::

		var sText = pdfPage.toStructuredText()
		sText.walk({
			beginLine: function (bbox, wmode, direction) {
				console.log("beginLine", bbox, wmode, direction)
			},
			endLine: function () {
				console.log("endLine")
			},
			beginTextBlock: function (bbox) {
				console.log("beginTextBlock", bbox)
			},
			endTextBlock: function () {
				console.log("endTextBlock")
			},
			beginStruct: function (standard, raw, index) {
				console.log("beginStruct", standard, raw, index)
			},
			endStruct: function () {
				console.log("endStruct")
			},
			onChar: function (utf, origin, font, size, quad, argb) {
				console.log("onChar", utf, origin, font, size, quad, argb)
			},
			onImageBlock: function (bbox, transform, image) {
				console.log("onImageBlock", bbox, transform, image)
			},
			onVector: function (isStroked, isRectangle, argb) {
				console.log("onVector", isStroked, isRectangle, argb)
			},
		})

.. method:: StructuredText.prototype.asJSON(scale)

	Returns a JSON string representing the structured text data.

	:param number scale: Optional scaling factor to multiply all the coordinates by.

	:returns: string

	.. code-block::

		var json = sText.asJSON()

.. method:: StructuredText.prototype.asHTML(id)

	Returns a string containing an HTML representation.

	:param number id:
		Used to number the "id" on the top div tag (as ``"page" + id``).

	:returns: string

.. method:: StructuredText.prototype.asText()

	Returns a plain text representation.

	:returns: string
