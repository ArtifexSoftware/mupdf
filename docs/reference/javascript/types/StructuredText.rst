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

.. method:: StructuredText.prototype.search(needle)

	Search the text for all instances of needle, and return an array with all matches found on the page.

	Each match in the result is an array containing one or more Quads that cover the matching text.

	:param string needle:
	:returns: Array of Array of `Quad`

	.. code-block::

		var result = sText.search("Hello World!")

.. method:: StructuredText.prototype.highlight(p, q, max_hits)

	Return an array of `Quad` used to highlight a selection defined by the start and end points.

	:param Point p: Start point.
	:param Point q: End point.
	:param number (default 100) max_hits: The maximum number of hits to return.

	:returns: Array of `Quad`

	.. code-block::

		var result = sText.highlight([100,100], [200,100])

.. method:: StructuredText.prototype.copy(p, q)

	Return the text from the selection defined by the start and end points.

	:param Point p: start point
	:param Point q: end point

	:returns: string

	.. code-block::

		var result = sText.copy([100,100], [200,100])

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
			beginTextBlock: function (bbox) {
				console.log("beginTextBlock", bbox)
			},
			endLine: function () {
				console.log("endLine")
			},
			endTextBlock: function () {
				console.log("endTextBlock")
			},
			onChar: function (utf, origin, font, size, quad) {
				console.log("onChar", utf, origin, font, size, quad)
			},
			onImageBlock: function (bbox, transform, image) {
				console.log("onImageBlock", bbox, transform, image)
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
