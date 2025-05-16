.. default-domain:: js

.. highlight:: javascript

StructuredTextWalker
====================

Constructors
------------

.. class:: StructuredTextWalker

On beginLine the direction parameter is a vector (e.g. [0, 1]) and
can you can calculate the rotation as an angle with some trigonometry on the vector.

.. function:: beginTextBlock(bbox)

	Called before every text block in the `StructuredText`.

	:param Rect bbox:

.. function:: endTextBlock()

	Called after every text block.

.. function:: beginLine(bbox, wmode, direction)

	Called bfore every line of text in a block.

	:param Rect bbox:
	:param number wmode:
	:param Point direction:

.. function:: endLine()

	Called after every line of text.

.. function:: beginStruct()

	Called to indicate that a new structure element begins. May not
	be neatly nested within blocks or lines.

.. function:: endStruct()

	Called after every structure element.

.. function:: onChar(c, origin, font, size, quad, color)

	Called for every character in a line of text.

	:param string c:
	:param Point origin:
	:param Font font:
	:param number size:
	:param Quad quad:
	:param Color color:

.. function:: onImageBlock(bbox, transform, image)

	Called for every image in a `StructuredText` if its options were
	set to preserve images.

	:param Rect bbox:
	:param Matrix transform:
	:param Image image:

.. function:: onVector()

	Called for every vector in a `StructuredText` if its options
	were set to collect vectors.

	:param Object flags:
	:param Array of number rgb:
