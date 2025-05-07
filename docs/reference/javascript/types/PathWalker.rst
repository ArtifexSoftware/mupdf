.. default-domain:: js

.. highlight:: javascript

PathWalker
==========

An object implementing this interface of optional callback functions
can be used to get calls whenever `Path.prototype.walk()` iterates over a
basic drawing operation corresponding to that of the function name.

.. function:: closePath()

	Called when `Path.prototype.walk()` encounters a close subpath operation.

.. function:: curveTo(x1, y1, x2, y2, x3, y3)

	Called when `Path.prototype.walk()` encounters an operation drawing a Bézier
	curve from the current point to (x3, y3) using (x1, y1) and (x2, y2)
	as control points.

	.. imagesvg:: ../../../images/curveTo.svg
	   :tagtype: object

	:param x1: X1 coordinate.
	:type x1: number
	:param y1: Y1 coordinate.
	:type y1: number
	:param x2: X2 coordinate.
	:type x2: number
	:param y2: Y2 coordinate.
	:type y2: number
	:param x3: X3 coordinate.
	:type x3: number
	:param y3: Y3 coordinate.
	:type y3: number

.. function:: lineTo(x, y)

	Called when `Path.prototype.walk()` encounters an operation drawing a straight
	line from the current point to the given point.

	.. imagesvg:: ../../../images/lineTo.svg
	   :tagtype: object

	:param x: X coordinate.
	:type x: number
	:param y: Y coordinate.
	:type y: number

.. function:: moveTo(x, y)

	Called when `Path.prototype.walk()` encounters an operation moving the pen to
	the given point, beginning a new subpath and sets the current point.

	:param x: X coordinate.
	:type x: number
	:param y: Y coordinate.
	:type y: number
