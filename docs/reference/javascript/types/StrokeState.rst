.. default-domain:: js

.. highlight:: javascript

StrokeState
===========

A StrokeState controls the properties of how stroking operations are performed.
Besides controlling the line width, it is also possible to control
:term:`line cap style`, :term:`line join style`, and the :term:`miter limit`.

Constructors
------------

.. class:: StrokeState([template])

	Create a new empty stroke state object.

	:param template: An object with the parameters to set.

	.. code-block::

		var strokeState = new mupdf.StrokeState({
			lineCap: "Round",
			lineWidth: 2.0,
		})

Instance methods
----------------

.. method:: StrokeState.prototype.setLineCap(style)

	Set the
	:term:`line cap style` to be used when stroking.

	The style can be either of these values: ``"Butt" | "Round" | "Square"``

	:param string | number style: The desired line cap style.

	.. code-block::

		strokeState.setLineCap("Butt")

.. method:: StrokeState.prototype.getLineCap()

	Get the
	:term:`line cap style` to be used when stroking.

	The style is either of these values: ``"Butt" | "Round" | "Square"``

	:returns: number. The set line cap style.

	.. code-block::

		var lineCap = strokeState.getLineCap()

.. method:: StrokeState.prototype.setLineJoin(style)

	Set the
	:term:`line join style` to be used when stroking.

	The style can be either of these values: ``"Miter" | "Round" | "Bevel"``

	:param string | number style: The desired line join style.

	.. code-block::

		strokeState.setLineJoin("Round")

.. method:: StrokeState.prototype.getLineJoin()

	Get the
	:term:`line join style` to be used when stroking.

	The style is either of these values: ``"Miter" | "Round" | "Bevel"``

	:returns: number. The set line cap style.

	.. code-block::

		var lineJoin = strokeState.getLineJoin()

.. method:: StrokeState.prototype.setLineWidth(width)

	Set line width for the stroking operations.

	:param number width: The desired line width.

	.. code-block::

		strokeState.setLineWidth(2)

.. method:: StrokeState.prototype.getLineWidth()

	Get the line line width used for stroking operations.

	:returns: number

	.. code-block::

		var width = strokeState.getLineWidth()

.. method:: StrokeState.prototype.setMiterLimit(miter)

	Set the
	:term:`miter limit` to be used when stroking.

	:param number miter: The desired miter limit.

	.. code-block::

		strokeState.setMiterLimit(2)

.. method:: StrokeState.prototype.getMiterLimit()

	Get the
	:term:`miter limit` to be used when stroking.

	:returns: number

	.. code-block::

		var limit = strokeState.getMiterLimit()
