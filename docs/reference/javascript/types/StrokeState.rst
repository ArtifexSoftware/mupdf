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

	The Javascript object used as template allows for setting
	the following attributes:

	* "lineCap": string: The :term:`line cap style` to be used. One of ``"Butt" | "Round" | "Square"``
	* "lineJoin": string: The :term:`line join style` to be used. One of ``"Miter" | "Round" | "Bevel"``
	* "lineWidth": number: The line width to be used.
	* "miterLimit": number: The :term:`miter limit` to be used.
	* "dashPhase": number: The dash phase to be used.
	* "dashPattern": Array of number: The sequence of dash lengths to be used.

	:param Object template: An object with the parameters to set.

	.. code-block::

		var strokeState = new mupdf.StrokeState({
			lineCap: "Square",
			lineJoin: "Bevel",
			lineWidth: 2.0,
			miterLimit: 1.414,
			dashPhase: 11,
			dashPattern: [ 2, 3 ]
		})

Instance methods
----------------

.. method:: StrokeState.prototype.getLineCap()

	Get the
	:term:`line cap style` to be used when stroking.

	The style is either of these values: ``"Butt" | "Round" | "Square"``

	:returns: number. The set line cap style.

	.. code-block::

		var lineCap = strokeState.getLineCap()

.. method:: StrokeState.prototype.getLineJoin()

	Get the
	:term:`line join style` to be used when stroking.

	The style is either of these values: ``"Miter" | "Round" | "Bevel"``

	:returns: number. The set line cap style.

	.. code-block::

		var lineJoin = strokeState.getLineJoin()

.. method:: StrokeState.prototype.getLineWidth()

	Get the line line width used for stroking operations.

	:returns: number

	.. code-block::

		var width = strokeState.getLineWidth()

.. method:: StrokeState.prototype.getMiterLimit()

	Get the
	:term:`miter limit` to be used when stroking.

	:returns: number

	.. code-block::

		var limit = strokeState.getMiterLimit()

.. method:: StrokeState.prototype.getDashPhase()

	Get the dash phase.

	:returns: number

	.. code-block:: javascript

		var limit = strokeState.getDashPhase()

.. method:: StrokeState.prototype.getDashPattern()

	Get an array of numbers of lengths for the dashes and gaps in
	the dash pattern.

	:returns: Array of number

	.. code-block:: javascript

		var dashPattern = strokeState.getDashPattern()
