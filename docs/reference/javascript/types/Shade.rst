.. default-domain:: js

.. highlight:: javascript

Shade
=====

A Shade object is used to define shadings.

.. note::

	The details of shadings are not exposed in Javascript yet.


.. class:: Shade

	|no_new|

Instance methods
----------------

.. method:: Shade.prototype.getBounds()

	Returns a rectangle containing the dimensions of the shading
	contents.

	:returns: `Rect`

	.. code-block::

		var bounds = shade.getBounds()
