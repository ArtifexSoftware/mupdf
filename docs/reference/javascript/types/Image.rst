.. default-domain:: js

.. highlight:: javascript

Image
=====

Constructors
------------

.. class::
	Image(data)
	Image(filename)

	Create an `Image` by decoding an image file from the supplied data buffer or file.

	:param `Buffer` | `ArrayBuffer` | `Uint8Array` data: Image data.
	:param string filename: Image file to load.

	.. code-block::

		var image = new mupdf.Image("logo.png")

Instance methods
----------------

.. method:: Image.prototype.getWidth()

	Get the image width in pixels.

	:returns: number

	.. code-block::

		var width = image.getWidth()

.. method:: Image.prototype.getHeight()

	Get the image height in pixels.

	:returns: number

	.. code-block::

		var height = image.getHeight()

.. method:: Image.prototype.getXResolution()

	Returns the x resolution for the `Image` in dots per inch.

	:returns: number

	.. code-block::

		var xRes = image.getXResolution()

.. method:: Image.prototype.getYResolution()

	Returns the y resolution for the `Image` in dots per inch.

	:returns: number

	.. code-block::

		var yRes = image.getYResolution()

.. method:: Image.prototype.getColorSpace()

	Returns the `ColorSpace` for the `Image`.

	:returns: `ColorSpace`

	.. code-block::

		var cs = image.getColorSpace()

.. method:: Image.prototype.getNumberOfComponents()

	Number of colors; plus one if an alpha channel is present.

	:returns: number

	.. code-block::

		var num = image.getNumberOfComponents()

.. method:: Image.prototype.getBitsPerComponent()

	Returns the number of bits per component.

	:returns: number

	.. code-block::

		var bits = image.getBitsPerComponent()

.. method:: Image.prototype.getImageMask()

	Returns *true* if this image is an image mask.

	:returns: boolean

	.. code-block::

		var hasMask = image.getImageMask()

.. method:: Image.prototype.getMask()

	Get another `Image` used as a mask for this one.

	:returns: `Image` | null

	.. code-block::

		var mask = image.getMask()

.. method:: Image.prototype.toPixmap()

	Create a `Pixmap` from the image.

	:returns: `Pixmap`

	.. code-block::

		var pixmap = image.toPixmap()
