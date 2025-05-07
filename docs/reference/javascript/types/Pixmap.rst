.. default-domain:: js

.. highlight:: javascript

Pixmap
======

A Pixmap object contains a color raster image (short for pixel map).
The components in a pixel in the Pixmap are all byte values,
with the transparency as the last component.

A Pixmap also has a location (x, y) in addition to its size;
so that they can easily be used to represent tiles of a page.

Constructors
------------

.. class:: Pixmap(colorspace: ColorSpace, bbox?: Rect, alpha: boolean = false)

	Create a new Pixmap. Note: The pixel data is **not** initialized.

	:param ColorSpace colorspace: The desired colorspace for the new pixmap.
	:param Rect bbox: The desired dimensions of the new pixmap.
	:param boolean alpha: Whether the new pixmap should have an alpha component.
	:returns: `Pixmap`

	.. code-block::

		var pixmap = new mupdf.Pixmap(mupdf.ColorSpace.DeviceRGB, [0,0,100,100], true)

Instance methods
----------------

.. method:: Pixmap.prototype.clear(value)

	Clear the pixels to the specified value. Pass 255 for white, 0 for black, or omit for transparent.

	:param number value: The value to use for clearing.

	.. code-block::

		pixmap.clear(255)

.. method:: Pixmap.prototype.getBounds()

	Return the pixmap bounds.

	:returns: `Rect`

	.. code-block::

		var rect = pixmap.getBounds()

.. method:: Pixmap.prototype.getWidth()

	Get the width of the pixmap.

	:returns: number

	.. code-block::

		var w = pixmap.getWidth()

.. method:: Pixmap.prototype.getHeight()

	Get the height of the pixmap.

	:returns: number

	.. code-block::

		var h = pixmap.getHeight()

.. method:: Pixmap.prototype.getNumberOfComponents()

	Number of colors; plus one if an alpha channel is present.

	:returns: number

	.. code-block::

		var num = pixmap.getNumberOfComponents()

.. method:: Pixmap.prototype.getAlpha()

	*True* if alpha channel is present.

	:returns: boolean

	.. code-block::

		var alpha = pixmap.getAlpha()

.. method:: Pixmap.prototype.getStride()

	Number of bytes per row.

	:returns: number

	.. code-block::

		var stride = pixmap.getStride()

.. method:: Pixmap.prototype.getColorSpace()

	Returns the colorspace of this pixmap.

	:returns: `ColorSpace`

	.. code-block::

		var cs = pixmap.getColorSpace()

.. method:: Pixmap.prototype.setResolution(x, y)

	Set horizontal and vertical resolution.

	:param number x: Horizontal resolution in dots per inch.
	:param number y: Vertical resolution in dots per inch.

	.. code-block::

		pixmap.setResolution(300, 300)

.. method:: Pixmap.prototype.getXResolution()

	Returns the horizontal resolution in dots per inch for this pixmap.

	:returns: number

	.. code-block::

		var xRes = pixmap.getXResolution()

.. method:: Pixmap.prototype.getYResolution()

	Returns the vertical resolution in dots per inch for this pixmap.

	:returns: number

	.. code-block::

		var yRes = pixmap.getYResolution()

.. method:: Pixmap.prototype.invert()

	Invert all pixels. All components are processed, except alpha which is unchanged.

	.. code-block::

		pixmap.invert()

.. method:: Pixmap.prototype.invertLuminance()

	Transform all pixels so that luminance of each pixel is inverted,
	and the chrominance remains as unchanged as possible.
	All components are processed, except alpha which is unchanged.

	.. code-block::

		pixmap.invertLuminance()

.. method:: Pixmap.prototype.gamma(p)

	Apply gamma correction to this pixmap. All components are processed,
	except alpha which is unchanged.

	Values ``>= 0.1 & < 1`` = darken, ``> 1 & < 10`` = lighten.

	:param number p: Desired gamma level.

	.. code-block::

		pixmap.gamma(3.5)

.. method:: Pixmap.prototype.tint(black, white)

	Tint all pixels in RGB, BGR or Gray pixmaps.
	Map black and white respectively to the given hex RGB values.

	:param Color | number black: Black tint.
	:param Color | number white: White tint.

	.. code-block::

		pixmap.tint(0xffff00, 0xffff00)

.. method:: Pixmap.prototype.warp(points, width, height)

	Return a warped subsection of this pixmap, where the result has the requested dimensions.

	:param Array of Point points: The corners of a convex quadrilateral within the `Pixmap` to be warped.
	:param number width: TODO(Robin)
	:param number height: TODO(Robin)

	:returns: `Pixmap`

	.. code-block::

		var warpedPixmap = pixmap.warp([[0,0], [100,100], [130,170], [150,200]],200,200)

.. method:: Pixmap.prototype.convertToColorSpace(colorspace, keepAlpha)

	Convert pixmap into a new pixmap of a desired colorspace.
	A proofing colorspace, a set of default colorspaces and color
	parameters used during conversion may be specified.
	Finally a boolean indicates if alpha should be preserved
	(default is to not preserve alpha).

	:param ColorSpace colorspace: The desired colorspace.
	:param boolean keepAlpha: Whether to keep the alpha component.

	:returns: `Pixmap`

.. method:: Pixmap.prototype.getPixels()

	Returns an array of pixels for this pixmap.

	:returns: [number]

	.. code-block::

		var pixels = pixmap.getPixels()

.. method:: Pixmap.prototype.asPNG()

	Returns a buffer of this pixmap as a PNG.

	:returns: `Buffer`

	.. code-block::

		var buffer = pixmap.asPNG()

.. method:: Pixmap.prototype.asPSD()

	Returns a buffer of this pixmap as a PSD.

	:returns: `Buffer`

	.. code-block::

		var buffer = pixmap.asPSD()

.. method:: Pixmap.prototype.asPAM()

	Returns a buffer of this pixmap as a PAM.

	:returns: `Buffer`

	.. code-block::

		var buffer = pixmap.asPAM()

.. method:: Pixmap.prototype.asJPEG(quality, invert_cmyk)

	Returns a buffer of this pixmap as a JPEG.
	Note, if this pixmap has an alpha channel then an exception will be thrown.

	:param number quality: Desired compression quality, between ``0`` and ``100``.
	:param boolean invert_cmyk: Whether to invert the CMYK jpeg.
	:returns: `Buffer`

	.. code-block::

		var buffer = pixmap.asJPEG(80, false)
