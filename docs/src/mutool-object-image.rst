.. Copyright (C) 2001-2023 Artifex Software, Inc.
.. All Rights Reserved.


.. default-domain:: js

.. _mutool_object_image:



.. _mutool_run_js_api_image:




`Image`
------------

`Image` objects are similar to `Pixmaps`, but can contain compressed data.


.. method:: new Image(ref)

    *Constructor method*.

    Create a new image from a `Pixmap` data, or load an image from a file.

    :return: `Image`.

    **Example**

    .. code-block:: javascript

        var image = new Image("my-image-file.png");


.. method:: getWidth()

    Get the image width in pixels.

    :return: The width value.

.. method:: getHeight()

    Get the image height in pixels.

    :return: The height value.

.. method:: getXResolution()

    Returns the x resolution for the `Image`.

    :return: `Int` Image resolution in dots per inch.


.. method:: getYResolution()

    Returns the y resolution for the `Image`.

    :return: `Int` Image resolution in dots per inch.

.. method:: getColorSpace()

    Returns the `ColorSpace` for the `Image`.

    :return: `ColorSpace`.



.. method:: getNumberOfComponents()

    Number of colors; plus one if an alpha channel is present.

    :return: `Integer`.


.. method:: getBitsPerComponent()

    Returns the number of bits per component.

    :return: `Integer`.


.. method:: getInterpolate()

    Returns *true* if interpolated was used during decoding.

    :return: `Boolean`.


.. method:: getColorKey()

    Returns an array with 2 * N integers for an N component image with color key masking, or `null` if masking is not used. Each pair of integers define an interval, and component values within that interval are not painted.

    :return: `[]`.

.. method:: getDecode()

    Returns an array with 2 * N numbers for an N component image with color mapping, or `null` if mapping is not used. Each pair of numbers define the lower and upper values to which the component values are mapped linearly.

    :return: `[]`.


.. method:: getOrientation()

    Returns the orientation of the image.

    :return: `Integer`.

.. method:: setOrientation(orientation)

    Set the image orientation to the given orientation.

    :arg orientation: `Integer` Orientation value from the table below:


.. list-table::
   :header-rows: 0

   * - **0**
     - Undefined
   * - **1**
     - 0 degree ccw rotation. (Exif = 1)
   * - **2**
     - 90 degree ccw rotation. (Exif = 8)
   * - **3**
     - 180 degree ccw rotation. (Exif = 3)
   * - **4**
     - 270 degree ccw rotation. (Exif = 6)
   * - **5**
     - flip on X. (Exif = 2)
   * - **6**
     - flip on X, then rotate ccw by 90 degrees. (Exif = 5)
   * - **7**
     - flip on X, then rotate ccw by 180 degrees. (Exif = 4)
   * - **8**
     - flip on X, then rotate ccw by 270 degrees. (Exif = 7)


.. method:: getImageMask()

    Returns *true* if this image is an image mask.

    :return: `Boolean`.

.. method:: getMask()

    Get another `Image` used as a mask for this one.

    :return: `Image` (or `null`).



.. method:: toPixmap(scaledWidth, scaledHeight)

    Create a `Pixmap` from the image. The `scaledWidth` and `scaledHeight` arguments are optional, but may be used to decode a down-scaled `Pixmap`.

    :arg scaledWidth: Width value.
    :arg scaledHeight: Height value.

    :return: `Pixmap`.
