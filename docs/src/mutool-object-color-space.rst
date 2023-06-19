.. Copyright (C) 2001-2023 Artifex Software, Inc.
.. All Rights Reserved.

----

.. default-domain:: js

.. include:: html_tags.rst

.. _mutool_object_color_space:

.. _mutool_run_javascript_api_colorspace:

.. _mutool_run_js_api_colorspace:


`ColorSpace`
----------------------------

**Properties**


`DeviceGray`

    The default grayscale colorspace.

`DeviceRGB`

    The default RGB colorspace.

`DeviceBGR`

    The default RGB colorspace, but with components in reverse order.

`DeviceCMYK`

    The default CMYK colorspace.

`DeviceLab`

    The default Lab colorspace.


**Methods**





.. method:: new ColorSpace(from, name)

    |wasm_tag|

    *Constructor method*.

    Create a new `ColorSpace`.

    :arg from: A buffer containing an ICC profile.
    :arg name: A user descriptive name.

    :return: `ColorSpace`.

    |example_tag|

    .. code-block:: javascript

        var icc_colorspace = new mupdf.ColorSpace(fs.readFileSync("SWOP.icc"), "SWOP");


.. method:: getNumberOfComponents()

    A grayscale colorspace has one component, RGB has 3, CMYK has 4, and DeviceN may have any number of components.


    |example_tag|

    .. code-block:: javascript

        var cs = mupdf.ColorSpace.DeviceRGB;
        var num = cs.getNumberOfComponents(); // 3


.. method:: toString()

    Return name of `ColorSpace`.

    :return: `String`.

    .. code-block:: javascript

        var cs = mupdf.ColorSpace.DeviceRGB;
        var num = cs.toString(); // "DeviceRGB"


.. method:: isGray()

    |mutool_tag|

    Returns true if the object is a gray color space.

    :return: `Boolean`.

    .. code-block:: javascript

        var bool = colorSpace.isGray();

    .. |tor_todo| Make wasm method to match this.


.. method:: isRGB()

    |mutool_tag|

    Returns true if the object is an RGB color space.

    :return: `Boolean`.

    .. code-block:: javascript

        var bool = colorSpace.isRGB();

    .. |tor_todo| Make wasm method to match this.


.. method:: isCMYK()

    |mutool_tag|

    Returns true if the object is a CMYK color space.

    :return: `Boolean`.

    .. code-block:: javascript

        var bool = colorSpace.isCMYK();

    .. |tor_todo| Make wasm method to match this.

.. method:: isIndexed()

    |mutool_tag|

    Returns true if the object is an Indexed color space.

    :return: `Boolean`.

    .. code-block:: javascript

        var bool = colorSpace.isIndexed();

    .. |tor_todo| Make wasm method to match this.

.. method:: isLab()

    |mutool_tag|

    Returns true if the object is a Lab color space.

    :return: `Boolean`.

    .. code-block:: javascript

        var bool = colorSpace.isLab();

    .. |tor_todo| Make wasm method to match this.

.. method:: isDeviceN()

    |mutool_tag|

    Returns true if the object is a Device N color space.

    :return: `Boolean`.

    .. code-block:: javascript

        var bool = colorSpace.isDeviceN();


    .. |tor_todo| Make wasm method to match this.


.. method:: isSubtractive()

    |mutool_tag|

    Returns true if the object is a subtractive color space.

    :return: `Boolean`.

    .. code-block:: javascript

        var bool = colorSpace.isSubtractive();


    .. |tor_todo| Make wasm method to match this.


.. method:: getType()

    |wasm_tag|

    Returns a string indicating the type.

    :return: `String` One of "None", "Gray", "RGB", "BGR", "CMYK", "Lab", "Indexed", "Separation".


    .. |tor_todo| Make mutool run method match this.



.. _mutool_object_default_color_spaces:

`DefaultColorSpaces`
------------------------------


.. |jamie_todo| Look into the Device interfaces and see how DefaultColorSpaces is used there.


`DefaultColorSpaces` is an object with keys for:

.. method:: getDefaultGray()

    Get the default gray colorspace.

    :return: `ColorSpace`.

.. method:: getDefaultRGB()

    Get the default RGB colorspace.

    :return: `ColorSpace`.

.. method:: getDefaultCMYK()

    Get the default CMYK colorspace.

    :return: `ColorSpace`.

.. method:: getOutputIntent()

    Get the output intent.

    :return: `ColorSpace`.

.. method:: setDefaultGray(colorspace)

    :arg colorspace: `ColorSpace`.

.. method:: setDefaultRGB(colorspace)

    :arg colorspace: `ColorSpace`.

.. method:: setDefaultCMYK(colorspace)

    :arg colorspace: `ColorSpace`.

.. method:: setOutputIntent(colorspace)

    :arg colorspace: `ColorSpace`.
