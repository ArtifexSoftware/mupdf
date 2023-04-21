.. Copyright (C) 2001-2023 Artifex Software, Inc.
.. All Rights Reserved.

.. default-domain:: js


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


----


**Instance methods**


.. method:: getNumberOfComponents()

    A grayscale colorspace has one component, RGB has 3, CMYK has 4, and DeviceN may have any number of components.


    **Example**

    .. code-block:: javascript

        var cs = DeviceRGB;
        var num = cs.getNumberOfComponents();
        print(num);  //3


.. method:: toString()

    Return name of `ColorSpace`.

    :return: `String`.


.. method:: isGray()

    Returns true if the object is a gray color space.

    :return: `Boolean`.

.. method:: isRGB()

    Returns true if the object is an RGB color space.

    :return: `Boolean`.

.. method:: isCMYK()

    Returns true if the object is a CMYK color space.

    :return: `Boolean`.

.. method:: isIndexed()

    Returns true if the object is an Indexed color space.

    :return: `Boolean`.

.. method:: isLab()

    Returns true if the object is a Lab color space.

    :return: `Boolean`.

.. method:: isDeviceN()

    Returns true if the object is a Device N color space.

    :return: `Boolean`.

.. method:: isLabICC()

    Returns true if the object is a Lab ICC color space.

    :return: `Boolean`.

.. method:: isSubtractive()

    Returns true if the object is a subtractive color space.

    :return: `Boolean`.

.. method:: isDevice()

    Returns true if the object is a Device color space.

    :return: `Boolean`.

.. method:: isDeviceGray()

    Returns true if the object is a Device gray color space.

    :return: `Boolean`.

.. method:: isDeviceCMYK()

    Returns true if the object is a Device CMYK color space.

    :return: `Boolean`.


.. _mutool_object_default_color_spaces:

`DefaultColorSpaces`
------------------------------

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
