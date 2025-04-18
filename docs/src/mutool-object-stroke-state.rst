.. Copyright (C) 2001-2023 Artifex Software, Inc.
.. All Rights Reserved.

----

.. default-domain:: js

.. include:: html_tags.rst

.. _mutool_object_stroke_state:

.. _mutool_run_js_api_stroke_state:

`StrokeState`
--------------

A `StrokeState` object is used to define stroke styles.


.. method:: new StrokeState(obj)


    *Constructor method*.

    Create a new stroke state object with the specified :ref:`properties<mutool_run_js_api_stroke_object>`.

    :return: `StrokeState`.

    |example_tag|

    .. code-block:: javascript

        var strokeState = new mupdf.StrokeState({
                lineCap: 'Butt',
                lineJoin: 'Round',
                lineWidth: 1.5,
                miterLimit: 10.0,
                dashPhase: 0,
                dashes: [ 4, 8 ],
        })



|instance_methods|



.. method:: getLineCap()


    :return: `String` One of "Butt", "Round" or "Square".

    |example_tag|

    .. code-block:: javascript

        var lineCap = strokeState.getLineCap();


.. method:: getLineJoin()


    :return: `String` One of "Miter", "Round" or "Bevel".

    |example_tag|

    .. code-block:: javascript

        var lineJoin = strokeState.getLineJoin();


.. method:: getLineWidth()


    :return: `Integer`.

    |example_tag|

    .. code-block:: javascript

        var width = strokeState.getLineWidth();


.. method:: getMiterLimit()


    :return: `Integer`.

    |example_tag|

    .. code-block:: javascript

        var limit = strokeState.getMiterLimit();
