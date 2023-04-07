.. Copyright (C) 2001-2023 Artifex Software, Inc.
.. All Rights Reserved.


.. default-domain:: js

.. _mutool_object_path:



.. _mutool_run_js_api_path:


`Path`
-----------

A `Path` object represents vector graphics as drawn by a pen. A path can be either stroked or filled, or used as a clip mask.


.. method:: new Path()

    *Constructor method*.

    Create a new empty path.

    :return: `Path`.

    **Example**

    .. code-block:: javascript

        var path = new Path();


.. method:: bound(stroke, transform)

    Return a bounding rectangle for the path.

    :arg stroke: `Float` The stroke for the path.
    :arg transform: `[a,b,c,d,e,f]`. The transform :ref:`matrix<mutool_run_js_api_matrix>` for the path.
    :return: `[ulx,uly,lrx,lry]` :ref:`Rectangle<mutool_run_js_api_rectangle>`.



.. method:: moveTo(x, y)

    Lift and move the pen to the coordinate.

    :arg x: X coordinate.
    :arg y: Y coordinate.

.. method:: lineTo(x, y)

    Draw a line to the coordinate.

    :arg x: X coordinate.
    :arg y: Y coordinate.

.. method:: curveTo(x1, y1, x2, y2, x3, y3)

    Draw a cubic bezier curve to (`x3`, `y3`) using (`x1`, `y1`) and (`x2`, `y2`) as control points.

    :arg x1: X1 coordinate.
    :arg y1: Y1 coordinate.
    :arg x2: X2 coordinate.
    :arg y2: Y2 coordinate.
    :arg x3: X3 coordinate.
    :arg y3: Y3 coordinate.

.. method:: curveToV(cx, cy, ex, ey)

    Draw a cubic bezier curve to (`ex`, `ey`) using the start point and (`cx`, `cy`) as control points.

    :arg cx: CX coordinate.
    :arg cy: CY coordinate.
    :arg ex: EX coordinate.
    :arg ey: EY coordinate.


.. method:: curveToY(cx, cy, ex, ey)

    Draw a cubic bezier curve to (`ex`, `ey`) using the (`cx`, `cy`) and (`ex`, `ey`) as control points.

    :arg cx: CX coordinate.
    :arg cy: CY coordinate.
    :arg ex: EX coordinate.
    :arg ey: EY coordinate.

.. method:: closePath()

    Close the path by drawing a line to the last `moveTo`.

.. method:: rect(x1, y1, x2, y2)

    Shorthand for `moveTo`, `lineTo`, `lineTo`, `lineTo`, `closePath` to draw a rectangle.

    :arg x1: X1 coordinate.
    :arg y1: Y1 coordinate.
    :arg x2: X2 coordinate.
    :arg y2: Y2 coordinate.


.. method:: walk(pathWalker)

    Call `moveTo`, `lineTo`, `curveTo` and `closePath` methods on the `pathWalker` object to replay the path.


    :arg pathWalker: The path walker object. A user definable :title:`JavaScript` object which can be used to trigger your own functions on the path methods.

    .. note::

        A path walker object has callback methods that are called when `walk()` walks over `moveTo`, `lineTo`, `curveTo` and `closePath` operators in a `Path`.


    **Example**

    .. code-block:: javascript

        var myPathWalker = {
            moveTo: function (x, y) { ... do whatever ... },
            lineTo: function (x, y) { ... do whatever ... },
        }

        path.walk(myPathWalker);



.. method:: transform(transform)

    Transform path by the given transform matrix.

    :arg transform: `[a,b,c,d,e,f]`. The transform :ref:`matrix<mutool_run_js_api_matrix>` for the path.
