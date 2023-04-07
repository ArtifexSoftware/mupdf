.. Copyright (C) 2001-2022 Artifex Software, Inc.
.. All Rights Reserved.


.. default-domain:: js


.. title:: mutool JavaScript API

.. include:: header.rst

.. meta::
   :description: MuPDF documentation
   :keywords: MuPDF, pdf, epub


.. _mutool_run_javascript_api:





Global :title:`MuPDF` methods
------------------------------------------



.. method:: print(...)

    Print arguments to `stdout`, separated by spaces and followed by a newline.

    :arg ...: Arguments to print.

    **Example**

    .. code-block:: javascript

        var document = new Document("my_pdf.pdf");
        print(document); // [object pdf_document]



.. method:: write(...)

    Print arguments to `stdout`, separated by spaces.

    :arg ...: Arguments to print.


.. method:: repr(object)

    Format the `object` into a string with :title:`JavaScript` syntax.


    **Example**

    .. code-block:: javascript

        var document = new Document("my_pdf.pdf");
        repr(document); // "[userdata pdf_document]"


.. method:: gc(report)

    Run the garbage collector to free up memory. Optionally report statistics on the garbage collection.

    :arg report: `Boolean` If *true* then the results will be printed to `stdout`.

.. method:: load(fileName)

    Load and execute script in `fileName`.

    :arg fileName: `String` :title:`JavaScript` file to load.


.. method:: read(fileName)

    Read the contents of a file and return them as a :title:`UTF-8` decoded string.

    :arg fileName: `String`.

.. method:: readline()

    Read one line of input from `stdin` and return it as a string.

    :return: `String`.

.. method:: require(module)

    Load a :title:`JavaScript` module.


.. method:: setUserCSS(userStyleSheet, usePublisherStyles)

    Set user styles and whether to use publisher styles when laying out reflowable documents.

    :arg userStyleSheet: Link to :title:`CSS` stylesheet file.
    :arg usePublisherStyles: `Boolean`.


.. method:: quit()

    Exit the shell.





Matrices and Rectangles
----------------------------

These are not classes as such but array definitions. All dimensions are in points unless otherwise specified.



.. _mutool_run_js_api_matrix:

Matrices
~~~~~~~~~~~~

Matrices are simply 6-element arrays representing a 3-by-3 transformation matrix as:


.. code-block:: bash

    / a b 0 \
    | c d 0 |
    \ e f 1 /

This matrix is represented in :title:`JavaScript` as `[a,b,c,d,e,f]`.


**Properties**

`Identity`

    The identity matrix, short hand for `[1,0,0,1,0,0]`.


**Methods**

.. method:: Scale(sx, sy)

    Returns a scaling matrix, short hand for `[sx,0,0,sy,0,0]`.

    :return: `[a,b,c,d,e,f]`.

.. method:: Translate(tx, ty)

    Return a translation matrix, short hand for `[1,0,0,1,tx,ty]`.

    :return: `[a,b,c,d,e,f]`.

.. method:: Rotate(theta)

    Return a rotation matrix, short hand for `[cos(theta),sin(theta),-sin(theta),cos(theta),0,0]`.

    :return: `[a,b,c,d,e,f]`.

.. method:: Concat(a, b)

    Concatenate matrices `a` and `b`. Bear in mind that matrix multiplication is not commutative.

    :return: `[a,b,c,d,e,f]`.

.. _mutool_run_js_api_rectangle:

Rectangles
~~~~~~~~~~~~

Rectangles are 4-element arrays, specifying the minimum and maximum corners (typically upper left and lower right, in a coordinate space with the origin at the top left with descending y): `[ulx,uly,lrx,lry]`.

If the minimum x coordinate is bigger than the maximum x coordinate, :title:`MuPDF` treats the rectangle as infinite in size.



.. _mutool_run_js_api_colors:

Colors
----------

Colors are specified as arrays with the appropriate number of components for the :ref:`color space<mutool_run_javascript_api_colorspace>`. Each number is a floating point between `0` and `1` for the color value.

Therefore colors are represented as an array of up to 4 component values.

For example:

- In the `DeviceCMYK` color space a color would be `[Cyan,Magenta,Yellow,Black]`. A full magenta color would therefore be `[0,1,0,0]`.
- In the `DeviceRGB` color space a color would be `[Red,Green,Blue]`. A full green color would therefore be `[0,1,0]`.
- In the `DeviceGray` color space a color would be `[Black]`. A full black color would therefore be `[1]`.



.. _mutool_run_js_api_color_params:

Color parameters
~~~~~~~~~~~~~~~~~~~~

This object is a dictionary with keys for:

`renderingIntent`
    Either of "Perceptual", "RelativeColorimetric", "Saturation" or "AbsoluteColorimetric".

`blackPointCompensation`
    *True* if black point compensation is activated.

`overPrinting`
    *True* if overprint is activated.

`overPrintMode`
    The overprint mode. Can be either `0` or `1`.


.. _mutool_run_js_api_alpha:

Alpha
~~~~~~~~~~~~

Alpha values are floats between `0` and `1`, whereby `0` denotes full transparency & `1` denotes full opacity.



.. include:: mutool-object-protocols.rst








.. include:: mutool-object-buffer.rst

.. include:: mutool-object-document.rst

.. include:: mutool-object-page.rst

.. include:: mutool-object-structured-text.rst

.. include:: mutool-object-color-space.rst

.. include:: mutool-object-pixmap.rst

.. include:: mutool-object-draw-device.rst

.. include:: mutool-object-display-list.rst

.. include:: mutool-object-display-list-device.rst

.. include:: mutool-object-device.rst

.. include:: mutool-object-path.rst

.. include:: mutool-object-text.rst

.. include:: mutool-object-font.rst

.. include:: mutool-object-image.rst

.. include:: mutool-object-document-writer.rst

.. include:: mutool-object-pdf-document.rst

.. include:: mutool-object-pdf-graft-map.rst

.. include:: mutool-object-pdf-object.rst

.. include:: mutool-object-pdf-page.rst

.. include:: mutool-object-pdf-annotation.rst

.. include:: mutool-object-pdf-widget.rst

.. include:: mutool-object-outline-iterator.rst

.. include:: mutool-object-archive.rst

.. include:: mutool-object-story.rst

.. include:: mutool-object-xml.rst

.. _mutool_run_js_api_pdf_processor:


PDF Processor
----------------------

A :title:`PDF processor` provides callbacks that get called for each :title:`PDF` operator handled by `PDFPage` `process()` & `PDFAnnotation` `process()` methods. The callbacks whose names start with `op_` correspond to each :title:`PDF` operator. Refer to the :title:`PDF` specification for what these do and what the callback arguments are.


Methods
~~~~~~~~~~~

Main methods
"""""""""""""""""""""""""

- `push_resources(resources)`
- `pop_resources()`


General graphics state callbacks
"""""""""""""""""""""""""""""""""""""""""""

- `op_w(lineWidth)`
- `op_j(lineJoin)`
- `op_J(lineCap)`
- `op_M(miterLimit)`
- `op_d(dashPattern, phase)`
- `op_ri(intent)`
- `op_i(flatness)`
- `op_gs(name, extGState)`



Special graphics state
"""""""""""""""""""""""""""""""""""""""""""

- `op_q()`
- `op_Q()`
- `op_cm(a, b, c, d, e, f)`

Path construction
"""""""""""""""""""""""""""""""""""""""""""

- `op_m(x, y)`
- `op_l(x, y)`
- `op_c(x1, y1, x2, y2, x3, y3)`
- `op_v(x2, y2, x3, y3)`
- `op_y(x1, y1, x3, y3)`
- `op_h()`
- `op_re(x, y, w, h)`

Path painting
"""""""""""""""""""""""""""""""""""""""""""

- `op_S()`
- `op_s()`
- `op_F()`
- `op_f()`
- `op_fstar()`
- `op_B()`
- `op_Bstar()`
- `op_b()`
- `op_bstar()`
- `op_n()`

Clipping paths
"""""""""""""""""""""""""""""""""""""""""""

- `op_W()`
- `op_Wstar()`

Text objects
"""""""""""""""""""""""""""""""""""""""""""

- `op_BT()`
- `op_ET()`

Text state
"""""""""""""""""""""""""""""""""""""""""""

- `op_Tc(charSpace)`
- `op_Tw(wordSpace)`
- `op_Tz(scale)`
- `op_TL(leading)`
- `op_Tf(name, size)`
- `op_Tr(render)`
- `op_Ts(rise)`

Text positioning
"""""""""""""""""""""""""""""""""""""""""""

- `op_Td(tx, ty)`
- `op_TD(tx, ty)`
- `op_Tm(a, b, c, d, e, f)`
- `op_Tstar()`

Text showing
"""""""""""""""""""""""""""""""""""""""""""

- `op_TJ(textArray)` number/string

- `op_Tj(stringOrByteArray)`

- `op_squote(stringOrByteArray)`

- `op_dquote(wordSpace, charSpace, stringOrByteArray)`

Type 3 fonts
"""""""""""""""""""""""""""""""""""""""""""

- `op_d0(wx, wy)`
- `op_d1(wx, wy, llx, lly, urx, ury)`

Color
"""""""""""""""""""""""""""""""""""""""""""

- `op_CS(name, colorspace)`
- `op_cs(name, colorspace)`
- `op_SC_color(color)`
- `op_sc_color(color)`
- `op_SC_pattern(name, patternID, color)`
    API not settled, arguments may change in the future.

- `op_sc_pattern(name, patternID, color)`
    API not settled, arguments may change in the future.

- `op_SC_shade(name, shade)`
    API not settled, arguments may change in the future.

- `op_sc_shade(name, shade)`
    API not settled, arguments may change in the future.

- `op_G(gray)`
- `op_g(gray)`
- `op_RG(r, g, b)`
- `op_rg(r, g, b)`
- `op_K(c, m, y, k)`
- `op_k(c, m, y, k)`

Shadings, images and XObjects
"""""""""""""""""""""""""""""""""""""""""""

- `op_BI(image, colorspace)`
- `op_sh(name, shade)`
    API not settled, arguments may change in the future.

- `op_Do_image(name, image)`
- `op_Do_form(xobject, resources)`

Marked content
"""""""""""""""""""""""""""""""""""""""""""

- `op_MP(tag)`
- `op_DP(tag, raw)`
- `op_BMC(tag)`
- `op_BDC(tag, raw)`
- `op_EMC()`

Compatibility
"""""""""""""""""""""""""""""""""""""""""""

- `op_BX()`
- `op_EX()`


.. include:: footer.rst
