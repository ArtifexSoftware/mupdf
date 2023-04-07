.. Copyright (C) 2001-2023 Artifex Software, Inc.
.. All Rights Reserved.


.. default-domain:: js

.. _mutool_object_text:



.. _mutool_run_js_api_text:




`Text`
--------------

A `Text` object contains text.


.. method:: new Text()

    *Constructor method*.

    Create a new empty text object.

    :return: `Text`.

    **Example**

    .. code-block:: javascript

        var text = new Text();



.. method:: showGlyph(font, transform, glyph, unicode, wmode)

    Add a glyph to the text object.

    Transform is the text matrix, specifying font size and glyph location. For example: `[size,0,0,-size,x,y]`.

    Glyph and unicode may be `-1` for n-to-m cluster mappings. For example, the "fi" ligature would be added in two steps: first the glyph for the 'fi' ligature and the unicode value for 'f'; then glyph `-1` and the unicode value for 'i'.

    :arg font: `Font` object.
    :arg transform: `[a,b,c,d,e,f]`. The transform :ref:`matrix<mutool_run_js_api_matrix>`.
    :arg glyph:
    :arg unicode:
    :arg wmode: `0` for horizontal writing, and `1` for vertical writing.


.. method:: showString(font, transform, string)

    Add a simple string to the `Text` object. Will do font substitution if the font does not have all the unicode characters required.

    :arg font: `Font` object.
    :arg transform: `[a,b,c,d,e,f]`. The transform :ref:`matrix<mutool_run_js_api_matrix>`.
    :arg string: String content for `Text` object.

.. method:: walk(textWalker)

    Call the `showGlyph` method on the `textWalker` object for each glyph in the text object.

    :arg textWalker: The text walker object. A user definable :title:`JavaScript` object which can be used to trigger your own functions on the text methods.


    **Example**

    .. code-block:: javascript

        var myTextWalker = {
            showGlyph: function (font, transform, glyph, unicode, wmode) { ... do whatever ... },
        }

        text.walk(myTextWalker);
