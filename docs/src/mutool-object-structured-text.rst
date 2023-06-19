.. Copyright (C) 2001-2023 Artifex Software, Inc.
.. All Rights Reserved.

----

.. default-domain:: js

.. include:: html_tags.rst

.. _mutool_object_structured_text:

.. _mutool_run_js_api_structured_text:

`StructuredText`
----------------------------

`StructuredText` objects hold text from a page that has been analyzed and grouped into blocks, lines and spans. To obtain a `StructuredText` instance use :ref:`Page toStructuredText()<mutool_page_toStructuredText>`.


|instance_methods|

.. method:: search(needle)

    |mutool_tag_wasm_soon|

    Search the text for all instances of `needle`, and return an array with :ref:`rectangles<mutool_run_js_api_rectangle>` of all matches found.

    :arg needle: `String`.
    :return: `[...]`.

    |example_tag|

    .. code-block:: javascript

        var result = sText.search("Hello World!");

    .. |tor_todo| WASM, Even says "TODO" in the mupdf.js source file :)



.. method:: highlight(p, q)

    Return an array with :ref:`rectangles<mutool_run_js_api_rectangle>` needed to highlight a selection defined by the start and end points.

    :arg p: Start point in format `[x,y]`.
    :arg q: End point in format `[x,y]`.

    :return: `[...]`.

    |example_tag|

    .. code-block:: javascript

        var result = sText.highlight([100,100], [200,100]);

    .. |tor_todo| WASM, Even says "TODO" in the mupdf.js source file :)


.. method:: copy(p, q)

    Return the text from the selection defined by the start and end points.

    :arg p: Start point in format `[x,y]`.
    :arg q: End point in format `[x,y]`.

    :return: `String`.


    |example_tag|

    .. code-block:: javascript

        var result = sText.highlight([100,100], [200,100]);


    .. |tor_todo| WASM, Even says "TODO" in the mupdf.js source file :)



.. method:: walk(walker)

    |wasm_tag|

    Walk through the blocks (images or text blocks) of the structured text. For each text block walk over its lines of text, and for each line each of its characters. For each block, line or charcter the walker will have a method called.

    |example_tag|

    .. code-block:: javascript

        var stext = pdfPage.toStructuredText();
        stext.walk({
            beginLine: function (bbox, wmode, direction) {
                print("beginLine", bbox, wmode, direction);
            },
            beginTextBlock: function (bbox) {
                print("beginTextBlock", bbox);
            },
            endLine: function () {
                print("endLine");
            },
            endTextBlock: function () {
                print("endTextBlock");
            },
            onChar: function (utf, origin, font, size, quad, color) {
                print("onChar", utf, origin, font, size, quad, color);
            },
            onImageBlock: function (bbox, transform, image) {
                print("onImageBlock", bbox, transform, image);
            },
        });




.. method:: asJSON()

    |wasm_tag|

    Returns the instance in :title:`JSON` format.

    :return: `String`.

    |example_tag|

    .. code-block:: javascript

        var json = sText.asJSON();
