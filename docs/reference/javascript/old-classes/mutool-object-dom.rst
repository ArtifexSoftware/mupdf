.. _mutool_object_xml:

.. _mutool_run_js_api_object_xml:


`DOM`
-------------

|mutool_tag|

This represents an :title:`HTML` or an :title:`DOM` node. It is a helper class intended to access the :title:`DOM` (:title:`Document Object Model`) content of a :ref:`Story<mutool_object_story>` object.


|instance_methods|


.. method:: body()

    Return an `DOM` for the body element.

    :return: `DOM`.

    |example_tag|

    .. code-block:: javascript

        var result = xml.body();


.. method:: documentElement()

    Return an `DOM` for the top level element.

    :return: `DOM`.

    |example_tag|

    .. code-block:: javascript

        var result = xml.documentElement();

.. method:: createElement(tag)

    Create an element with the given tag type, but do not link it into the `DOM` yet.

    :arg tag: `String`.

    :return: `DOM`.

    |example_tag|

    .. code-block:: javascript

        var result = xml.createElement("div");


.. method:: createTextNode(text)

    Create a text node with the given text contents, but do not link it into the `DOM` yet.

    :arg text: `String`.

    :return: `DOM`.

    |example_tag|

    .. code-block:: javascript

        var result = xml.createElement("Hello world!");

.. method:: find(tag, attribute, value)

    Find the element matching the `tag`, `attribute` and `value`. Set either of those to `null` to match anything.

    :arg tag: `String`.
    :arg attribute: `String`.
    :arg value: `String`.

    :return: `DOM`.


    |example_tag|

    .. code-block:: javascript

        var result = xml.find("tag", "attribute", "value");


.. method:: findNext(tag, attribute, value)

    Find the next element matching the `tag`, `attribute` and `value`. Set either of those to `null` to match anything.

    :arg tag: `String`.
    :arg attribute: `String`.
    :arg value: `String`.

    :return: `DOM`.

    |example_tag|

    .. code-block:: javascript

        var result = xml.findNext("tag", "attribute", "value");


.. method:: appendChild(dom, childDom)

    Insert an element as the last child of a parent, unlinking the child from its current position if required.

    :arg dom: `DOM`.
    :arg childDom: `DOM`.

    |example_tag|

    .. code-block:: javascript

        xml.appendChild(dom, childDom);


.. method:: insertBefore(dom, elementDom)

    Insert an element before this element, unlinking the new element from its current position if required.

    :arg dom: `DOM`.
    :arg elementDom: `DOM`.

    |example_tag|

    .. code-block:: javascript

        xml.insertBefore(dom, elementDom);


.. method:: insertAfter(dom, elementDom)

    Insert an element after this element, unlinking the new element from its current position if required.

    :arg dom: `DOM`.
    :arg elementDom: `DOM`.

    |example_tag|

    .. code-block:: javascript

        xml.insertAfter(dom, elementDom);

.. method:: remove()

    Remove this element from the `DOM`. The element can be added back elsewhere if required.

    :return: `DOM`.

    |example_tag|

    .. code-block:: javascript

        var result = xml.remove();


.. method:: clone()

    Clone this element (and its children). The clone is not yet linked into the `DOM`.

    :return: `DOM`.

    |example_tag|

    .. code-block:: javascript

        var result = xml.clone();

.. method:: firstChild()

    Return the first child of the element as a `DOM`, or `null` if no child exist.

    :return: `DOM` \| `null`.

    |example_tag|

    .. code-block:: javascript

        var result = xml.firstChild();

.. method:: parent()

    Return the parent of the element as a `DOM`, or `null` if no parent exists.

    :return: `DOM` \| `null`.

    |example_tag|

    .. code-block:: javascript

        var result = xml.parent();

.. method:: next()

    Return the next element as a `DOM`, or `null` if no such element exists.

    :return: `DOM` \| `null`.


    |example_tag|

    .. code-block:: javascript

        var result = xml.next();

.. method:: previous()

    Return the previous element as a `DOM`, or `null` if no such element exists.

    :return: `DOM` \| `null`.


    |example_tag|

    .. code-block:: javascript

        var result = xml.previous();

.. method:: addAttribute(attribute, value)

    Add attribute with the given value, returns the updated element as an `DOM`.

    :arg attribute: `String`.
    :arg value: `String`.

    :return: `DOM`.

    |example_tag|

    .. code-block:: javascript

        var result = xml.addAttribute("attribute", "value");


.. method:: removeAttribute(attribute)

    Remove the specified attribute from the element.

    :arg attribute: `String`.

    |example_tag|

    .. code-block:: javascript

        xml.removeAttribute("attribute");


.. method:: attribute(attribute)

    Return the element's attribute value as a `String`, or `null` if no such attribute exists.

    :arg attribute: `String`.

    :return: `String` \| `null`.

    |example_tag|

    .. code-block:: javascript

        var result = xml.attribute("attribute");


.. method:: getAttributes()

    Returns a dictionary object with properties and their values corresponding to the element's attributes and their values.

    :return: `{}`.

    |example_tag|

    .. code-block:: javascript

        var dict = xml.getAttributes();
