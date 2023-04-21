.. Copyright (C) 2001-2023 Artifex Software, Inc.
.. All Rights Reserved.

.. default-domain:: js

.. _mutool_object_buffer:

.. _mutool_run_js_api_buffer:





`Buffer`
--------------

`Buffer` objects are used for working with binary data. They can be used much like arrays, but are much more efficient since they only store bytes.



.. method:: new Buffer()

    *Constructor method*.

    Create a new empty buffer.

    :return: `Buffer`.

    **Example**

    .. code-block:: javascript

        var buffer = new Buffer();


.. method:: new Buffer(original)

    *Constructor method*.

    Create a new buffer with a copy of the data from the original buffer.

    :arg original: `Buffer`.

    :return: `Buffer`.


.. method:: readFile(fileName)

    *Constructor method*.

    Create a new buffer with the contents of a file.

    :arg fileName: The path to the file to read.

    :return: `Buffer`.

    **Example**

    .. code-block:: javascript

        var buffer = readFile("my_file.pdf");

----

**Instance properties**



`length`

   The number of bytes in the buffer. `Read-only`.


`[n]`

    Read/write the byte at index 'n'. Will throw exceptions on out of bounds accesses.


    **Example**

    .. code-block:: javascript

        var byte = buffer[0];




----

**Instance methods**

.. method:: writeByte(b)

    Append a single byte to the end of the buffer.

    :arg b: The byte value.


.. method:: writeRune(c)

    Encode a unicode character as UTF-8 and append to the end of the buffer.

    :arg c: The character value.

.. method:: writeLine(...)

    Append arguments to the end of the buffer, separated by spaces, ending with a newline.

    :arg ...: List of arguments.

.. method:: write(...)

    Append arguments to the end of the buffer, separated by spaces.

    :arg ...: List of arguments.

.. method:: writeBuffer(data)

    Append the contents of the 'data' buffer to the end of the buffer.

    :arg data: Data buffer.


.. method:: slice(start end)

    Create a new buffer containing a (subset of) the data in this buffer. Start and end are offsets from the beginning of this buffer, and if negative from the end of this buffer.

    :arg start: Start index.
    :arg start: End index.

    :return: `Buffer`.


.. method:: save(fileName)

    Write the contents of the buffer to a file.

    :arg fileName: Filename to save to.
