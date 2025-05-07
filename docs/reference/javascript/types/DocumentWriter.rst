.. default-domain:: js

.. highlight:: javascript

DocumentWriter
===================

DocumentWriter objects are used to create new documents in several formats.

Constructors
------------

.. class:: DocumentWriter(buffer, format, options)

	Create a new document writer to create a document with the specified format and output options. The ``options`` argument is a comma separated list of flags and key-value pairs.

	The output ``format`` and ``options`` are the same as in the `mutool convert <https://mupdf.readthedocs.io/en/latest/mutool-convert.html>`_ command.

	:param Buffer buffer: The buffer to output to.
	:param string format: The file format.
	:param string options: The options as key-value pairs.
	:returns: `DocumentWriter`

	.. code-block::

		var writer = new mupdf.DocumentWriter(buffer, "PDF", "")

Instance methods
----------------

.. method:: DocumentWriter.prototype.beginPage(mediabox)

	Begin rendering a new page. Returns a `Device` that can be used to render the page graphics.

	:param Rect mediaBox: The page size.

	:returns: `Device`

	.. code-block::

		var device = writer.beginPage([0,0,100,100])

.. method:: DocumentWriter.prototype.endPage()

	Finish the page rendering.

	.. code-block::

		writer.endPage()

.. method:: DocumentWriter.prototype.close()

	Finish the document and flush any pending output.

	.. code-block::

		writer.close()
