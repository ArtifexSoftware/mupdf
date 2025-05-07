.. default-domain:: js

.. highlight:: javascript

PDFGraftMap
===================

The graft map is a structure used to copy objects between different PDF documents,
and track which objects have already been copied so that they can be re-used.

Constructors
------------

.. class:: PDFGraftMap

	|no_new|

Call `PDFDocument.prototype.newGraftMap` to create a graft map.

Instance methods
----------------

.. method:: PDFGraftMap.prototype.graftObject(obj)

	Use the graft map to copy objects, with the ability to remember previously copied objects.

	:param PDFObject object: The object to graft.

	.. code-block::

		var map = document.newGraftMap()
		map.graftObject(obj)

.. method:: PDFGraftMap.prototype.graftPage(to, srcDoc, srcPage)

	Graft a page and its resources at the given page number from the source document to the requested page number in the destination document connected to the map.

	:param number to: The page number to insert the page before. Page numbers start at 0 and -1 means at the end of the document.
	:param PDFDocument srcDoc: Source document.
	:param number srcPage: Source page number.

	.. code-block::

		var map = dstdoc.newGraftMap()
		map.graftObject(-1, srcdoc, 0)
