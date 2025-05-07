.. default-domain:: js

.. highlight:: javascript

TreeArchive
===========

|only_mutool|

Constructors
------------

.. class:: TreeArchive()

	Create a new empty tree archive.

	:returns: `TreeArchive`.

	.. code-block::

		var treeArchive = new mupdf.TreeArchive()

Instance properties
-------------------

.. method:: TreeArchive.prototype.add(name, buffer)

	Add a named buffer to a tree archive.

	:param string name: Name of archive entry to add.
	:param Buffer buffer: Buffer of data to store with the entry.

	.. code-block::

		var buf = new mupdf.Buffer()
		buf.writeLine("hello world!")
		var archive = new mupdf.TreeArchive()
		archive.add("file2.txt", buf)
		print(archive.hasEntry("file2.txt"))
