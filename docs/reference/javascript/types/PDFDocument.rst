.. default-domain:: js

.. highlight:: javascript

PDFDocument
===========

The PDFDocument is a specialized subclass of Document which has additional
methods that are only available for PDF files.

PDF Objects
-----------

A PDF document contains objects: dictionaries, arrays, names, strings, numbers,
booleans, and indirect references.
Some dictionaries also have attached data. These are called streams,
and may be compressed.

At the root of the PDF document is the trailer object; which contains pointers to the meta
data dictionary and the catalog object, which in turn contains references to the pages and
forms and everything else.

Pointers in PDF are called indirect references, and are of the form
32 0 R (where 32 is the object number, 0 is the generation, and R is
magic syntax). All functions in MuPDF dereference indirect
references automatically.

	PDFObjects are always bound to the document that created them. Do
	**NOT** mix and match objects from one document with another
	document!

Constructors
------------

.. class:: PDFDocument()

	Create a brand new PDF document instance that begins empty with no pages.

To open an existing PDF document, use the Document.openDocument function.

Instance methods
----------------

.. method:: PDFDocument.prototype.deletePage(index)

	Deletes a page at a specific index. Zero-indexed.

	:param index: number. 0 = first page of document.

.. method:: PDFDocument.prototype.bake(bakeAnnots, bakeWidgets)

	*Baking* a document changes all the annotations and/or form fields (otherwise known as widgets) in the document into static content. It "bakes" the appearance of the annotations and fields onto the page, before removing the interactive objects so they can no longer be changed.

	Effectively this removes the "annotation or "widget" type of these objects, but keeps the appearance of the objects.

	:param bakeAnnots: boolean Whether to bake annotations or not. Defaults to true.
	:param bakeWidgets: boolean Whether to bake widgets or not. Defaults to true.

.. method:: PDFDocument.prototype.newGraftMap()

	Create a graft map on the destination document, so that objects that have already been copied can be found again. Each graft map should only be used with one source document. Make sure to create a new graft map for each source document used.

	:returns: PDFGraftMap.

	.. code-block::

		var graftMap = doc.newGraftMap()

.. method:: PDFDocument.prototype.graftObject(obj)

	Deep copy an object into the destination document. This function will not remember previously copied objects. If you are copying several objects from the same source document using multiple calls, you should use a graft map instead.

	:param PDFObject obj: The object to graft.

	.. code-block::

		doc.graftObject(obj)

.. method:: PDFDocument.prototype.graftPage(to, srcDoc, srcPage)

	Graft a page and its resources at the given page number from the source document to the requested page number in the document.

	:param number to: The page number to insert the page before. Page numbers start at 0 and -1 means at the end of the document.
	:param PDFDocument srcDoc: Source document.
	:param number srcPage: Source page number.

	This would copy the first page of the source document (0) to the last page (-1) of the current PDF document.

	.. code-block::

		doc.graftPage(-1, srcDoc, 0)

.. _embedded-files:

.. method:: PDFDocument.prototype.deleteEmbeddedFile(filename)

	Delete an embedded file by name.

	:param filename: string. The name of the file.

	.. code-block::

		doc.deleteEmbeddedFile("test.txt")

.. method:: PDFDocument.prototype.getEmbeddedFiles()

	Returns a record of any embedded files on the this PDFDocument.

	:returns: Record<string,PDFObject>

.. method:: PDFDocument.prototype.getEmbeddedFileParams(ref)

	Gets the embedded file parameters from a PDFObject reference.

	:param PDFObject ref: Reference to embedded file params.

	:returns: {filename:string, mimetype:string, size:number, creationDate:Date, modificationDate:Date}

.. method:: PDFDocument.prototype.getEmbeddedFileContents(ref)

	Gets the embedded file content from a PDFObject reference.

	:param PDFObject ref: Reference to embedded file contents.

	:returns: Buffer | null.

.. method:: PDFDocument.prototype.needsPassword()

	Returns true if a password is required to open a password protected PDF.

	:returns: boolean

	.. code-block::

		var needsPassword = document.needsPassword()

.. _authenticate password return values:

.. method:: PDFDocument.prototype.authenticatePassword(password)

	Returns a bitfield value against the password authentication result.

	:param password: string. The password to attempt authentication with.
	:returns: number

	**Return values**

	.. list-table::
		:header-rows: 1

		* - **Bitfield value**
		  - **Description**
		* - 0
		  - Failed
		* - 1
		  - No password needed
		* - 2
		  - Is User password and is okay
		* - 4
		  - Is Owner password and is okay
		* - 6
		  - Is both User & Owner password and is okay

	.. code-block::

		var auth = document.authenticatePassword("abracadabra")

.. method:: PDFDocument.prototype.hasPermission(permission)

	Returns true if the document has permission for the supplied permission parameter.

	:param permission: string The permission to seek for, e.g. "edit".
	:returns: boolean

	**Permission strings**

	.. list-table::
		:header-rows: 1

		* - **String**
		  - **Description**
		* - print
		  - Can print
		* - edit
		  - Can edit
		* - copy
		  - Can copy
		* - annotate
		  - Can annotate
		* - form
		  - Can fill out forms
		* - accessibility
		  - Can copy for accessibility
		* - assemble
		  - Can manage document pages
		* - print-hq
		  - Can print high-quality

	.. code-block::

		var canEdit = document.hasPermission("edit")

.. method:: PDFDocument.prototype.getMetaData(key)

	Return various meta data information. The common keys are: format, encryption, info:ModDate, and info:Title.

	:param key: string.
	:returns: string

	.. code-block::

		var format = document.getMetaData("format")
		var modificationDate = doc.getMetaData("info:ModDate")
		var author = doc.getMetaData("info:Author")

.. method:: PDFDocument.prototype.setMetaData(key, value)

	Set document meta data information field to a new value.

	:param key: string.
	:param value: string.

	.. code-block::

		document.setMetaData("info:Author", "My Name")

.. method:: PDFDocument.prototype.countPages()

	Count the number of pages in the document.

	:returns: number

	.. code-block::

		var numPages = document.countPages()

.. method:: PDFDocument.prototype.loadOutline()

	Returns an array with the outline (also known as "table of contents" or "bookmarks"). In the array is an object for each heading with the property 'title', and a property 'page' containing the page number. If the object has a 'down' property, it contains an array with all the sub-headings for that entry.

	:returns: [OutlineItem]

	.. code-block::

		var outline = document.loadOutline()

.. method:: PDFDocument.prototype.outlineIterator()

	Returns an OutlineIterator for the document outline.

	:returns: OutlineIterator.

	.. code-block::

		var obj = document.outlineIterator()

.. method:: PDFDocument.prototype.resolveLink(link)

	Resolve a document internal link URI to a page index.

	:param uri: string | Link.
	:returns: number

	.. code-block::

		var pageNumber = document.resolveLink(uri)

.. method:: PDFDocument.prototype.resolveLinkDestination(uri)

	Resolve a document internal link URI to a link destination.

	:param uri: string.
	:returns: :ref:Link destination <Glossary_Object_Protocols_Link_Destination_Object>.

	.. code-block::

		var linkDestination = document.resolveLinkDestination(uri)

.. method:: PDFDocument.prototype.formatLinkURI(dest)

	Format a document internal link destination object to a URI string suitable for createLink().

	:param dest: LinkDest. :ref:Link destination <Glossary_Object_Protocols_Link_Destination_Object>.
	:returns: string

	.. code-block::

		var uri = document.formatLinkURI({chapter:0, page:42,
				type:"FitV", x:0, y:0, width:100, height:50, zoom:1})
		document.createLink([0,0,100,100], uri)

.. method:: PDFDocument.prototype.setPageLabels(index, style, prefix, start)

	Sets the page label numbering for the page and all pages following it, until the next page with an attached label.

	:param index: number. The start page index to start labeling from.
	:param style: string. Can be one of the following strings: "" (none), "D" (decimal), "R" (roman numerals upper-case), "r" (roman numerals lower-case), "A" (alpha upper-case), or "a" (alpha lower-case).
	:param prefix: string. Define a prefix for the labels.
	:param start: number The ordinal with which to start numbering.

	.. code-block::

		doc.setPageLabels(0, "D", "Prefix", 1)

.. method:: PDFDocument.prototype.deletePageLabels(index)

	Removes any associated page label from the page.

	:param index: number.

	.. code-block::

		doc.deletePageLabels(0)

.. method:: PDFDocument.prototype.getPageNumbers(label, onlyOne)

	Gets the page numbers with an associated label.

	:param label: string. The label to search for.
	:param onlyOne: boolean. Set to true if you only want to return the first result of a found label.

	:returns: number[]

	.. code-block::

		// find all the pages labeled as "Appendix-A"
		var result = doc.getPageNumbers("Appendix-A")

.. method:: PDFDocument.prototype.getTrailer()

	The trailer dictionary. This contains indirect references to the "Root" and "Info" dictionaries. See: :ref:PDF object access <PDFDocument_Object_Access>.

	:returns: PDFObject

	.. code-block::

		var dict = doc.getTrailer()

.. method:: PDFDocument.prototype.countObjects()

	Return the number of objects in the PDF.
	Object number 0 is reserved, and may not be used for anything. See: :ref:PDF object access <PDFDocument_Object_Access>.

	:returns: number Object count.

	.. code-block::

		var num = doc.countObjects()

.. method:: PDFDocument.prototype.createObject()

	Allocate a new numbered object in the PDF, and return an indirect reference to it. The object itself is uninitialized.

	:returns: PDFObject

	.. code-block::

		var obj = doc.createObject()

.. method:: PDFDocument.prototype.deleteObject(num)

	Delete the object referred to by an indirect reference or its object number.

	:param PDFObject | number num: Delete the referenced object number.

	.. code-block::

		doc.deleteObject(obj)

. method:: PDFDocument.prototype.saveToBuffer(options)

	Saves the document to a Buffer.

	:param string options: See :doc:`/reference/common/pdf-write-options`.
	:returns: `Buffer`

	.. code-block::

		var buffer = doc.saveToBuffer("garbage=2,compress=yes")

. method:: PDFDocument.prototype.save(filename, options)

	Saves the document to a file.

	:param string filename:
	:param string options: -ee :doc:`/reference/common/pdf-write-options`

	.. code-block::

		doc.save("out.pdf", "incremental")

.. method:: PDFDocument.prototype.addObject(obj)

	Add obj to the PDF as a numbered object, and return an indirect reference to it.

	:param obj: any. Object to add.

	:returns: PDFObject

	.. code-block::

		var ref = doc.addObject(obj)

.. method:: PDFDocument.prototype.addStream(buf, obj)

	Create a stream object with the contents of buffer, add it to the PDF, and return an indirect reference to it. If object is defined, it will be used as the stream object dictionary.

	:param buf: AnyBuffer object.
	:param obj: any. The object to add the stream to.

	:returns: PDFObject

	.. code-block::

		var stream = doc.addStream(buffer, object)

.. method:: PDFDocument.prototype.addRawStream(buf, obj)

	Create a stream object with the contents of buffer, add it to the PDF, and return an indirect reference to it. If object is defined, it will be used as the stream object dictionary. The buffer must contain already compressed data that matches "Filter" and "DecodeParms" set in the stream object dictionary.

	:param buf: AnyBuffer object.
	:param obj: any. The object to add the stream to.

	:returns: PDFObject

	.. code-block::

		var stream = doc.addRawStream(buffer, object)

.. method:: PDFDocument.prototype.newNull()

	Create a new null object.

	:returns: PDFObject

	.. code-block::

		var obj = doc.newNull()

.. method:: PDFDocument.prototype.newBoolean(v)

	Create a new boolean object.

	:param v: boolean.

	:returns: PDFObject

	.. code-block::

		var obj = doc.newBoolean(true)

.. method:: PDFDocument.prototype.newInteger(v)

	Create a new integer object.

	:param v: number.

	:returns: PDFObject

	.. code-block::

		var obj = doc.newInteger(1)

.. method:: PDFDocument.prototype.newReal(v)

	Create a new real number object.

	:param v: number.

	:returns: PDFObject

	.. code-block::

		var obj = doc.newReal(7.3)

.. method:: PDFDocument.prototype.newString(v)

	Create a new string object.

	:param v: string.

	:returns: PDFObject

	.. code-block::

		var obj = doc.newString("hello")

.. method:: PDFDocument.prototype.newByteString(v)

	Create a new byte string object.

	:param v: Uint8Array.

	:returns: PDFObject

	.. code-block::

		var obj = doc.newByteString([21, 31])

.. method:: PDFDocument.prototype.newName(v)

	Create a new name object.

	:param v: string.

	:returns: PDFObject

	.. code-block::

		var obj = doc.newName("hello")

.. method:: PDFDocument.prototype.newIndirect(v)

	Create a new indirect object.

	:param v: number.

	:returns: PDFObject

	.. code-block::

		var obj = doc.newIndirect(100)

.. method:: PDFDocument.prototype.newArray(cap)

	Create a new array object.

	:param cap: number. Defaults to 8.

	:returns: PDFObject

	.. code-block::

		var obj = doc.newArray()

.. method:: PDFDocument.prototype.newDictionary(cap)

	Create a new dictionary object.

	:param cap: number. Defaults to 8.

	:returns: PDFObject

	.. code-block::

		var obj = doc.newDictionary()
