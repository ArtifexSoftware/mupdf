.. default-domain:: js

.. highlight:: javascript

PDFObject
=========

All functions that take a `PDFObject` apply an automatic translation between
Javascript objects and `PDFObject` using a few basic rules:

-
	``null``, ``true``, ``false``, and numbers are translated directly.

-
	Strings are translated to PDF names, unless they are surrounded by
	parentheses: ``"Foo"`` becomes the ``/Foo`` and ``"(Foo)"`` becomes
	``(Foo)``.

-
	Arrays and dictionaries are recursively translated to PDF arrays and dictionaries.
	Be aware of cycles though! The translation does NOT cope with cyclic references!

|only_mutool|
This automatic translation goes both ways -- entries of PDF dictionaries and
arrays can be accessed like Javascript objects and arrays.

Constructors
------------

.. class:: PDFObject

	|no_new|

Use the methods on a `PDFDocument` instance to create new objects.

Instance properties
-------------------

.. TODO mupdf.js implements "get length()", but what does that mean? will that become a read-only attribute?

.. attribute:: PDFObject.prototype.length

	Number of entries in array and dictionary PDFObjects.

.. TODO does this work in mupdf.js? I imagine so, but I can't easily verify it.

.. attribute:: PDFObject.prototype.[n]

	|only_mutool|

	Get or set the element at index ``n`` in an array.

	See `PDFObject.prototype.get()` and `PDFObject.prototype.put()` for the equivalent in mupdf.js.

	:throws: Error on out of bounds accesses.

	.. code-block::

		var pdfObject = pdfDocument.newArray()
		pdfObject[0] = "hello"
		pdfObject[1] = "world"

.. TODO does this work in mupdf.js? I imagine so, but I can't easily verify it.

.. attribute:: PDFObject.prototype.name

	|only_mutool|

	Access a key named ``name`` in a dictionary. It is both possible to
	get and set its value, but also delete the key entirely.

	See `PDFObject.prototype.get()`, `PDFObject.prototype.put()`, and
	`PDFObject.prototype.delete()` for the equivalent in mupdf.js.

	.. code-block::

		var pages = doc.getTrailer().Root.Pages
		pages.Hello = "world"
		delete pages.Hello

Instance methods
----------------

.. TODO murun doesn't support paths while mupdf.js does

.. method:: PDFObject.prototype.get(...path)

	Access dictionaries and arrays in the `PDFObject`.

	:param Array<number | string | PDFObject> ...path: The path.

	:returns: `PDFObject`

	.. code-block::

		var dict = pdfDocument.newDictionary()
		var value = dict.get("my_key")
		var arr = pdfDocument.newArray()
		var value = arr.get(1)
		var page7 = pdfDocument.getTrailer().get("Root", "Pages", "Kids", 7)

.. method:: PDFObject.prototype.getInheritable()

	For a dictionary, if the requested key does not exist,
	getInheritable() will walk Parent references to parent
	dictionaries and lookup the same key there.

	If no key can be found in any parent or grand-parent or
	grand-grand-parent, all the way up, ``null`` is returned.

	:param PDFObject | string ref: Key or index.

	:returns: The value for the key or index.

	.. code-block:: javascript

		var dict = pdfDocument.newDictionary()
		var grandParent = pdfDocument.newDictionary()
		var grandgrandParent = pdfDocument.newDictionary()
		grandgrandParent.put("my_key", "my_value")
		grandParent.put("Parent", grandgrandParent)
		dict.put("Parent", grandParent)
		var value = dict.getInheritable("my_key")
		var arr = pdfDocument.newArray()
		var value = arr.get(0)

.. method:: PDFObject.prototype.put(key, value)

	Put information into dictionaries and arrays in the `PDFObject`.
	Dictionaries and arrays can also be accessed using normal property syntax: ``obj.Foo = 42; delete obj.Foo; x = obj[5]``.

	:param PDFObject | string | number key: Interpreted as an index for arrays or a key string for dictionaries.
	:param PDFObject | Array | string | number | boolean | null value: The value to set at the array index or for dictionary key.

	.. code-block::

		var dict = pdfDocument.newDictionary()
		dict.put("my_key", "my_value")
		var arr = pdfDocument.newArray()
		arr.put(0, 42)

.. method:: PDFObject.prototype.delete(key)

	Delete a reference from a `PDFObject`.

	:param number | string | PDFObject key:

	.. code-block::

		var dict = pdfDocument.newDictionary()
		dict.put("my_key", "my_value")
		dict.delete("my_key")
		var arr = pdfDocument.newArray()
		arr.put(1, 42)
		arr.delete(1)

.. method:: PDFObject.prototype.resolve()

	If the object is an indirect reference, return the object it points to; otherwise return the object itself.

	:returns: `PDFObject`

	.. code-block::

		var resolvedObj = obj.resolve()

.. method:: PDFObject.prototype.isArray()

	:returns: boolean

	.. code-block::

		var result = obj.isArray()

.. method:: PDFObject.prototype.isDictionary()

	:returns: boolean

	.. code-block::

		var result = obj.isDictionary()

.. method:: PDFObject.prototype.forEach(callback)

	Iterate over all the entries in a dictionary or array and call a function for each value-key pair.

	:param callback: ``(val: PDFObject, key: number | string, self: PDFObject) => void``

	.. code-block::

		obj.forEach(function (value, key) {
			console.log("value="+value+",key="+key)
		})

.. method:: PDFObject.prototype.push(item)

	Append item to the end of the object.

	:param PDFObject item:

	.. code-block::

		obj.push("item")

.. method:: PDFObject.prototype.toString(tight, ascii)

	Returns the object as a pretty-printed string.

	:param boolean tight: Whether to print the object as tightly as possible, or as human-readably as possible.
	:param boolean ascii: Whetehr to print binary data as ascii or as binary data.

	:returns: string

	.. code-block::

		var str = obj.toString()

.. TODO in murun indirect references are do appear to be converted to "R"

.. method:: PDFObject.prototype.valueOf()

	Try to convert a PDF object into a corresponding primitive Javascript value.

	Indirect references are converted to the string "obj 0 R" where obj
	is the PDF object's object number.

	Names are converted to strings.

	Arrays and dictionaries are not converted.

	:returns: A Javascript value or this.

	.. code-block::

		var val = obj.valueOf()

.. method:: PDFObject.prototype.compare(other_obj)

	|only_mutool|

	Compare the object to another one. Returns 0 on match, non-zero
	on mismatch. Streams always mismatch.

	:param PDFObject other:

	:returns: number

	.. code-block:: javascript

		var match = pdfObj.compare(other_obj)

PDF streams
------------------------------------------

The only way to access a stream is via an indirect object, since all streams are numbered objects.

.. method:: PDFObject.prototype.isStream()

	Returns whether the object is an indirect reference pointing to a stream.

	:returns: boolean

	.. code-block::

		var val = obj.isStream()

.. method:: PDFObject.prototype.readStream()

	Read the contents of the stream object into a `Buffer`.

	:returns: `Buffer`

	.. code-block::

		var buffer = obj.readStream()

.. method:: PDFObject.prototype.readRawStream()

	Read the raw, uncompressed, contents of the stream object into a
	`Buffer`.

	:returns: `Buffer`

	.. code-block::

		var buffer = obj.readRawStream()

.. method:: PDFObject.prototype.writeObject(obj)

	Update the object the indirect reference points to.

	:param PDFObject obj:

	.. code-block::

		obj.writeObject(obj)

.. method:: PDFObject.prototype.writeStream(buf)

	Update the contents of the stream the indirect reference points to.
	This will update the "Length", "Filter" and "DecodeParms" automatically.

	:param Buffer | ArrayBuffer | Uint8Array buf:

	.. code-block::

		obj.writeStream(buffer)

.. method:: PDFObject.prototype.writeRawStream(buf)

	Update the contents of the stream the indirect reference points to.
	The buffer must contain already compressed data that matches
	the "Filter" and "DecodeParms". This will update the "Length"
	automatically, but leave the "Filter" and "DecodeParms" untouched.

	:param Buffer | ArrayBuffer | Uint8Array buf:

	.. code-block::

		obj.writeRawStream(buffer)

Primitive Objects
---------------------

Primitive PDF objects such as booleans, names, and numbers can usually be
treated like Javascript values. When that is not sufficient use these
functions:

.. method:: PDFObject.prototype.isNull()

	Returns true if the object is null.

	:returns: boolean

	.. code-block::

		var val = obj.isNull()

.. method:: PDFObject.prototype.isBoolean()

	Returns whether the object is a boolean.

	:returns: boolean

	.. code-block::

		var val = obj.isBoolean()

.. method:: PDFObject.prototype.asBoolean()

	Get the boolean primitive value.

	:returns: boolean

	.. code-block::

		var val = obj.asBoolean()

.. method:: PDFObject.prototype.isInteger()

	Returns whether the object is an integer.

	:returns: boolean

	.. code-block::

		var val = obj.isInteger()

.. method:: PDFObject.prototype.isNumber()

	Returns whether the object is a number.

	:returns: boolean

	.. code-block::

		var val = obj.isNumber()

.. method:: PDFObject.prototype.asNumber()

	Get the number primitive value.

	:returns: number

	.. code-block::

		var val = obj.asNumber()

.. method:: PDFObject.prototype.isName()

	Returns whether the object is a name.

	:returns: boolean

	.. code-block::

		var val = obj.isName()

.. method:: PDFObject.prototype.asName()

	Get the name as a string.

	:returns: string

	.. code-block::

		var val = obj.asName()

.. method:: PDFObject.prototype.isString()

	Returns whether the object is a string.

	:returns: boolean

	.. code-block::

		var val = obj.isString()

.. method:: PDFObject.prototype.asString()

	Convert a "text string" to a Javascript unicode string.

	:returns: string

	.. code-block::

		var val = obj.asString()

.. TODO murun returns an rray of number, is that really equivalent?

.. method:: PDFObject.prototype.asByteString()

	Convert a string to an array of byte values.

	:returns: Uint8Array

	.. code-block::

		var val = obj.asByteString()

.. TODO should this even be here?

.. method:: PDFObject.prototype.isReal()

	|only_mutool|

	Returns whether the object is a PDF real number.

	:returns: boolean

	.. code-block:: javascript

		var val = pdfObj.isReal()

.. TODO getNumber, getName, getString(), should these even be in mutool run!?

.. method:: PDFObject.prototype.getNumber()

	Convert a primitive PDF integer or real object to a
	Javascript number object.

	:returns: number

	.. code-block:: javascript

		var nbr = pdfObj.getNumber()

.. method:: PDFObject.prototype.getName()

	Convert a primitive PDF name object to a Javascript string.

	:returns: string

	.. code-block:: javascript

		var name = pdfObj.getName()

.. method:: PDFObject.prototype.getString()

	Convert a primitive PDF string object to a Javascript string.

	:returns: string

	.. code-block:: javascript

		var str = pdfObj.getString()

.. method:: PDFObject.prototype.isIndirect()

	Is the object an indirect reference.

	:returns: boolean

	.. code-block::

		var val = obj.isIndirect()

.. method:: PDFObject.prototype.asIndirect()

	Return the object number the indirect reference points to.

	:returns: number

	.. code-block::

		var val = obj.asIndirect()
