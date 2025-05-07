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

.. attribute:: length

	Number of entries in array and dictionary PDFObjects.

Instance methods
----------------

.. method:: PDFObject.prototype.get(...path)

	Access dictionaries and arrays in the `PDFObject`.

	:param Array<number | string | PDFObject> ...path: The path.
	:returns: `PDFObject`

	.. code-block::

		var dict = pdfDocument.newDictionary()
		var value = dict.get("my_key")
		var arr = pdfDocument.newArray()
		var value = arr.get(1)

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

		obj.delete("my_key")
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

		obj.forEach(function (value,key) {
			console.log("value="+value+",key="+key)
		})

.. method:: PDFObject.prototype.push(item)

	Append item to the end of the object.

	:param PDFObject item:

	.. code-block::

		obj.push("item")

.. method:: PDFObject.prototype.toString()

	Returns the object as a pretty-printed string.

	:returns: string

	.. code-block::

		var str = obj.toString()

.. method:: PDFObject.prototype.valueOf()

	Try to convert a PDF object into a corresponding primitive Javascript value.

	Indirect references are converted to the string "R".

	Names are converted to strings.

	Arrays and dictionaries are not converted.

	:returns: A Javascript value or this.

	.. code-block::

		var val = obj.valueOf()

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

.. method:: PDFObject.prototype.isFilespec()

	Is the object a file specification (or a reference to a file specification).

	:returns: boolean

	.. code-block::

		var val = obj.isFilespec()

PDF streams
------------------------------------------

The only way to access a stream is via an indirect object, since all streams are numbered objects.

.. method:: PDFObject.prototype.isStream()

	*True* if the object is an indirect reference pointing to a stream.

	:returns: boolean

	.. code-block::

		var val = obj.isStream()

.. method:: PDFObject.prototype.readStream()

	Read the contents of the stream object into a `Buffer`.

	:returns: `Buffer`

	.. code-block::

		var buffer = obj.readStream()

.. method:: PDFObject.prototype.readRawStream()

	Read the raw, uncompressed, contents of the stream object into a `Buffer`.

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

Primitive PDF objects such as booleans, names, and numbers can usually be treated like JavaScript values. When that is not sufficient use these functions:

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

	Convert a "text string" to a JavaScript unicode string.

	:returns: string

	.. code-block::

		var val = obj.asString()

.. method:: PDFObject.prototype.asByteString()

	Convert a string to an array of byte values.

	:returns: Uint8Array

	.. code-block::

		var val = obj.asByteString()
