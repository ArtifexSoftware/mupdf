.. default-domain:: js

.. highlight:: javascript

FileSpecification
=================

This object is used to represent a file.

In order to retrieve information from this object see the relevant
methods on `PDFDocument`.

This Object contains metadata about a filespec, it has properties for:

``filename``
    The name of the embedded file.

``mimetype``
    The MIME type of the embedded file, or ``undefined`` if none exists.

``size``
    The size in bytes of the embedded file contents.

``creationDate``
    The creation date of the embedded file.

``modificationDate``
    The modification date of the embedded file.
