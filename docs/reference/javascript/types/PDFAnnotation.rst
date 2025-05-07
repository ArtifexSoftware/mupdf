.. default-domain:: js

.. highlight:: javascript

PDFAnnotation
#############

PDF Annotations belong to a specific `PDFPage` and may be
created/changed/removed. Because annotation appearances may change (for several
reasons) it is possible to scan through the annotations on a page and query
them to see whether a re-render is necessary.

Additionally redaction annotations can be applied to a `PDFPage`,
destructively removing content from the page.

Annotation Types
================

These are the annotation types, and which attributes they have.

Text
	An icon with a popup of text.

	Set the appearance with the Icon attribute.

	Attributes: Rect, Color, Icon.

FreeText
	Text in a rectangle on the page.

	The text font and color is defined by DefaultAppearance.

	Attributes: Border, Rect, DefaultAppearance.

Line
	A line with optional arrow heads.

	The line width is determined by the border attribute.

	The end points are defined by the Line attribute.

	Attributes: Border, Color, Line, LineEndingStyles.

Square
	A rectangle.

	Attributes: Rect, Border, Color, InteriorColor.

Circle
	An ellipse.

	Attributes: Rect, Border, Color, InteriorColor.

Polygon, PolyLine
	A polygon shape (closed and open).

	The shape is defined by the Vertices attribute.

	The line width is defined by the Border attribute.

	Attributes: Vertices, Border, Color, InteriorColor, LineEndingStyles.

Highlight, Underline, Squiggly, StrikeOut
	Text markups.

	The shape is defined by the QuadPoints.

Stamp
	A rubber stamp.

	The appearance is either a stock name, or a custom image.

Ink
	A free-hand line.

	The shape is defined by the InkList attribute.

FileAttachment
	A file attachment.

	The appearance is an icon on the page.

	Set the attached file contents with the FileSpec attribute,
	and the appearance with the Icon attribute.

Redaction
	A black box.

	Redaction annotations are used to mark areas of the page that
	can be redacted. They do NOT redact any content by themselves,
	you MUST apply them using `PDFAnnotation.prototype.applyRedaction` or
	`PDFPage.prototype.applyRedactions`.

These annotation types are special and handled with other APIs:

- `Link`
- Popup -- see `PDFAnnotation.prototype.setPopup()`
- Widget -- see `PDFWidget`

Constructors
============

.. class:: PDFAnnotation

	|no_new|

To get the annotations on a page use `PDFPage.prototype.getAnnotations()`.

To create a new annotation call `PDFPage.prototype.createAnnotation()`.

Instance methods
================

.. method:: PDFAnnotation.prototype.getBounds()

	Returns a rectangle containing the location and dimension of the annotation.

	:returns: `Rect`

	.. code-block::

		var bounds = annotation.getBounds()

.. method:: PDFAnnotation.prototype.run(device, matrix)

	Calls the device functions to draw the annotation.

	:param Device device: The device to make device calls to while rendering the annotation.
	:param Matrix matrix: The transformation matrix.

	.. code-block::

		annotation.run(device, mupdf.Matrix.identity)

.. method:: PDFAnnotation.prototype.toPixmap(matrix, colorspace, alpha)

	Render the annotation into a `Pixmap`, using the
	``transform``, ``colorspace`` and ``alpha`` parameters.

	:param Matrix matrix: Transformation matrix.
	:param ColorSpace colorspace: The desired colorspace of the returned pixmap.
	:param boolean alpha: Whether the returned pixmap has transparency or not. If the pixmap handles transparency, it starts out transparent (otherwise it is filled white), before the contents of the display list are rendered onto the pixmap.

	:returns: `Pixmap`

	.. code-block::

		var pixmap = annotation.toPixmap(mupdf.Matrix.identity, mupdf.ColorSpace.DeviceRGB, true)

.. method:: PDFAnnotation.prototype.toDisplayList()

	Record the contents of the annotation into a `DisplayList`.

	:returns: `DisplayList`

	.. code-block::

		var displayList = annotation.toDisplayList()

.. method:: PDFAnnotation.prototype.getObject()

	Get the underlying `PDFObject` for an annotation.

	:returns: `PDFObject`

	.. code-block::

		var obj = annotation.getObject()

.. method:: PDFAnnotation.prototype.setAppearance(appearance, state, transform, bbox, resources, contents)

	Set the annotation appearance stream for the given appearance. The
	desired appearance is given as a transform along with a bounding box, a
	PDF dictionary of resources and a content stream.

	:param string appearance: Appearance stream ("N", "R" or "D").
	:param string state: The annotation state to set the appearance for or null for the current state. Only widget annotations of pushbutton, check box, or radio button type have states, which are "Off" or "Yes". For other types of annotations pass null.
	:param Matrix transform: The transformation matrix.
	:param Rect bbox: The bounding box.,
	:param PDFObject resources: Resources object.
	:param string contents: Contents string.

	.. code-block::

		annotation.setAppearance(
			"N",
			null,
			mupdf.Matrix.identity,
			[0, 0, 100, 100],
			resources,
			contents
		)

.. method:: PDFAnnotation.prototype.update()

	Update the appearance stream to account for changes in the annotation.

	.. code-block::

		annotation.update()

.. method:: PDFAnnotation.prototype.setAppearanceFromDisplayList(appearance, state, transform, list)

	Set the annotation appearance stream for the given appearance. The
	desired appearance is given as a transform along with a display list.

	:param string appearance: Appearance stream ("N", "R" or "D").
	:param string state: The annotation state to set the appearance for or null for the current state. Only widget annotations of pushbutton, check box, or radio button type have states, which are "Off" or "Yes". For other types of annotations pass null.
	:param Matrix transform: The transformation matrix.
	:param DisplayList list: The display list.

	.. code-block::

		annotation.setAppearanceFromDisplayList(
			"N",
			null,
			mupdf.Matrix.identity,
			displayList
		)

.. method:: PDFAnnotation.prototype.getHiddenForEditing()

	Get a special annotation hidden flag for editing. This flag prevents the annotation from being rendered.

	:returns: boolean

	.. code-block::

		var hidden = annotation.getHiddenForEditing()

.. method:: PDFAnnotation.prototype.setHiddenForEditing(hidden)

	Set a special annotation hidden flag for editing. This flag prevents the annotation from being rendered.

	:param boolean hidden:

	.. code-block::

		annotation.setHiddenForEditing(true)

.. method:: PDFAnnotation.prototype.applyRedaction(blackBoxes, imageMethod, lineArtMethod, textMethod)

	Applies a single Redaction annotation.

	See `PDFPage.prototype.applyRedactions` for details.

Annotation attributes
=====================

PDF Annotations have many attributes. Some of these are common to all
annotations, and some only exist on specific annotation types.

Common
-------------

.. method:: PDFAnnotation.prototype.getType()

	Return the :term:`annotation type` for this annotation.

	:returns: string

	.. code-block::

		var type = annotation.getType()

.. method:: PDFAnnotation.prototype.getFlags()

	Get the annotation flags.

	See `PDFAnnotation.prototype.setFlags`.

	:returns: number

	.. code-block::

		var flags = annotation.getFlags()

.. method:: PDFAnnotation.prototype.setFlags(flags)

	Set the annotation flags.

	:param number flags: A bit mask with the flags (see below).

	.. table::
		:align: left

		=======	====================
		Bit	Name
		=======	====================
		1	Invisible
		2	Hidden
		3	Print
		4	NoZoom
		5	NoRotate
		6	NoView
		7	ReadOnly
		8	Locked
		9	ToggleNoView
		10	LockedContents
		=======	====================

	.. code-block::

		annotation.setFlags(4); // Clears all other flags and sets "NoZoom".

.. method:: PDFAnnotation.prototype.getContents()

	Get the annotation contents.

	:returns: string

	.. code-block::

		var contents = annotation.getContents()

.. method:: PDFAnnotation.prototype.setContents(text)

	Set the annotation contents.

	:param string text:

	.. code-block::

		annotation.setContents("Hello World")

.. method:: PDFAnnotation.prototype.getCreationDate()

	Get the annotation creation date as a Date object.

	:returns: Date

	.. code-block::

		var date = annotation.getCreationDate()

.. method:: PDFAnnotation.prototype.setCreationDate(date)

	Set the creation date.

	:param Date date: A Date object.

	.. code-block::

		annotation.setCreationDate(new Date())

.. method:: PDFAnnotation.prototype.getModificationDate()

	Get the annotation modification date as a Date object.

	:returns: Date

	.. code-block::

		var date = annotation.getModificationDate()

.. method:: PDFAnnotation.prototype.setModificationDate(date)

	Set the modification date.

	:param Date date:

	.. code-block::

		annotation.setModificationDate(new Date())

.. method:: PDFAnnotation.prototype.getLanguage()

	Get the annotation language (or get the inherited document
	language). These are follow the ISO 3166 and thus start with a two
	character language code with a specialization, e.g. ``"en"``,
	``"kr"``, ``"zh-CN"``, or ``"zh-TW"``.

	:returns: string

	.. code-block::

		var language = annotation.getLanguage()

.. method:: PDFAnnotation.prototype.setLanguage(language)

	Set the annotation language. These are follow the ISO 3166 and
	thus start with a two character language code with a
	specialization, e.g. ``"en"``, ``"kr"``, ``"zh-CN"``, or
	``"zh-TW"``.

	:param string language: The desired language code.

	.. code-block::

		annotation.setLanguage("en")

Rect
----

For annotations that can be resized by setting its bounding box rectangle
(e.g. Square and FreeText), `PDFAnnotation.prototype.hasRect()` returns ``true``.

Other annotation types, (e.g. Line, Polygon, and InkList)
change size by adding/removing vertices.
Yet other annotations (e.g. Highlight and StrikeOut)
change size by adding/removing QuadPoints.

The underlying Rect attribute on the PDF object is automatically updated as needed
for these other annotation types.

.. method:: PDFAnnotation.prototype.hasRect()

	Checks whether the annotation can be resized by setting its
	bounding box.

	:returns: boolean

	.. code-block::

		var hasRect = annotation.hasRect()

.. method:: PDFAnnotation.prototype.getRect()

	Get the annotation bounding box.

	:returns: `Rect`

	.. code-block::

		var rect = annotation.getRect()

.. method:: PDFAnnotation.prototype.setRect(rect)

	Set the annotation bounding box.

	:param Rect rect: The new desired bounding box.

	.. code-block::

		annotation.setRect([0, 0, 100, 100])

Color
-----

The meaning of the color attribute depends on the annotation type. For some it is the color
of the border.

.. method:: PDFAnnotation.prototype.getColor()

	Get the annotation color, represented as an array of 1, 3, or 4 component values.

	:returns: `Color`

	.. code-block::

		var color = annotation.getColor()

.. method:: PDFAnnotation.prototype.setColor(color)

	Set the annotation color, represented as an array of 1, 3, or 4 component values.

	:param Color color: The new color.

	.. code-block::

		annotation.setColor([0, 1, 0])

Opacity
-------

.. method:: PDFAnnotation.prototype.getOpacity()

	Get the annotation :term:`opacity`.

	:returns: number

	.. code-block::

		var opacity = annotation.getOpacity()

.. method:: PDFAnnotation.prototype.setOpacity(opacity)

	Set the annotation :term:`opacity`.

	:param number opacity: The desired opacity.

	.. code-block::

		annotation.setOpacity(0.5)

Quadding
--------

.. method:: PDFAnnotation.prototype.getQuadding()

	Get the annotation quadding (justification). Quadding value, 0
	for left-justified, 1 for centered, 2 for right-justified

	:returns: number

	.. code-block::

		var quadding = annotation.getQuadding()

.. method:: PDFAnnotation.prototype.setQuadding(value)

	Set the annotation quadding (justification). Quadding value, 0
	for left-justified, 1 for centered, 2 for right-justified.

	:param number value: The desired quadding.

	.. code-block::

		annotation.setQuadding(1)

Author
------

.. method:: PDFAnnotation.prototype.hasAuthor()

	Checks whether the annotation has an author.

	:returns: boolean

	.. code-block::

		var hasAuthor = annotation.hasAuthor()

.. method:: PDFAnnotation.prototype.getAuthor()

	Gets the annotation author.

	:returns: string

	.. code-block::

		var author = annotation.getAuthor()

.. method:: PDFAnnotation.prototype.setAuthor(author)

	Sets the annotation author.

	:param string author:

	.. code-block::

		annotation.setAuthor("Jane Doe")

Border
------

.. method:: PDFAnnotation.prototype.hasBorder()

	Check support for the annotation border style.

	:returns: boolean

	.. code-block::

		var hasBorder = annotation.hasBorder()

.. method:: PDFAnnotation.prototype.getBorderStyle()

	Get the annotation :term:`border style`.

	:returns: string

	.. code-block::

		var borderStyle = annotation.getBorderStyle()

.. method:: PDFAnnotation.prototype.setBorderStyle(style)

	Set the annotation :term:`border style`.

	:param string style: The annotation style.

	.. code-block::

		annotation.setBorderStyle("Dashed")

.. method:: PDFAnnotation.prototype.getBorderWidth()

	Get the border width in points.

	:returns: number

	.. code-block::

		var w = annotation.getBorderWidth()

.. method:: PDFAnnotation.prototype.setBorderWidth(width)

	Set the border width in points. Retains any existing border effects.

	:param number width:

	.. code-block::

		annotation.setBorderWidth(1.5)

.. method:: PDFAnnotation.prototype.getBorderDashCount()

	Returns the number of items in the border dash pattern.

	:returns: number

	.. code-block::

		var dashCount = annotation.getBorderDashCount()

.. method:: PDFAnnotation.prototype.getBorderDashItem(idx)

	Returns the length of dash pattern item idx.

	:param number idx:
	:returns: number

	.. code-block::

		var length = annotation.getBorderDashItem(0)

.. method:: PDFAnnotation.prototype.setBorderDashPattern(list)

	Set the annotation border dash pattern to the given array of dash item lengths. The supplied array represents the respective line stroke and gap lengths, e.g. [1, 1] sets a small dash and small gap, [2, 1, 4, 1] would set a medium dash, a small gap, a longer dash and then another small gap.

	:param Array of number dashPattern:

	.. code-block::

		annotation.setBorderDashPattern([2.0, 1.0, 4.0, 1.0])

.. method:: PDFAnnotation.prototype.clearBorderDash()

	Clear the entire border dash pattern for an annotation.

	.. code-block::

		annotation.clearBorderDash()

.. method:: PDFAnnotation.prototype.addBorderDashItem(length)

	Append an item (of the given length) to the end of the border dash pattern.

	:param number length:

	.. code-block::

		annotation.addBorderDashItem(10.0)

.. method:: PDFAnnotation.prototype.hasBorderEffect()

	Check support for annotation border effect.

	:returns: boolean

	.. code-block::

		var hasEffect = annotation.hasBorderEffect()

.. method:: PDFAnnotation.prototype.getBorderEffect()

	Get the :term:`border effect`.

	:returns: string

	.. code-block::

		var effect = annotation.getBorderEffect()

.. method:: PDFAnnotation.prototype.setBorderEffect(effect)

	Set the :term:`border effect`.

	:param string effect: The border effect.

	.. code-block::

		annotation.setBorderEffect("None")

.. method:: PDFAnnotation.prototype.getBorderEffectIntensity()

	Get the annotation border effect intensity.

	:returns: number

	.. code-block::

		var intensity = annotation.getBorderEffectIntensity()

.. method:: PDFAnnotation.prototype.setBorderEffectIntensity(intensity)

	Set the annotation border effect intensity. Recommended values are between 0 and 2 inclusive.

	:param number intensity: Border effect intensity.

	.. code-block::

		annotation.setBorderEffectIntensity(1.5)

Callout
-------

Callouts are used with FreeText annotations and
allow for a graphical line to point to an area on a page.

.. image:: /images/callout-annot.png
		  :alt: Callout annotation
		  :width: 100%

.. method:: PDFAnnotation.prototype.hasCallout()

	Returns whether the annotation is capable of supporting a callout or not.

	:returns: boolean

.. method:: PDFAnnotation.prototype.setCalloutLine(line)

	Takes an array of 2 or 3 points.

	:param Array of Point points:

.. method:: PDFAnnotation.prototype.getCalloutLine()

	Returns the array of points.

	:returns: Array of `Point`

.. method:: PDFAnnotation.prototype.setCalloutPoint(p)

	Takes a point where the callout should point to.

	:param points: `Point`.

.. method:: PDFAnnotation.prototype.getCalloutPoint()

	Returns the callout point.

	:returns: `Point`

.. method:: PDFAnnotation.prototype.setCalloutStyle(style)

	Sets the :term:`line ending style` of the callout line.

	:param string style:

.. method:: PDFAnnotation.prototype.getCalloutStyle()

	Returns the callout style.

	:returns: string

Default Appearance
------------------

.. method:: PDFAnnotation.prototype.hasDefaultAppearance()

	|only_mutool|

	Returns whether the annotation is capable of supporting a bounding
	box.

	:return: boolean

	.. code-block:: javascript

		var hasRect = annotation.hasRect()

.. method:: PDFAnnotation.prototype.getDefaultAppearance()

	Get the default text appearance used for free text annotations
	as an object containing the font, size, and color.

	:returns:
		``{ font: string, size: number, color: Color }``

	.. code-block::

		var appearance = annotation.getDefaultAppearance()
		console.log("DA font:", appearance.font, appearance.size)
		console.log("DA color:", appearance.color)

.. method:: PDFAnnotation.prototype.setDefaultAppearance(font, size, color)

	Set the default text appearance used for free text annotations.

	:param string font: The desired default font: ``"Helv" | "TiRo" | "Cour"`` for Helvetica, Times Roman, and Courier respectively.
	:param number size: The desired default font size.
	:param Color color: The desired default font color.

	.. code-block::

		annotation.setDefaultAppearance("Helv", 16, [0, 0, 0])

FileSpec
--------

.. method:: PDFAnnotation.prototype.hasFileSpec()

	Check support for the annotation file specification.

	:returns: boolean

	.. code-block::

		var hasFileSpec = annotation.hasFileSpec()

.. method:: PDFAnnotation.prototype.getFileSpec()

	Get the :term:`FileSpec` object for the file attachment.

	:returns: `PDFObject`

	.. code-block::

		var fs = annotation.getFileSpec()

.. method:: PDFAnnotation.prototype.setFileSpec(fs)

	Set the :term:`FileSpec` object for the file attachment.

	:param PDFObject fs:

	.. code-block::

		annotation.setFileSpec(fs)

Icon
----

.. method:: PDFAnnotation.prototype.hasIcon()

	Checks the support for annotation icon.

	:returns: boolean

	.. code-block::

		var hasIcon = annotation.hasIcon()

.. method:: PDFAnnotation.prototype.getIcon()

	Get the annotation :term:`icon name`, either a standard or custom name.

	:returns: string

	.. code-block::

		var icon = annotation.getIcon()

.. method:: PDFAnnotation.prototype.setIcon(name)

	Set the annotation :term:`icon name`.

	Note that standard icon names can be used to resynthesize the annotation appearance, but custom names cannot.

	:param string name: An :term:`icon name`.

	.. code-block::

		annotation.setIcon("Note")

Ink List
--------

Ink annotations consist of a number of strokes, each consisting of a sequence of vertices between which a smooth line will be drawn. These can be controlled by:

.. method:: PDFAnnotation.prototype.hasInkList()

	Check support for the annotation ink list.

	:returns: boolean

	.. code-block::

		var hasInkList = annotation.hasInkList()

.. method:: PDFAnnotation.prototype.getInkList()

	Get the annotation ink list, represented as an array of strokes, each an array of points each an array of its X/Y coordinates.

	:returns: Array of Array of `Point`

	.. code-block::

		var inkList = annotation.getInkList()

.. method:: PDFAnnotation.prototype.setInkList(inkList)

	Set the annotation ink list, represented as an array of strokes, each an array of points each an array of its X/Y coordinates.

	:param inkList: Array of Array of `Point`

	.. code-block::

		annotation.setInkList([
			[
				[0, 0]
			],
			[
				[10, 10], [20, 20], [30, 30]
			]
		])

.. method:: PDFAnnotation.prototype.clearInkList()

	Clear the list of ink strokes for the annotation.

	.. code-block::

		annotation.clearInkList()

.. method:: PDFAnnotation.prototype.addInkListStroke()

	Add a new empty stroke to the ink annotation.

	.. code-block::

		annotation.addInkListStroke()

.. method:: PDFAnnotation.prototype.addInkListStrokeVertex(v)

	Append a vertex to end of the last stroke in the ink annotation.

	:param Point v:

	.. code-block::

		annotation.addInkListStrokeVertex([0, 0])

Interior Color
--------------

.. method:: PDFAnnotation.prototype.hasInteriorColor()

	Checks whether the annotation has support for an interior color.

	:returns: boolean

	.. code-block::

		var hasInteriorColor = annotation.hasInteriorColor()

.. method:: PDFAnnotation.prototype.getInteriorColor()

	Gets the annotation interior color.

	:returns: `Color`

	.. code-block::

		var interiorColor = annotation.getInteriorColor()

.. method:: PDFAnnotation.prototype.setInteriorColor(color)

	Sets the annotation interior color.

	:param Color color: The new desired interior color.

	.. code-block::

		annotation.setInteriorColor([0, 1, 1])

Line
----

.. method:: PDFAnnotation.prototype.hasLine()

	Checks the support for annotation line.

	:returns: boolean

	.. code-block::

		var hasLine = annotation.hasLine()

.. method:: PDFAnnotation.prototype.getLine()

	Get line end points, represented by an array of two points, each represented as an [x, y] array.

	:returns: Array of `Point`

	.. code-block::

		var line = annotation.getLine()

.. method:: PDFAnnotation.prototype.setLine(a, b)

	Set the two line end points, each represented as an [x, y] array.

	:param Point a: The new point a.
	:param Point b: The new point b.

	.. code-block::

		annotation.setLine([100, 100], [150, 175])

Line Ending Styles
------------------

.. method:: PDFAnnotation.prototype.hasLineEndingStyles()

	Checks the support for :term:`line ending style`.

	:returns: boolean

	.. code-block::

		var hasLineEndingStyles = annotation.hasLineEndingStyles()

.. method:: PDFAnnotation.prototype.getLineEndingStyles()

	Get the start and end :term:`line ending style` values.

	:returns: ``{start: string, end: string}`` Returns an object with the key/value pairs

	.. code-block::

		var lineEndingStyles = annotation.getLineEndingStyles()

.. method:: PDFAnnotation.prototype.setLineEndingStyles(start, end)

	Sets the :term:`line ending style` object.

	:param string start:
	:param string end:

	.. code-block::

		annotation.setLineEndingStyles("Square", "OpenArrow")

Line Leaders
------------

In a PDF line annotation, "line leaders" refer to visual elements that can be added to the endpoints of a line annotation to enhance its appearance or meaning.

.. image:: /images/leader-lines.png
		  :alt: Leader lines explained
		  :width: 100%

.. method:: PDFAnnotation.prototype.setLineLeader(v)

	Sets the line leader length.

	:param number v:
		The length of leader lines that extend from each endpoint of
		the line perpendicular to the line itself. A positive value
		means that the leader lines appear in the direction that is
		clockwise when traversing the line from its starting point to
		its ending point a negative value indicates the opposite
		direction.

	Setting a value of 0 effectively removes the line leader.

.. method:: PDFAnnotation.prototype.getLineLeader()

	Gets the line leader length.

	:returns: number

.. method:: PDFAnnotation.prototype.setLineLeaderExtension(v)

	Sets the line leader extension.

	:param number v:
		A non-negative number representing the length of leader line
		extensions that extend from the line proper 180 degrees from
		the leader lines.

	Setting a value of 0 effectively removes the line leader extension.

.. method:: PDFAnnotation.prototype.getLineLeaderExtension()

	Gets the line leader extension.

	:returns: number

.. method:: PDFAnnotation.prototype.setLineLeaderOffset(v)

	Sets the line leader offset.

	:param number v:
		A non-negative number representing the length of the leader
		line offset, which is the amount of empty space between the
		endpoints of the annotation and the beginning of the leader
		lines.

	Setting a value of 0 effectively removes the line leader offset.

.. method:: PDFAnnotation.prototype.getLineLeaderOffset()

	Gets the line leader offset.

	:returns: number

.. method:: PDFAnnotation.prototype.setLineCaption(on)

	Sets whether line caption is enabled or not.

	:param boolean on:

	.. note::

		When line captions are enabled then using the `setContents` method on the Line will graphically render the caption contents onto the line.

.. method:: PDFAnnotation.prototype.getLineCaption()

	Returns whether the line caption is enabled or not.

	:returns: boolean

.. method:: PDFAnnotation.prototype.setLineCaptionOffset(point)

	Sets any line caption offset.

	:param point: `Point`. A point, [x, y], specifying the offset of the caption text from its normal position. The first value is the horizontal offset along the annotation line from its midpoint, with a positive value indicating offset to the right and a negative value indicating offset to the left. The second value is the vertical offset perpendicular to the annotation line, with a positive value indicating a shift up and a negative value indicating a shift down.

	.. image:: /images/offset-caption.png
		  :alt: Offset caption explained
		  :width: 100%

	.. note::

		Setting a point of [0, 0] effectively removes the caption offset.

.. method:: PDFAnnotation.prototype.getLineCaptionOffset()

	Returns the line caption offset as a point, [x, y].

	:returns: `Point`

Open
----

Open refers to whether the annotation is display in an open state when the
page is loaded. A Text Note annotation is considered open if the user has
clicked on it to view its contents.

.. method:: PDFAnnotation.prototype.hasOpen()

	Checks the support for annotation open state.

	:returns: boolean

	.. code-block::

		var hasOpen = annotation.hasOpen()

.. method:: PDFAnnotation.prototype.getIsOpen()

	Get annotation open state.

	:returns: boolean

	.. code-block::

		var isOpen = annotation.getIsOpen()

.. method:: PDFAnnotation.prototype.setIsOpen(state)

	Set annotation open state.

	:param boolean state:

	.. code-block::

		annotation.setIsOpen(true)

Popup
-----

.. method:: PDFAnnotation.prototype.hasPopup()

	Checks the support for annotation popup.

	:returns: boolean

	.. code-block::

		var hasPopup = annotation.hasPopup()

.. method:: PDFAnnotation.prototype.getPopup()

	Get annotation popup rectangle.

	:returns: `Rect`

	.. code-block::

		var popupRect = annotation.getPopup()

.. method:: PDFAnnotation.prototype.setPopup(rect)

	Set annotation popup rectangle.

	:param Rect rect: The desired area where the popup should appear.

	.. code-block::

		annotation.setPopup([0, 0, 100, 100])

QuadPoints
----------

Text markup and redaction annotations consist of a set of
quadadrilaterals, or QuadPoints. These are used in e.g. Highlight
annotations to mark up several disjoint spans of text.

.. method:: PDFAnnotation.prototype.hasQuadPoints()

	Check whether the annotation type supports QuadPoints.

	:returns: boolean

	.. code-block::

		var hasQuadPoints = annotation.hasQuadPoints()

.. method:: PDFAnnotation.prototype.getQuadPoints()

	Get the annotation's quadpoints, describing the areas affected by
	text markup annotations and link annotations.

	:returns: Array of `Quad`

	.. code-block::

		var quadPoints = annotation.getQuadPoints()

.. method:: PDFAnnotation.prototype.setQuadPoints(quadList)

	Set the annotation quadpoints describing the areas affected by
	text markup annotations and link annotations.

	:param Array of Quad quadList: The quadpoints to set.

	.. code-block::

		annotation.setQuadPoints([
			[1, 2, 3, 4, 5, 6, 7, 8],
			[1, 2, 3, 4, 5, 6, 7, 8],
			[1, 2, 3, 4, 5, 6, 7, 8]
		])

.. method:: PDFAnnotation.prototype.clearQuadPoints()

	Clear the list of quadpoints for the annotation.

	.. code-block::

		annotation.clearQuadPoints()

.. method:: PDFAnnotation.prototype.addQuadPoint(quad)

	Append a single quadrilateral as an array of 8 elements, where
	each pair are the X/Y coordinates of a corner of the quad.

	:param Quad quad: The quadrilateral to add.

	.. code-block::

		annotation.addQuadPoint([1, 2, 3, 4, 5, 6, 7, 8])

Vertices
--------

Polygon and polyline annotations consist of a sequence of vertices with a straight line between them. Those can be controlled by:

.. method:: PDFAnnotation.prototype.hasVertices()

	Check support for the annotation vertices.

	:returns: boolean

	.. code-block::

		var hasVertices = annotation.hasVertices()

.. method:: PDFAnnotation.prototype.getVertices()

	Get the annotation vertices, represented as an array of vertices each an array of its X/Y coordinates.

	:returns: Array of `Point`

	.. code-block::

		var vertices = annotation.getVertices()

.. method:: PDFAnnotation.prototype.setVertices(vertices)

	Set the annotation vertices, represented as an array of vertices each an array of its X/Y coordinates.

	:param Array of Point vertices:

	.. code-block::

		annotation.setVertices([
			[0, 0],
			[10, 10],
			[20, 20]
		])

.. method:: PDFAnnotation.prototype.clearVertices()

	Clear the list of vertices for the annotation.

	.. code-block::

		annotation.clearVertices()

.. method:: PDFAnnotation.prototype.addVertex(vertex)

	Append a single vertex as an array of its X/Y coordinates.

	:param Point vertex:

	.. code-block::

		annotation.addVertex([0, 0])
