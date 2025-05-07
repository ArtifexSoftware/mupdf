.. default-domain:: js

.. highlight:: javascript

PDFWidget
===================

Widgets refer to components which make up form items such as buttons, text
inputs and signature fields.

Constructors
------------

.. class:: PDFWidget

	|no_new|

To get the widgets on a page, see `PDFPage.prototype.getWidgets()`.

Instance methods
----------------

.. method:: PDFWidget.prototype.getFieldType()

	Return the :term:`widget type`.

	:returns: string

	.. code-block::

		var type = widget.getFieldType()

.. method:: PDFWidget.prototype.getFieldFlags()

	Return the field flags. Refer to the PDF specification for their
	meanings.

	:returns: number

	.. code-block::

		var flags = widget.getFieldFlags()

.. method:: PDFWidget.prototype.getRect()

	Get the widget bounding box.

	:returns: `Rect`

	.. code-block::

		var rect = widget.getRect()

.. method:: PDFWidget.prototype.setRect(rect)

	Set the widget bounding box.

	:param Rect rect: New desired bounding rectangle.

	.. code-block::

		widget.setRect([0,0,100,100])

.. method:: PDFWidget.prototype.getMaxLen()

	Get maximum allowed length of the string value.

	:returns: number

	.. code-block::

		var length = widget.getMaxLen()

.. method:: PDFWidget.prototype.getValue()

	Get the widget value.

	:returns: string

	.. code-block::

		var value = widget.getValue()

.. method:: PDFWidget.prototype.setTextValue(value)

	Set the widget string value.

	:param string value: New text value.

	.. code-block::

		widget.setTextValue("Hello World!")

.. method:: PDFWidget.prototype.setChoiceValue(value)

	Sets the choice value against the widget.

	:param string value: New choice value.

	.. code-block::

		widget.setChoiceValue("Yes")

.. method:: PDFWidget.prototype.toggle()

	Toggle the state of the widget, returns ``1`` if the state changed.

	:returns: number

	.. code-block::

		var state = widget.toggle()

.. method:: PDFWidget.prototype.getOptions()

	Returns an array of strings which represents the value for each corresponding radio button or checkbox field.

	:returns: Array of string

	.. code-block::

		var options = widget.getOptions()

.. method:: PDFWidget.prototype.getLabel()

	Get the field name as a string.

	:returns: string

	.. code-block::

		var label = widget.getLabel()

.. method:: PDFWidget.prototype.update()

	Update the appearance stream to account for changes to the widget.

	.. code-block::

		widget.update()

.. method:: PDFWidget.prototype.isReadOnly()

	If the value is read only and the widget cannot be interacted with.

	:returns: boolean

	.. code-block::

		var isReadOnly = widget.isReadOnly()

.. method:: PDFWidget.prototype.isMultiline()

	Return whether the widget is multiline.

	:returns: boolean

.. method:: PDFWidget.prototype.isPassword()

	Return whether the widget is a password input.

	:returns: boolean

.. method:: PDFWidget.prototype.isComb()

	Return whether the widget is a text field laid out in "comb" style (forms where you write one character per square).

	:returns: boolean

.. method:: PDFWidget.prototype.isButton()

	Return whether the widget is of "button", "checkbox" or "radiobutton" type.

	:returns: boolean

.. method:: PDFWidget.prototype.isPushButton()

	Return whether the widget is of "button" type.

	:returns: boolean

.. method:: PDFWidget.prototype.isCheckbox()

	Return whether the widget is of "checkbox" type.

	:returns: boolean

.. method:: PDFWidget.prototype.isRadioButton()

	Return whether the widget is of "radiobutton" type.

	:returns: boolean

.. method:: PDFWidget.prototype.isText()

	Return whether the widget is of "text" type.

	:returns: boolean

.. method:: PDFWidget.prototype.isChoice()

	Return whether the widget is of "combobox" or "listbox" type.

	:returns: boolean

.. method:: PDFWidget.prototype.isListBox()

	Return whether the widget is of "listbox" type.

	:returns: boolean

.. method:: PDFWidget.prototype.isComboBox()

	Return whether the widget is of "combobox" type.

	:returns: boolean
