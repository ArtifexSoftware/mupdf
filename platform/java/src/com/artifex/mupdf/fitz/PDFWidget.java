package com.artifex.mupdf.fitz;

public class PDFWidget extends PDFAnnotation
{
	static {
		Context.init();
	}

	protected PDFWidget(long p) {
		super(p);
	}

	/* IMPORTANT: Keep in sync with mupdf/pdf/widget.h */
	public static final int TYPE_UNKNOWN = 0;
	public static final int TYPE_BTN_PUSH = 1;
	public static final int TYPE_BTN_CHECK = 2;
	public static final int TYPE_BTN_RADIO = 3;
	public static final int TYPE_TX = 4;
	public static final int TYPE_CH_COMBO = 5;
	public static final int TYPE_CH_LIST = 6;
	public static final int TYPE_SIG = 7;

	public static final int TX_FORMAT_NONE = 0;
	public static final int TX_FORMAT_NUMBER = 1;
	public static final int TX_FORMAT_SPECIAL = 2;
	public static final int TX_FORMAT_DATE = 3;
	public static final int TX_FORMAT_TIME = 4;

	/* Field flags */
	public static final int PDF_FIELD_IS_READ_ONLY = 1;
	public static final int PDF_FIELD_IS_REQUIRED = 1 << 1;
	public static final int PDF_FIELD_IS_NO_EXPORT = 1 << 2;

	/* Text fields */
	public static final int PDF_TX_FIELD_IS_MULTILINE = 1 << 12;
	public static final int PDF_TX_FIELD_IS_PASSWORD = 1 << 13;
	public static final int PDF_TX_FIELD_IS_COMB = 1 << 24;

	/* Button fields */
	public static final int PDF_BTN_FIELD_IS_NO_TOGGLE_TO_OFF = 1 << 14;
	public static final int PDF_BTN_FIELD_IS_RADIO = 1 << 15;
	public static final int PDF_BTN_FIELD_IS_PUSHBUTTON = 1 << 16;

	/* Choice fields */
	public static final int PDF_CH_FIELD_IS_COMBO = 1 << 17;
	public static final int PDF_CH_FIELD_IS_EDIT = 1 << 18;
	public static final int PDF_CH_FIELD_IS_SORT = 1 << 19;
	public static final int PDF_CH_FIELD_IS_MULTI_SELECT = 1 << 21;

	// These don't change after creation, so are cached in java fields.
	private int fieldType;
	private int fieldFlags;
	private int textFormat; /* text field formatting type */
	private int maxLen; /* text field max length */
	private String[] options; /* choice field option list */

	/* All fields */

	public int getFieldType() {
		return fieldType;
	}
	public int getFieldFlags() {
		return fieldFlags;
	}
	public boolean isReadOnly() {
		return (getFieldFlags() & PDF_FIELD_IS_READ_ONLY) != 0;
	}
	public native String getValue();
	public native boolean setValue(String val);

	/* Button fields */

	public boolean isButton() {
		int ft = getFieldType();
		return ft == TYPE_BTN_PUSH || ft == TYPE_BTN_CHECK || ft == TYPE_BTN_RADIO;
	}
	public boolean isPushButton() {
		return getFieldType() == TYPE_BTN_PUSH;
	}
	public boolean isCheckbox() {
		return getFieldType() == TYPE_BTN_CHECK;
	}
	public boolean isRadioButton() {
		return getFieldType() == TYPE_BTN_RADIO;
	}
	public native boolean toggle();

	/* Text fields */

	public boolean isText() {
		return getFieldType() == TYPE_TX;
	}
	public boolean isMultiline() {
		return (getFieldFlags() & PDF_TX_FIELD_IS_MULTILINE) != 0;
	}
	public boolean isPassword() {
		return (getFieldFlags() & PDF_TX_FIELD_IS_PASSWORD) != 0;
	}
	public boolean isComb() {
		return (getFieldFlags() & PDF_TX_FIELD_IS_COMB) != 0;
	}
	public int getMaxLen() {
		return maxLen;
	}
	public int getTextFormat() {
		return textFormat;
	}
	public native boolean setTextValue(String val);

	/* WIP in-line text editing support */
	public native Quad[] textQuads();
	public native void setEditing(boolean state);
	public native boolean isEditing();

	private String originalValue;
	public void startEditing() {
		setEditing(true);
		originalValue = getValue();
	}
	public void cancelEditing() {
		setValue(originalValue);
		setEditing(false);
	}
	public boolean commitEditing(String newValue) {
		setValue(originalValue);
		setEditing(false);
		if (setTextValue(newValue)) {
			return true;
		} else {
			setEditing(true);
			return false;
		}
	}

	/* Choice fields */

	public boolean isChoice() {
		int ft = getFieldType();
		return ft == TYPE_CH_COMBO || ft == TYPE_CH_LIST;
	}
	public boolean isComboBox() {
		return getFieldType() == TYPE_CH_COMBO;
	}
	public boolean isListBox() {
		return getFieldType() == TYPE_CH_LIST;
	}
	public String[] getOptions() {
		return options;
	}
	public native boolean setChoiceValue(String val);
}
