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

	public native boolean setTextValue(String val);
	public native boolean setValue(String val);
	public native String getValue();
	public native Quad[] textQuads();
	public native void setEditingState(boolean state);
	public native boolean getEditingState();
	public native boolean toggle();

	// These don't change after creation, so are cached in java fields.
	private int kind;
	private int fieldFlags;
	private int textFormat; /* text field formatting type */
	private int maxLen; /* text field max length */
	private String[] options; /* choice field option list */

	public int getKind() { return kind; }
	public int getFieldFlags() { return fieldFlags; }
	public int getMaxLen() { return maxLen; }
	public int getTextFormat() { return textFormat; }
	public String[] getOptions() { return options; }
}
