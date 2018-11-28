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
	public static final int TYPE_NOT_WIDGET = -1;
	public static final int TYPE_PUSHBUTTON = 0;
	public static final int TYPE_CHECKBOX = 1;
	public static final int TYPE_RADIOBUTTON = 2;
	public static final int TYPE_TEXT = 3;
	public static final int TYPE_LISTBOX = 4;
	public static final int TYPE_COMBOBOX = 5;
	public static final int TYPE_SIGNATURE = 6;

	public static final int CONTENT_UNRESTRAINED = 0;
	public static final int CONTENT_NUMBER = 1;
	public static final int CONTENT_SPECIAL = 2;
	public static final int CONTENT_DATE = 3;
	public static final int CONTENT_TIME = 4;

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

	public native void setValue(String val);
	public native String getValue();
	public native Quad[] textQuads();

	// These don't change after creation, so are cached in java fields.
	private int kind;
	private int fieldFlags;
	private int contentType; /* text field content type */
	private int maxLen; /* text field max length */
	private String[] options; /* choice field option list */

	public int getKind() { return kind; }
	public int getFieldFlags() { return fieldFlags; }
	public int getMaxLen() { return maxLen; }
	public int getContentType() { return contentType; }
	public String[] getOptions() { return options; }
}
