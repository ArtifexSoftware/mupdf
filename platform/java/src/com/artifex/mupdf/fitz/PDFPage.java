package com.artifex.mupdf.fitz;

public class PDFPage extends Page
{
	static {
		Context.init();
	}

	private PDFPage(long p) { super(p); }

	public native PDFAnnotation createAnnotation(int subtype);
	public native void deleteAnnotation(Annotation annot);

	public native boolean update();

	private PDFWidget[] widgets;
	private native PDFWidget[] getWidgetsNative();
	private native long selectWidgetAtNative(int pageX, int pageY);

	public PDFWidget[] getWidgets() {
		if (widgets == null)
			widgets = getWidgetsNative();
		return widgets;
	}

	public PDFWidget selectWidgetAt(int pageX, int pageY) {
		long focus = selectWidgetAtNative(pageX, pageY);
		for (PDFWidget widget : getWidgets())
			if (widget.equals(focus))
				return widget;
		return null;
	}
}
