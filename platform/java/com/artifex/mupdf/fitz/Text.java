package com.artifex.mupdf.fitz;

public class Text implements TextWalker
{
	private long pointer;

	protected native void finalize();

	public void destroy() {
		finalize();
		pointer = 0;
	}

	private native long newNative();
	private native long cloneNative(Text old);

	private Text(long p) {
		pointer = p;
	}

	public Text(Text old) {
		pointer = cloneNative(old);
	}

	public Text() {
		pointer = newNative();
	}

	public native void showGlyph(Font font, boolean vertical, Matrix trm, int glyph, int unicode);

	public native Rect getBounds(StrokeState stroke, Matrix ctm);

	public native void walk(TextWalker walker);
}
