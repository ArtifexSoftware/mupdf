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

	public native void showGlyph(Font font, Matrix trm, int glyph, int unicode, int wmode);
	public native void showString(Font font, Matrix trm, String string, int wmode);

	public native Rect getBounds(StrokeState stroke, Matrix ctm);

	public void showGlyph(Font font, Matrix trm, int glyph, int unicode) {
		showGlyph(font, trm, glyph, unicode, 0);
	}

	public void showString(Font font, Matrix trm, String string) {
		showString(font, trm, string, 0);
	}

	public native void walk(TextWalker walker);
}
