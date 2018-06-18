package com.artifex.mupdf.fitz;

public class StructuredText
{
	static {
		Context.init();
	}

	private long pointer;

	protected native void finalize();

	public void destroy() {
		finalize();
		pointer = 0;
	}

	private StructuredText(long p) {
		pointer = p;
	}

	public native Quad[] search(String needle);
	public native Quad[] highlight(Point a, Point b);
	public native String copy(Point a, Point b);

	public native TextBlock[] getBlocks();

	public class TextBlock {
		public TextLine[] lines;
		public Rect bbox;
	}

	public class TextLine {
		public TextChar[] chars;
		public Rect bbox;
	}

	public class TextChar {
		public int c;
		public Quad quad;
		public boolean isWhitespace() {
			return Character.isWhitespace(c);
		}
	}

}
