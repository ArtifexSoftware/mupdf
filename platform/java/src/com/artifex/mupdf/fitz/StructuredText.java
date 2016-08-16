package com.artifex.mupdf.fitz;

public class StructuredText
{
	private long pointer;

	protected native void finalize();

	public void destroy() {
		finalize();
		pointer = 0;
	}

	private StructuredText(long p) {
		pointer = p;
	}

	public native Rect[] search(String needle);
	public native Rect[] highlight(Rect rect);
	public native String copy(Rect rect);

	public native TextBlock[] getBlocks();

	public class TextBlock
	{
		public TextLine[] lines;
		public Rect bbox;
	}

	public class TextLine
	{
		public TextSpan[] spans;
		public Rect bbox;
	}

	public class TextSpan
	{
		public TextChar[] chars;
		public Rect bbox;
	}

	public class TextChar
	{
		public int c;
		public Rect bbox;

		public boolean isWhitespace()
		{
			return Character.isWhitespace(c);
		}
	}

}
