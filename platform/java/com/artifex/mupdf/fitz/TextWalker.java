package com.artifex.mupdf.fitz;

public interface TextWalker
{
	public void showGlyph(Font font, boolean vertical, Matrix trm, int glyph, int unicode);
}
