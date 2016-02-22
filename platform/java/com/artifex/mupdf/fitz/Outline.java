package com.artifex.mupdf.fitz;

public class Outline
{
	private long pointer;

	protected native void finalize();

	public void destroy() {
		finalize();
		pointer = 0;
	}

	private Outline(long p) {
		pointer = p;
	}
}
