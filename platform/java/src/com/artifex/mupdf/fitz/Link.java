package com.artifex.mupdf.fitz;

public class Link
{
	public Rect bounds;
	public String uri;

	public Link(Rect bounds, String uri) {
		this.bounds = bounds;
		this.uri = uri;
	}

	public String toString() {
		return "Link(bounds="+bounds+",uri="+uri+")";
	}
}
