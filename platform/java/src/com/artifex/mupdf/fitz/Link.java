package com.artifex.mupdf.fitz;

public class Link
{
	public Rect bounds;
	public int page;
	public String uri;

	//  for internal links, the page coordinates
	public float x;
	public float y;

	public Link(Rect bounds, int page, String uri, float x, float y) {
		this.bounds = bounds;
		this.page = page;
		this.uri = uri;
		this.x = x;
		this.y = y;
	}

	public String toString() {
		return "Link(b="+bounds+",page="+page+",uri="+uri+",x="+x+",y="+y+")";
	}
}
