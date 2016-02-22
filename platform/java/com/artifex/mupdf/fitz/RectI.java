package com.artifex.mupdf.fitz;

public class RectI
{
	public int x0;
	public int y0;
	public int x1;
	public int y1;

	public RectI(int x0, int y0, int x1, int y1) {
		this.x0 = x0;
		this.y0 = y0;
		this.x1 = x1;
		this.y1 = y1;
	}

	public RectI(RectI r) {
		this(r.x0, r.y0, r.x1, r.y1);
	}

	public RectI(Rect r) {
		this.x0 = (int)Math.floor(r.x0);
		this.y0 = (int)Math.ceil(r.y0);
		this.x1 = (int)Math.floor(r.x1);
		this.y1 = (int)Math.ceil(r.y1);
	}

	public String toString() {
		return "[" + x0 + " " + y0 + " " + x1 + " " + y1 + "]";
	}

	public RectI transform(Matrix tm) {
		float ax0 = x0 * tm.a;
		float ax1 = x1 * tm.a;

		if (ax0 > ax1) {
			float t = ax0;
			ax0 = ax1;
			ax1 = t;
		}

		float cy0 = y0 * tm.c;
		float cy1 = y1 * tm.c;

		if (cy0 > cy1) {
			float t = cy0;
			cy0 = cy1;
			cy1 = t;
		}
		ax0 += cy0 + tm.e;
		ax1 += cy1 + tm.e;

		float bx0 = x0 * tm.b;
		float bx1 = x1 * tm.b;

		if (bx0 > bx1) {
			float t = bx0;
			bx0 = bx1;
			bx1 = t;
		}

		float dy0 = y0 * tm.d;
		float dy1 = y1 * tm.d;

		if (dy0 > dy1) {
			float t = dy0;
			dy0 = dy1;
			dy1 = t;
		}
		bx0 += dy0 + tm.f;
		bx1 += dy1 + tm.f;

		x0 = (int)Math.floor(ax0);
		x1 = (int)Math.ceil(ax1);
		y0 = (int)Math.floor(bx0);
		y1 = (int)Math.ceil(bx1);

		return this;
	}
}
