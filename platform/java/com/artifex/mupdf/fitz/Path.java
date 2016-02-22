package com.artifex.mupdf.fitz;

public class Path implements PathProcessor
{
	// Private data
	private long nativePath = 0;

	// Construction
	public Path()
	{
		nativePath = newNative();
	}

	private native long newNative();

	private Path(long path)
	{
		nativePath = path;
	}

	public Path(Path old)
	{
		nativePath = clone(old);
	}

	private native long clone(Path old);

	// Operation
	public native Point currentPoint();

	public void moveTo(Point xy)
	{
		moveTo(xy.x, xy.y);
	}

	public native void moveTo(float x, float y);

	public void lineTo(Point xy)
	{
		lineTo(xy.x, xy.y);
	}

	public native void lineTo(float x, float y);

	public void curveTo(Point c1, Point c2, Point e)
	{
		curveTo(c1.x, c1.y, c2.x, c2.y, e.x, e.y);
	}

	public native void curveTo(float cx1, float cy1, float cx2, float cy2, float ex, float ey);

	public void curveToV(Point c, Point e)
	{
		curveToV(c.x, c.y, e.x, e.y);
	}

	public native void curveToV(float cx, float cy, float ex, float ey);

	public void curveToY(Point c, Point e)
	{
		curveToY(c.x, c.y, e.x, e.y);
	}

	public native void curveToY(float cx, float cy, float ex, float ey);

	public native void close();

	public native void transform(Matrix mat);

	public native Rect bound(StrokeState stroke, Matrix ctm);

	public native void process(PathProcessor proc);

	// Destruction
	public void destroy()
	{
		finalize();
		nativePath = 0;
	}

	protected native void finalize();
}
