package com.artifex.mupdf.fitz;

public abstract class CDevice extends Device
{
	// Private data
	private Object nativeResource = null;
	protected long nativeInfo = 0;

	// Operation
	public native final void beginPage(Rect rect, Matrix ctm);
	public native final void endPage();

	public native final void fillPath(Path path, int even_odd, Matrix ctm, ColorSpace cs, float color[], float alpha);
	public native final void strokePath(Path path, StrokeState stroke, Matrix ctm, ColorSpace cs, float color[], float alpha);
	public native final void clipPath(Path path, Rect rect, int even_odd, Matrix ctm);
	public native final void clipStrokePath(Path path, Rect rect, StrokeState stroke, Matrix ctm);

	public native final void fillText(Text text, Matrix ctm, ColorSpace cs, float color[], float alpha);
	public native final void strokeText(Text text, StrokeState stroke, Matrix ctm, ColorSpace cs, float color[], float alpha);
	public native final void clipText(Text text, Matrix ctm, int accumulate);
	public native final void clipStrokeText(Text text, StrokeState stroke, Matrix ctm);
	public native final void ignoreText(Text text, Matrix ctm);

	public native final void fillShade(Shade shade, Matrix ctm, float alpha);
	public native final void fillImage(Image img, Matrix ctm, float alpha);
	public native final void fillImageMask(Image img, Matrix ctm, ColorSpace cs, float color[], float alpha);
	public native final void clipImageMask(Image img, Rect rect, Matrix ctm);

	public native final void popClip();

	public native final void beginMask(Rect rect, int luminosity, ColorSpace cs, float bc[]);
	public native final void endMask();
	public native final void beginGroup(Rect rect, int isolated, int knockout, int blendmode, float alpha);
	public native final void endGroup();

	public native final int beginTile(Rect area, Rect view, float xstep, float ystep, Matrix ctm, int id);
	public native final void endTile();

	// Destruction
	public final void destroy()
	{
		finalize();
		nativeDevice = 0;
		nativeResource = null;
		nativeInfo = 0;
	}

	protected native final void finalize();
}
