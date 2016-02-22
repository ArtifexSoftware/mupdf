package com.artifex.mupdf.fitz;

public abstract class Device
{
	/* Flags */
	public static final int FZ_DEVFLAG_MASK = 1;
	public static final int FZ_DEVFLAG_COLOR = 2;
	public static final int FZ_DEVFLAG_UNCACHEABLE = 4;
	public static final int FZ_DEVFLAG_FILLCOLOR_UNDEFINED = 8;
	public static final int FZ_DEVFLAG_STROKECOLOR_UNDEFINED = 16;
	public static final int FZ_DEVFLAG_STARTCAP_UNDEFINED = 32;
	public static final int FZ_DEVFLAG_DASHCAP_UNDEFINED = 64;
	public static final int FZ_DEVFLAG_ENDCAP_UNDEFINED = 128;
	public static final int FZ_DEVFLAG_LINEJOIN_UNDEFINED = 256;
	public static final int FZ_DEVFLAG_MITERLIMIT_UNDEFINED = 512;
	public static final int FZ_DEVFLAG_LINEWIDTH_UNDEFINED = 1024;

	/* PDF 1.4 -- standard separable */
	public static final int FZ_BLEND_NORMAL = 0;
	public static final int FZ_BLEND_MULTIPLY = 1;
	public static final int FZ_BLEND_SCREEN = 2;
	public static final int FZ_BLEND_OVERLAY = 3;
	public static final int FZ_BLEND_DARKEN = 4;
	public static final int FZ_BLEND_LIGHTEN = 5;
	public static final int FZ_BLEND_COLOR_DODGE = 6;
	public static final int FZ_BLEND_COLOR_BURN = 7;
	public static final int FZ_BLEND_HARD_LIGHT = 8;
	public static final int FZ_BLEND_SOFT_LIGHT = 9;
	public static final int FZ_BLEND_DIFFERENCE = 10;
	public static final int FZ_BLEND_EXCLUSION = 11;

	/* PDF 1.4 -- standard non-separable */
	public static final int FZ_BLEND_HUE = 12;
	public static final int FZ_BLEND_SATURATION = 13;
	public static final int FZ_BLEND_COLOR = 14;
	public static final int FZ_BLEND_LUMINOSITY = 15;

	/* For packing purposes */
	public static final int FZ_BLEND_MODEMASK = 15;
	public static final int FZ_BLEND_ISOLATED = 16;
	public static final int FZ_BLEND_KNOCKOUT = 32;

	/* To implement your own device in Java, you should define your own
	 * class that extends this one, and override as many of the following
	 * functions as is appropriate. For example:
	 *
	 * class ImageTraceDevice extends Device
	 * {
	 *	void fillImage(Image img, Matrix ctx, float alpha) {
	 *		Debug.Log("Image!");
	 *	}
	 * };
	 *
	 * There is no constructor here, as no one will ever construct a
	 * Device without subclassing.
	 */

	/* Everything under here is private implementation details.
	 * Ideally we'd like to hide these from prying eyes, but Java doesn't
	 * allow that.
	 */

	public static final int FZ_IGNORE_IMAGE = 1;
	public static final int FZ_IGNORE_SHADE = 2;

	/* None of our device functions do anything. Anyone interested will
	 * override them in a subclass either in Java, or (as a subclass of
	 * CDevice) in C.
	 */
	public void beginPage(Rect rect, Matrix ctm)
	{
	}

	public void endPage()
	{
	}

	public void fillPath(Path path, int even_odd, Matrix ctm, ColorSpace cs, float color[], float alpha)
	{
	}

	public void strokePath(long ctx, Path path, StrokeState stroke, Matrix ctm, ColorSpace cs, float color[], float alpha)
	{
	}

	public void clipPath(Path path, Rect rect, int even_odd, Matrix ctm)
	{
	}

	public void clipStrokePath(Path path, Rect rect, StrokeState stroke, Matrix ctm)
	{
	}

	public void fillText(Text text, Matrix ctm, ColorSpace cs, float color[], float alpha)
	{
	}

	public void strokeText(Text text, StrokeState stroke, Matrix ctm, ColorSpace cs, float color[], float alpha)
	{
	}

	public void clipText(Text text, Matrix ctm)
	{
	}

	public void clipStrokeText(Text text, StrokeState stroke, Matrix ctm)
	{
	}

	public void ignoreText(Text text, Matrix ctm)
	{
	}

	public void fillShade(Shade shade, Matrix ctm, float alpha)
	{
	}

	public void fillImage(Image img, Matrix ctm, float alpha)
	{
	}

	public void fillImageMask(Image img, Matrix ctm, ColorSpace cs, float color[], float alpha)
	{
	}

	public void clipImageMask(Image img, Rect rect, Matrix ctm)
	{
	}

	public void popClip()
	{
	}

	public void beginMask(Rect rect, int luminosity, ColorSpace cs, float bc[])
	{
	}

	public void endMask()
	{
	}

	public void beginGroup(Rect rect, int isolated, int knockout, int blendmode, float alpha)
	{
	}

	public void endGroup()
	{
	}

	public int beginTile(Rect area, Rect view, float xstep, float ystep, Matrix ctm, int id)
	{
		return 0;
	}

	public void endTile()
	{
	}

	/* An accessor for device hints */
	final native int getHints();
	final native void enableDeviceHints(int hints);
	final native void disableDeviceHints(int hints);

	// Destruction
	public void destroy()
	{
	}

	// Private data.
	// All java devices MUST leave this as 0.
	protected long nativeDevice;
}
