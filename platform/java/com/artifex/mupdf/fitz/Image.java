package com.artifex.mupdf.fitz;
import android.graphics.Bitmap;

public class Image
{
	// Private data
	private long nativeImage = 0;

	// Construction
	Image(Bitmap bm) throws Exception
	{
		if (bm == null)
			throw new Exception("null Bitmap passed to Image");
		nativeImage = newFromBitmapNative(bm, null);
	}

	Image(Bitmap bm, Image mask) throws Exception
	{
		if (bm == null)
			throw new Exception("null Bitmap passed to Image");
		nativeImage = newFromBitmapNative(bm, mask);
	}

	private native final long newFromBitmapNative(Bitmap bm, Image mask);

	// Private constructor for the C to use. Any objects created by the
	// C are done for purposes of calling back to a java device, and
	// should therefore be considered const.
	private Image(long l)
	{
		nativeImage = l;
	}

	// Accessors
	public native int getWidth();
	public native int getHeight();
	public native int getNumComponents();
	public native int getBitsPerComponent();
	public native int getXResolution();
	public native int getYResolution();
	public native boolean getImageMask();
	public native boolean getInterpolate();
	public native Image getMask();

	// FIXME: Get data back?
	// FIXME: Create images from data or java streams?

	// Destruction
	public void destroy()
	{
		finalize();
		nativeImage = 0;
	}

	protected native void finalize();
}
