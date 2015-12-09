package com.artifex.mupdf.fitz;

public class ColorSpace
{
	// Private data
	private long nativeColorSpace;

	// Statics
	public static ColorSpace DeviceGray = new ColorSpace(newDeviceGray());
	public static ColorSpace DeviceRGB = new ColorSpace(newDeviceRGB());
	public static ColorSpace DeviceCMYK = new ColorSpace(newDeviceCMYK());

	private static native long newDeviceGray();
	private static native long newDeviceRGB();
	private static native long newDeviceCMYK();

	// Construction
	private ColorSpace(long l)
	{
		nativeColorSpace = l;
	}

	// Accessors
	public native int getNumComponents();

	// Destruction
	public final void destroy()
	{
		finalize();
		nativeColorSpace = 0;
	}

	protected final native void finalize();
}
