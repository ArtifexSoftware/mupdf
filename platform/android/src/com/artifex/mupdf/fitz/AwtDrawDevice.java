package com.artifex.mupdf.fitz;

public final class AwtDrawDevice extends CDevice
{
	// Construction
	public AwtDrawDevice(int rgba[], int width, int height)
	{
		nativeDevice = newNative(rgba, width, height);
	}

	private native long newNative(int rgba[], int width, int height);
}
