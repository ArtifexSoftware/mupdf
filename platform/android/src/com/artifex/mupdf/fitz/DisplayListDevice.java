package com.artifex.mupdf.fitz;

import android.graphics.Bitmap;

public final class DisplayListDevice extends CDevice
{
	// Construction
	public DisplayListDevice(DisplayList list)
	{
		nativeDevice = newNative(list);
	}

	private native long newNative(DisplayList list);
}
