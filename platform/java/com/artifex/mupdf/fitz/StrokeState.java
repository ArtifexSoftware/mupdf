package com.artifex.mupdf.fitz;

import android.graphics.Rect;

public class StrokeState
{
	public static final int FZ_LINECAP_BUTT = 0;
	public static final int FZ_LINECAP_ROUND = 1;
	public static final int FZ_LINECAP_SQUARE = 2;
	public static final int FZ_LINECAP_TRIANGLE = 3;

	public static final int FZ_LINEJOIN_MITER = 0;
	public static final int FZ_LINEJOIN_ROUND = 1;
	public static final int FZ_LINEJOIN_BEVEL = 2;
	public static final int FZ_LINEJOIN_MITER_XPS = 3;

	// Private data
	private long nativeStroke;

	// Construction
	StrokeState(int startCap, int endCap, int lineJoin, float lineWidth, float miterLimit)
	{
		nativeStroke = newNative(startCap, 0, endCap, lineJoin, lineWidth, miterLimit, 0, null);
	}

	StrokeState(int startCap, int dashCap, int endCap, int lineJoin, float lineWidth, float miterLimit, float dashPhase, float dash[])
	{
		nativeStroke = newNative(startCap, dashCap, endCap, lineJoin, lineWidth, miterLimit, dashPhase, dash);
	}

	private native long newNative(int startCap, int dashCap, int endCap, int lineJoin, float lineWidth, float miterLimit, float dashPhase, float dash[]);

	// Private constructor for the C to use. Any objects created by the
	// C are done for purposes of calling back to a java device, and
	// should therefore be considered const. This is fine as we don't
	// currently provide mechanisms for changing individual elements
	// of the StrokeState.
	private StrokeState(long l)
	{
		nativeStroke = l;
	}

	// Operation
	public native void adjustRectForStroke(Rect rect, Matrix ctm);

	// Accessors
	public native int getStartCap();
	public native int getDashCap();
	public native int getEndCap();
	public native int getLineJoin();
	public native float getLineWidth();
	public native float getMiterLimit();
	public native float getDashPhase();
	public native float[] getDashes();

	// Destruction
	public void destroy()
	{
		finalize();
		nativeStroke = 0;
	}

	protected native void finalize();
}
