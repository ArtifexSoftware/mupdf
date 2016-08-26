package com.artifex.mupdf.android;

import android.content.Context;
import android.graphics.PorterDuff;
import android.support.annotation.ColorInt;
import android.util.AttributeSet;
import android.widget.ImageButton;

public class ToolbarButton extends ImageButton
{
	//  Color.GRAY (0xFF888888) is too dark.  Use something lighter.
	@ColorInt
	private static final int MYGRAY        = 0xFFAAAAAA;

	public ToolbarButton(Context context) {
		super(context);
	}

	public ToolbarButton(Context context, AttributeSet attrs) {
		super(context, attrs);
	}

	@Override public void setEnabled(boolean enabled)
	{
		super.setEnabled(enabled);
		if (enabled)
			setColorFilter(null);
		else
			setColorFilter(MYGRAY, PorterDuff.Mode.SRC_IN);
	}
}
