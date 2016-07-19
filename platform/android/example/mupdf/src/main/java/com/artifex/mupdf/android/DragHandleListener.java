package com.artifex.mupdf.android;

public interface DragHandleListener
{
	void onStartDrag(DragHandle handle);

	void onDrag(DragHandle handle);

	void onEndDrag(DragHandle handle);
}
