package com.artifex.mupdf.android;

import android.content.Context;
import android.graphics.Point;
import android.view.MotionEvent;
import android.view.View;
import android.widget.FrameLayout;

public class DragHandle extends FrameLayout implements View.OnTouchListener
{
	//  for tracking movement
	private int mDragDeltaX;
	private int mDragDeltaY;
	private boolean mIsDragging = false;

	//  the actual current position
	private int mPositionX = 0;
	private int mPositionY = 0;

	//  DragHandleListener
	private DragHandleListener mDragHandleListener;

	//  kinds for selection
	public static final int SELECTION_TOP_LEFT = 1;
	public static final int SELECTION_BOTTOM_RIGHT = 2;

	//  kinds for resizing
	public static final int RESIZE_TOP_LEFT = 3;
	public static final int RESIZE_TOP_RIGHT = 4;
	public static final int RESIZE_BOTTOM_LEFT = 5;
	public static final int RESIZE_BOTTOM_RIGHT = 6;

	//  kind for dragging and rotating
	public static final int DRAG = 7;
	public static final int ROTATE = 8;

	private int mKind = 0;

	public DragHandle(Context context, int resource, int kind)
	{
		super(context);

		mDragHandleListener = null;
		mKind = kind;

		//  inflate with the given resource
		View.inflate(context, resource, this);

		//  set our touch listener
		setOnTouchListener(this);
	}

	public int getKind()
	{
		return mKind;
	}

	//  test to see if this handle is a selection handle
	public boolean isSelectionKind()
	{
		return (mKind == SELECTION_TOP_LEFT || mKind == SELECTION_BOTTOM_RIGHT);
	}

	//  test to see if this handle is a resize handle
	public boolean isResizeKind()
	{
		return (mKind == RESIZE_TOP_LEFT ||
				mKind == RESIZE_TOP_RIGHT ||
				mKind == RESIZE_BOTTOM_LEFT ||
				mKind == RESIZE_BOTTOM_RIGHT);
	}

	//  test to see if this handle is a drag handle
	public boolean isDragKind()
	{
		return (mKind == DRAG);
	}

	//  test to see if this handle is a rotate handle
	public boolean isRotateKind()
	{
		return (mKind == ROTATE);
	}

	public void setDragHandleListener(DragHandleListener listener)
	{
		mDragHandleListener = listener;
	}

	//  this view is shown at the corners of a selection.
	//  We use a touch listener to drag it within its parent.
	//  It's parent is a RelativeLayout, so we effect moving by adjusting
	//  offsets.  The actual top and left are always 0,0.

	@Override
	public boolean onTouch(View view, MotionEvent event)
	{
		final int X = (int) event.getRawX();
		final int Y = (int) event.getRawY();

		final DragHandle theHandle = this;

		switch (event.getAction() & MotionEvent.ACTION_MASK)
		{
			case MotionEvent.ACTION_DOWN:
				Point position = getPosition();
				mDragDeltaX = X - position.x;
				mDragDeltaY = Y - position.y;
				mIsDragging = true;

				if (mDragHandleListener != null)
				{
					mDragHandleListener.onStartDrag(theHandle);
				}

				break;

			case MotionEvent.ACTION_UP:
				mIsDragging = false;

				if (mDragHandleListener != null)
				{
					mDragHandleListener.onEndDrag(theHandle);
				}

				break;

			case MotionEvent.ACTION_MOVE:

				moveTo(X - mDragDeltaX, Y - mDragDeltaY);

				if (mDragHandleListener != null)
				{
					mDragHandleListener.onDrag(theHandle);
				}

				break;
		}
		return true;
	}

	public void show(boolean bShow)
	{
		if (bShow)
			setVisibility(View.VISIBLE);
		else
			setVisibility(View.GONE);
	}

	public Point getPosition()
	{
		return new Point(mPositionX, mPositionY);
	}

	public void moveTo(int x, int y)
	{
		offsetLeftAndRight(x - mPositionX);
		offsetTopAndBottom(y - mPositionY);

		mPositionX = x;
		mPositionY = y;

		invalidate();
	}

	@Override
	protected void onLayout(boolean changed, int left, int top, int right, int bottom)
	{
		super.onLayout(changed, left, top, right, bottom);

		//  we control the position by setting offsets
		//  The actual position is always 0,0.
		//  Because of this, we need to reapply the offsets here.

		offsetLeftAndRight(mPositionX);
		offsetTopAndBottom(mPositionY);
	}

}
