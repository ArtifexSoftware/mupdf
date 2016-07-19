package com.artifex.mupdf.android;


import android.content.Context;
import android.graphics.Point;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.util.DisplayMetrics;
import android.util.Log;
import android.util.TypedValue;
import android.view.View;
import android.widget.RelativeLayout;

import com.artifex.mupdf.fitz.R;

public class DocView extends DocViewBase implements DragHandleListener
{
	//  selection handles
	private DragHandle mSelectionHandleTopLeft = null;
	private DragHandle mSelectionHandleBottomRight = null;

	//  dot size and padding
	private int selectionHandlePadPx;
	private int selectionHandleSizePx;

	//  selection
	DocPageView selectionStartPage = null;
	Point selectionStartLoc = new Point();
	DocPageView selectionEndPage = null;
	Point selectionEndLoc = new Point();

	public DocView(Context context)
	{
		super(context);
		initialize(context);
	}

	public DocView(Context context, AttributeSet attrs)
	{
		super(context, attrs);
		initialize(context);
	}

	public DocView(Context context, AttributeSet attrs, int defStyle)
	{
		super(context, attrs, defStyle);
		initialize(context);
	}

	private void initialize(Context context)
	{
		DisplayMetrics metrics = context.getResources().getDisplayMetrics();

		int padDp = context.getResources().getInteger(R.integer.selection_dot_padding);
		int sizeDp = context.getResources().getInteger(R.integer.selection_dot_size);

		TypedValue outValue = new TypedValue();
		getResources().getValue(R.dimen.selection_dot_scale, outValue, true);
		float scale = outValue.getFloat();

		selectionHandlePadPx = (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, padDp, metrics);
		selectionHandleSizePx = (int) (scale * TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, sizeDp, metrics));
		selectionHandleSizePx = selectionHandleSizePx * 8 / 10;
	}

	//  create the selection handles
	public void setupHandles(RelativeLayout layout)
	{
		//  selection handles
		mSelectionHandleTopLeft = setupHandle(layout, DragHandle.SELECTION_TOP_LEFT);
		mSelectionHandleBottomRight = setupHandle(layout, DragHandle.SELECTION_BOTTOM_RIGHT);
	}

	//  create a single DragHandle of a particular kind
	private DragHandle setupHandle(RelativeLayout layout, int kind)
	{
		//  create
		DragHandle dh;
		if (kind == DragHandle.DRAG)
			dh = new DragHandle(getContext(), R.layout.drag_handle, kind);
		else if (kind == DragHandle.ROTATE)
			dh = new DragHandle(getContext(), R.layout.rotate_handle, kind);
		else
			dh = new DragHandle(getContext(), R.layout.resize_handle, kind);

		//  add to the layout, initially hidden
		layout.addView(dh);
		dh.show(false);

		//  establish the listener
		dh.setDragHandleListener(this);

		return dh;
	}

	//  show or hide the selection handles
	private void showSelectionHandles(boolean show)
	{
		mSelectionHandleTopLeft.show(show);
		mSelectionHandleBottomRight.show(show);
	}

	private boolean getSelectionHandlesVisible()
	{
		return (mSelectionHandleTopLeft.getVisibility() == View.VISIBLE);
	}

	@Override
	protected void doSingleTap(float fx, float fy)
	{
		//  find the page view that was tapped.
		Point p = eventToScreen(fx, fy);
		final DocPageView dpv = findPageViewContainingPoint(p.x, p.y, false);
		if (dpv == null)
			return;

		if (getSelectionHandlesVisible())
		{
			//  hide handles and remove selection from pages
			showSelectionHandles(false);
			int numPages = getPageCount();
			for (int i = 0; i < numPages; i++)
			{
				DocPageView cv = (DocPageView) getOrCreateChild(i);
				cv.removeHighlight();
				if (cv.isReallyVisible())
					cv.invalidate();
			}
		}
		else
		{
			//  point in screen coordinates, result in page coordinates
			Rect r = dpv.getTappedRect(p);
			if (r != null)
			{
				//  show handles
				showSelectionHandles(true);

				//  set highlight boundaries
				selectionStartPage = dpv;
				selectionStartLoc.set(r.left, r.top);
				selectionEndPage = dpv;
				selectionEndLoc.set(r.right, r.bottom);

				//  do highlight
				doHighlight();

				moveHandlesToCorners();
			}
		}
	}

	private void doHighlight()
	{
		//  TODO: for now, we're dealing with one page at a time
		int numPages = getPageCount();
		for (int i = 0; i < numPages; i++)
		{
			DocPageView cv = (DocPageView) getOrCreateChild(i);
			if (cv.isReallyVisible() && cv == selectionStartPage && cv == selectionEndPage)
			{
				cv.setHighlight(selectionStartLoc, selectionEndLoc);
				logSelectedText();
			}
			else
			{
				cv.removeHighlight();
			}
			cv.invalidate();
		}
	}

	@Override
	protected void doDoubleTap(float fx, float fy)
	{

	}

	private Point viewToScreen(Point p)
	{
		Point newPoint = new Point(p);

		Rect r = new Rect();
		this.getGlobalVisibleRect(r);

		newPoint.offset(r.left, r.top);

		return newPoint;
	}

	//  position a handle, given page coordinates
	protected void positionHandle(DragHandle handle, DocPageView dpv, int pageX, int pageY)
	{
		if (handle != null)
		{
			//  convert to DocPageView-based coords
			Point p = dpv.pageToView(pageX, pageY);

			//  offset to 0,0
			p.offset(dpv.getLeft(), dpv.getTop());

			//  offset to position in the scrolling view (this)
			p.offset(-getScrollX(), -getScrollY());

			//  offset based on handle size and padding
			p.offset(-selectionHandlePadPx - selectionHandleSizePx / 2, -selectionHandlePadPx - selectionHandleSizePx / 2);

			//  move it
			handle.moveTo(p.x, p.y);
		}
	}

	@Override
	public void onStartDrag(DragHandle handle)
	{

	}

	@Override
	public void onDrag(DragHandle handle)
	{
		if (handle == mSelectionHandleTopLeft)
		{
			Point p1 = mSelectionHandleTopLeft.getPosition();
			p1.offset(selectionHandlePadPx + selectionHandleSizePx / 2, selectionHandlePadPx + selectionHandleSizePx / 2);
			p1 = viewToScreen(p1);
			DocPageView pageView1 = findPageViewContainingPoint(p1.x, p1.y, false);
			if (pageView1 != null)
			{
				selectionStartPage = pageView1;
				p1 = pageView1.screenToPage(p1);
				selectionStartLoc.set(p1.x, p1.y);
			}
		}

		if (handle == mSelectionHandleBottomRight)
		{
			Point p2 = mSelectionHandleBottomRight.getPosition();
			p2.offset(selectionHandlePadPx + selectionHandleSizePx / 2, selectionHandlePadPx + selectionHandleSizePx / 2);
			p2 = viewToScreen(p2);
			DocPageView pageView2 = findPageViewContainingPoint(p2.x, p2.y, false);
			if (pageView2 != null)
			{
				selectionEndPage = pageView2;
				p2 = pageView2.screenToPage(p2);
				selectionEndLoc.set(p2.x, p2.y);
			}
		}

		doHighlight();
	}

	@Override
	public void onEndDrag(DragHandle handle)
	{
		moveHandlesToCorners();
		logSelectedText();
	}

	private void logSelectedText()
	{
		int numPages = getPageCount();
		for (int i = 0; i < numPages; i++)
		{
			DocPageView cv = (DocPageView) getOrCreateChild(i);
			String s = cv.getSelectedText();
			if (s != null)
			{
				Log.i("example", s);
			}
		}
	}

	@Override
	protected void onLayout(boolean changed, int left, int top, int right, int bottom)
	{

		super.onLayout(changed, left, top, right, bottom);

		moveHandlesToCorners();
	}

	private void moveHandlesToCorners()
	{
		if (selectionStartPage != null && selectionEndPage != null)
		{
			positionHandle(mSelectionHandleTopLeft, selectionStartPage, selectionStartLoc.x, selectionStartLoc.y);
			positionHandle(mSelectionHandleBottomRight, selectionEndPage, selectionEndLoc.x, selectionEndLoc.y);
		}
	}
}
