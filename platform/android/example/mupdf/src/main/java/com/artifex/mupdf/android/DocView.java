package com.artifex.mupdf.android;


import android.content.Context;
import android.graphics.Point;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.util.DisplayMetrics;
import android.util.TypedValue;
import android.view.MotionEvent;
import android.widget.RelativeLayout;
import android.widget.Toast;

import com.artifex.mupdf.fitz.Page;
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

	//  searching
	//  what we're searching for
	private String mSearchNeedle = "";
	//  current page we're searching
	private int mSearchPage = 0;
	//  array of matching rects
	private com.artifex.mupdf.fitz.Rect mSearchRects[] = null;
	//  index into the array
	private int mSearchIndex = -1;

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

	@Override
	protected void doSingleTap(float fx, float fy)
	{
		//  find the page view that was tapped.
		Point p = eventToScreen(fx, fy);
		final DocPageView dpv = findPageViewContainingPoint(p.x, p.y, false);
		if (dpv == null)
			return;

		if (!getDrawMode())
		{
			if (dpv.onSingleTap(p.x, p.y))
			{
				onChangeSelection();
				return;
			}
			onChangeSelection();
		}

		if (hasSelection())
		{
			clearSelection();
			onChangeSelection();
		}
		else
		{
			//  point in screen coordinates, result in page coordinates
			Rect r = dpv.selectWord(p);
			if (r != null)
			{
				showSelectionHandles(true);

				selectionStartPage = dpv;
				selectionStartLoc.set(r.left, r.top);
				selectionEndPage = dpv;
				selectionEndLoc.set(r.right, r.bottom);

				moveHandlesToCorners();

				onChangeSelection();
			}
		}
	}

	private void clearSelection()
	{
		selectionStartPage = null;
		selectionEndPage = null;
		showSelectionHandles(false);
		int numPages = getPageCount();
		for (int i = 0; i < numPages; i++)
		{
			DocPageView cv = (DocPageView) getOrCreateChild(i);
			cv.removeSelection();
			if (cv.isReallyVisible())
				cv.invalidate();
		}
	}

	public boolean hasSelection()
	{
		return (selectionStartPage != null && selectionEndPage != null);
	}

	public boolean hasInkAnnotationSelected()
	{
		int numPages = getPageCount();
		for (int i = 0; i < numPages; i++)
		{
			DocPageView cv = (DocPageView) getOrCreateChild(i);
			if (cv.hasInkAnnotationSelected())
				return true;
		}

		return false;
	}

	public void setSelectedInkLineColor(int val)
	{
		int numPages = getPageCount();
		for (int i = 0; i < numPages; i++)
		{
			DocPageView cv = (DocPageView) getOrCreateChild(i);
			if (cv.hasInkAnnotationSelected())
				cv.setSelectedInkLineColor(val);
		}
	}

	public void setSelectedInkLineThickness(float val)
	{
		int numPages = getPageCount();
		for (int i = 0; i < numPages; i++)
		{
			DocPageView cv = (DocPageView) getOrCreateChild(i);
			if (cv.hasInkAnnotationSelected())
				cv.setSelectedInkLineThickness(val);
		}
	}

	private void onChangeSelection()
	{
		if (mSelectionChangeListener != null)
			mSelectionChangeListener.onSelectionChanged();
	}

	private SelectionChangeListener mSelectionChangeListener = null;
	public void setSelectionChangeListener (SelectionChangeListener l) {mSelectionChangeListener = l;}
	public interface SelectionChangeListener
	{
		public void onSelectionChanged();
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
				onChangeSelection();
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
				onChangeSelection();
			}
		}

		//  TODO: for now, we're dealing with one page at a time
		int numPages = getPageCount();
		for (int i = 0; i < numPages; i++)
		{
			DocPageView cv = (DocPageView) getOrCreateChild(i);
			if (cv.isReallyVisible() && cv == selectionStartPage && cv == selectionEndPage)
			{
				cv.setSelection(selectionStartLoc, selectionEndLoc);
			}
			else
			{
				cv.removeSelection();
			}
			cv.invalidate();
		}
	}

	@Override
	public void onEndDrag(DragHandle handle)
	{
		moveHandlesToCorners();
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
			Point p1 = selectionStartPage.getSelectionStart();
			Point p2 = selectionEndPage.getSelectionEnd();

			if (p1 != null && p2 != null)
			{
				selectionStartLoc.set(p1.x, p1.y);
				selectionEndLoc.set(p2.x, p2.y);
				positionHandle(mSelectionHandleTopLeft, selectionStartPage, selectionStartLoc.x, selectionStartLoc.y);
				positionHandle(mSelectionHandleBottomRight, selectionEndPage, selectionEndLoc.x, selectionEndLoc.y);
			}
		}
	}

	//  clear the selection on all pages
	private void removeSearchHighlights()
	{
		int numPages = getPageCount();
		for (int i = 0; i < numPages; i++)
		{
			DocPageView cv = (DocPageView) getOrCreateChild(i);
			cv.setSearchHighlight(null);
		}
	}

	//  change what's being searched for
	private void setNeedle(String needle)
	{
		if (!needle.equals(mSearchNeedle))
		{
			mSearchNeedle = needle;
			mSearchRects = null;
		}
	}

	public void onSearchNext(String needle)
	{
		setNeedle(needle);
		removeSearchHighlights();

		if (doSearch(1, mSearchPage))
		{
			DocPageView dpv = (DocPageView)getOrCreateChild(mSearchPage);
			dpv.setSearchHighlight(mSearchRects[mSearchIndex]);
			scrollRectIntoView(mSearchPage, mSearchRects[mSearchIndex]);
		}
	}

	public void onSearchPrevious(String needle)
	{
		setNeedle(needle);
		removeSearchHighlights();

		if (doSearch(-1, mSearchPage))
		{
			DocPageView dpv = (DocPageView)getOrCreateChild(mSearchPage);
			dpv.setSearchHighlight(mSearchRects[mSearchIndex]);
			scrollRectIntoView(mSearchPage, mSearchRects[mSearchIndex]);
		}
	}

	//  performs a search for the next match.
	//     direction - 1 for forward, -1 for backward
	//     startPage - used as a test for circularity.

	private boolean doSearch(int direction, int startPage)
	{
		if (mSearchRects == null)
		{
			//  see if we have matches for this page
			DocPageView dpv = (DocPageView)getOrCreateChild(mSearchPage);
			Page page = dpv.getPage();
			mSearchRects = page.search(mSearchNeedle);

			if (mSearchRects!=null && mSearchRects.length>0)
			{
				//  matches found, return the first one
				if (direction>0)
					mSearchIndex = 0;
				else
					mSearchIndex = mSearchRects.length-1;
				return true;
			}
		}

		//  look forward or backward for the next match
		if (mSearchRects!=null && mSearchRects.length>0)
		{
			if (direction>0)
			{
				if (mSearchIndex+1 < mSearchRects.length && mSearchIndex+1 >= 0)
				{
					mSearchIndex++;
					return true;
				}
			}
			else
			{
				if (mSearchIndex-1 < mSearchRects.length && mSearchIndex-1 >= 0)
				{
					mSearchIndex--;
					return true;
				}
			}
		}

		//  no more matches on this page, go to the next (or previous) page
		if (direction>0)
		{
			mSearchPage++;
			if (mSearchPage >= getPageCount())
				mSearchPage = 0;
		}
		else
		{
			mSearchPage--;
			if (mSearchPage < 0)
				mSearchPage = getPageCount()-1;
		}
		mSearchRects = null;

		//  give up if we're still looking
		if (mSearchPage == startPage)
			return false;

		//  look on the next page
		return doSearch(direction, startPage);
	}

	public void scrollRectIntoView(int pageNum, com.artifex.mupdf.fitz.Rect box)
	{
		//  get our viewport
		Rect viewport = new Rect();
		getGlobalVisibleRect(viewport);
		viewport.offset(0, -viewport.top);

		//  get the location of the box's lower left corner,
		//  relative to the viewport
		DocPageView cv = (DocPageView) getOrCreateChild(pageNum);
		Point point = cv.pageToView((int) box.x0, (int) box.y1);
		Rect childRect = cv.getChildRect();
		point.y += childRect.top;
		point.y -= getScrollY();

		//  if the point is outside the viewport, scroll so it is.
		if (point.y < viewport.top || point.y >= viewport.bottom)
		{
			int diff = (viewport.top + viewport.bottom) / 2 - point.y;
			smoothScrollBy(0, diff);
		}
	}

	public void onHighlight()
	{
		if (hasSelection())
		{
			Toast.makeText(getContext(),"onHighlight", Toast.LENGTH_SHORT).show();
		}
	}

	private boolean mNoteMode = false;
	public boolean getNoteMode() {return mNoteMode;}
	public void onNoteMode()
	{
		mNoteMode = !mNoteMode;
		mDrawMode = false;
		clearSelection();
		onChangeSelection();
	}

	private boolean mDrawMode = false;
	public boolean getDrawMode() {return mDrawMode;}
	public void onDrawMode()
	{
		mDrawMode = !mDrawMode;
		mNoteMode = false;
		clearSelection();
		onChangeSelection();
	}

	public void onDelete()
	{
		int numPages = getPageCount();
		for (int i = 0; i < numPages; i++)
		{
			DocPageView cv = (DocPageView) getOrCreateChild(i);
			if (cv.hasInkAnnotationSelected())
				cv.deleteSelectedInkAnnotation();
		}
	}

	@Override
	public boolean onTouchEvent(MotionEvent event)
	{
		if (mDrawMode)
		{
			float x = event.getX();
			float y = event.getY();
			switch (event.getAction())
			{
				case MotionEvent.ACTION_DOWN:
					touch_start(x, y);
					break;
				case MotionEvent.ACTION_MOVE:
					touch_move(x, y);
					break;
				case MotionEvent.ACTION_UP:
					touch_up();
					break;
			}

			return true;
		}

		return super.onTouchEvent(event);
	}

	private float mX, mY;
	private static final float TOUCH_TOLERANCE = 2;

	private int mCurrentInkLineColor = 0xFFFF0000;
	public void setInkLineColor(int val)
	{
		mCurrentInkLineColor=val;

		//  also change any selected annotation
		if (hasInkAnnotationSelected())
			setSelectedInkLineColor(val);
	}
	public int getInkLineColor() {return mCurrentInkLineColor;}

	private float mCurrentInkLineThickness = 4.5f;
	public float getInkLineThickness() {return mCurrentInkLineThickness;}
	public void setInkLineThickness(float val)
	{
		mCurrentInkLineThickness=val;

		//  also change any selected annotation
		if (hasInkAnnotationSelected())
			setSelectedInkLineThickness(val);
	}

	private void touch_start(float x, float y)
	{
		Point p = eventToScreen(x, y);
		final DocPageView dpv = findPageViewContainingPoint(p.x, p.y, false);
		if (dpv != null)
		{
			dpv.startDraw(p.x, p.y, mCurrentInkLineColor, mCurrentInkLineThickness);
		}

		mX = x;
		mY = y;
	}

	private void touch_move(float x, float y) {

		float dx = Math.abs(x - mX);
		float dy = Math.abs(y - mY);
		if (dx >= TOUCH_TOLERANCE || dy >= TOUCH_TOLERANCE)
		{
			Point p = eventToScreen(x, y);
			final DocPageView dpv = findPageViewContainingPoint(p.x, p.y, false);
			if (dpv != null)
			{
				dpv.continueDraw(p.x, p.y);
			}
			mX = x;
			mY = y;
		}
	}

	private void touch_up()
	{
		// NOOP
	}

}
