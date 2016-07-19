package com.artifex.mupdf.android;

import android.content.Context;
import android.graphics.Point;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.view.ScaleGestureDetector;

public class DocListPagesView extends DocViewBase
{

	private DocViewBase mMainView;

	public DocListPagesView(Context context)
	{
		super(context);
	}

	public DocListPagesView(Context context, AttributeSet attrs)
	{
		super(context, attrs);
	}

	public DocListPagesView(Context context, AttributeSet attrs, int defStyle)
	{
		super(context, attrs, defStyle);
	}

	public void setMainView(DocViewBase v)
	{
		mMainView = v;
	}

	@Override
	protected void doSingleTap(float fx, float fy)
	{
		Point p = eventToScreen(fx, fy);
		DocPageView v = findPageViewContainingPoint(p.x, p.y, false);
		if (v != null)
		{
			int pageNumber = v.getPageNumber();
			mMainView.scrollToPage(pageNumber);
		}
	}

	@Override
	protected void doDoubleTap(float fx, float fy)
	{
	}

	@Override
	public boolean onScale(ScaleGestureDetector detector)
	{
		return true;
	}

	@Override
	protected Point constrainScrollBy(int dx, int dy)
	{
		//  don't scroll sideways
		dx = 0;

		Rect viewport = new Rect();
		getGlobalVisibleRect(viewport);
		if (mPageCollectionHeight <= viewport.height())
		{
			//  all the pages are already visible vertically, do nothing
			dy = 0;
		}
		else
		{
			int sy = getScrollY();

			//  not too far down
			if (sy + dy < 0)
				dy = -sy;

			//  not too far up
			if (mPageCollectionHeight < sy + viewport.height() + dy)
				dy = 0;
		}

		return new Point(dx, dy);
	}

	public void setMostVisiblePage(int p)
	{
		//  set one of the pages in the  document to be the "most visible".
		int numPages = getPageCount();
		for (int i = 0; i < numPages; i++)
		{
			DocPageView cv = (DocPageView) getOrCreateChild(i);
			cv.setMostVisible(i == p);
		}
	}

	@Override
	public void onShowPages()
	{
	}

	@Override
	public void onHidePages()
	{
	}

}
