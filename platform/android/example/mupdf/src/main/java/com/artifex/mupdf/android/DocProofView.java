package com.artifex.mupdf.android;

import android.app.Activity;
import android.content.Context;
import android.util.AttributeSet;
import android.view.View;

public class DocProofView extends DocViewBase
{
	public DocProofView(Context context)
	{
		super(context);
		initialize(context);
	}

	public DocProofView(Context context, AttributeSet attrs)
	{
		super(context, attrs);
		initialize(context);
	}

	public DocProofView(Context context, AttributeSet attrs, int defStyle)
	{
		super(context, attrs, defStyle);
		initialize(context);
	}

	private void initialize(Context context)
	{
	}

	@Override
	protected void onLayout(boolean changed, int left, int top, int right, int bottom)
	{
		//  not if we've been finished
		if (finished())
			return;

		super.onLayout(changed, left, top, right, bottom);

		//  see if we've been given a start page
		handleStartPage();
	}

	@Override
	public void handleStartPage()
	{
		//  if we've been given a start page, go there.
		if (getStartPage()>0)
		{
			setCurrentPage(getStartPage()-1);
			setStartPage(0);  //  but only once
		}
	}

	private int mCurrentPage = 0;
	public int getCurrentPage() {return mCurrentPage;}

	public void setCurrentPage(int pageNum)
	{
		if (pageNum != mCurrentPage)
		{
			//  stop rendering the current page
			DocPageView pv = (DocPageView)getOrCreateChild(0);
			pv.stopRender();

			mCurrentPage = pageNum;

			//  when the page changes, reset what's in view.
			clearChildViews();
			removeAllViewsInLayout();

			//  scroll to 0,0 and do a new layout.
//			smoothScrollBy(getScrollX(),getScrollY());
			requestLayout();
		}
	}

	@Override
	protected int getPageCount()
	{
		int count = super.getPageCount();
		if (count==0)
			return 0;  //  no pages yet

		//  always return one page
		return 1;
	}

	@Override
	protected View getViewFromAdapter(int index)
	{
		//  only one view at a time, so we're not going to use the adapter
		//  we'll just create and reuse a single view
		if (mDocPageView==null) {
			final Activity activity = (Activity) mContext;
			mDocPageView = new DocPageView(activity, getDoc());
		}

		mDocPageView.setupPage(mCurrentPage, getWidth(), 1);
		return mDocPageView;
	}

	private DocPageView mDocPageView = null;

	@Override
	protected void doSingleTap(float fx, float fy)
	{
	}

	@Override
	public boolean shouldAdjustScaleEnd()
	{
		return false;
	}
}
