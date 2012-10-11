package com.artifex.mupdf;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Point;
import android.graphics.PointF;
import android.graphics.RectF;

public class MuPDFPageView extends PageView {
	private final MuPDFCore mCore;
	private SafeAsyncTask<Void,Void,Boolean> mPassClick;
	private RectF mWidgetAreas[];
	private SafeAsyncTask<Void,Void,RectF[]> mLoadWidgetAreas;

	public MuPDFPageView(Context c, MuPDFCore core, Point parentSize) {
		super(c, parentSize);
		mCore = core;
	}

	public int hitLinkPage(float x, float y) {
		// Since link highlighting was implemented, the super class
		// PageView has had sufficient information to be able to
		// perform this method directly. Making that change would
		// make MuPDFCore.hitLinkPage superfluous.
		float scale = mSourceScale*(float)getWidth()/(float)mSize.x;
		float docRelX = (x - getLeft())/scale;
		float docRelY = (y - getTop())/scale;

		return mCore.hitLinkPage(mPageNumber, docRelX, docRelY);
	}

	public boolean passClickEvent(float x, float y) {
		float scale = mSourceScale*(float)getWidth()/(float)mSize.x;
		final float docRelX = (x - getLeft())/scale;
		final float docRelY = (y - getTop())/scale;
		boolean hitWidget = false;

		if (mWidgetAreas != null) {
			for (int i = 0; i < mWidgetAreas.length && !hitWidget; i++)
				if (mWidgetAreas[i].contains(docRelX, docRelY))
					hitWidget = true;
		}

		if (hitWidget) {
			mPassClick = new SafeAsyncTask<Void,Void,Boolean>() {
				@Override
				protected Boolean doInBackground(Void... arg0) {
					return mCore.passClickEvent(mPageNumber, docRelX, docRelY);
				}

				@Override
				protected void onPostExecute(Boolean result) {
					if (result) {
						update();
					}
				}
			};

			mPassClick.execute();
		}

		return hitWidget;
	}

	@Override
	protected Bitmap drawPage(int sizeX, int sizeY,
			int patchX, int patchY, int patchWidth, int patchHeight) {
		return mCore.drawPage(mPageNumber, sizeX, sizeY, patchX, patchY, patchWidth, patchHeight);
	}

	@Override
	protected LinkInfo[] getLinkInfo() {
		return mCore.getPageLinks(mPageNumber);
	}

	@Override
	public void setPage(final int page, PointF size) {
		mLoadWidgetAreas = new SafeAsyncTask<Void,Void,RectF[]> () {
			@Override
			protected RectF[] doInBackground(Void... arg0) {
				return mCore.getWidgetAreas(page);
			}

			@Override
			protected void onPostExecute(RectF[] result) {
				mWidgetAreas = result;
			}
		};

		mLoadWidgetAreas.execute();

		super.setPage(page, size);
	}
}
