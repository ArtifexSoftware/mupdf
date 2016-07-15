package com.artifex.mupdf.android;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Point;
import android.graphics.Rect;
import android.os.AsyncTask;
import android.util.Log;
import android.view.KeyEvent.Callback;
import android.view.View;
import android.view.ViewGroup;

import com.artifex.mupdf.fitz.android.AndroidDrawDevice;
import com.artifex.mupdf.fitz.Annotation;
import com.artifex.mupdf.fitz.Cookie;
import com.artifex.mupdf.fitz.DisplayList;
import com.artifex.mupdf.fitz.DisplayListDevice;
import com.artifex.mupdf.fitz.Document;
import com.artifex.mupdf.fitz.Matrix;
import com.artifex.mupdf.fitz.Page;

public class DocPageView extends View implements Callback
{
	private final Document mDoc;
	private int mPageNum = -1;
	private Page mPage;
	private boolean mFinished = false;

	private float mScale = 1.0f;
	private float mZoom = 1.0f;

	//  rendering
	private Bitmap mRenderBitmap = null;
	private final Rect mRenderSrcRect = new Rect();
	private final Rect mRenderDstRect = new Rect();
	private float mRenderScale;
	private Rect mPatchRect = new Rect();

	//  drawing
	private Bitmap mDrawBitmap = null;
	private final Rect mDrawSrcRect = new Rect();
	private final Rect mDrawDstRect = new Rect();
	private float mDrawScale;
	private Rect mDisplayRect = new Rect();

	private final Paint mPainter;
	private final Rect mSrcRect = new Rect();
	private final Rect mDstRect = new Rect();

	//  cached display lists
	DisplayList pageContents = null;
	DisplayList annotContents = null;

	//  current size of this view
	private Point mSize;

	private static final boolean DEBUG_PAGE_RENDERING = false;

	private static final float mResolution = 160f;

	public static int bitmapMarginX = 0;
	public static int bitmapMarginY = 0;

	public DocPageView(Context context, Document theDoc)
	{
		super(context);
		setLayoutParams(new ViewGroup.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));

		mDoc = theDoc;
		mPainter = new Paint();

		setFocusable(true);
		setFocusableInTouchMode(true);
	}

	public void setupPage(final int thePageNum, int w, int h)
	{
		//  if the page number has not yet been set, or has changed,
		//  make a new page object.
		if (thePageNum != mPageNum)
		{
			mPageNum = thePageNum;

			//  de-cache contents and annotations
			if (pageContents != null) {
				pageContents.destroy();
				pageContents = null;
			}
			if (annotContents != null) {
				annotContents.destroy();
				annotContents = null;
			}

			//  destroy the page before making a new one.
			if (mPage!=null)
				mPage.destroy();
			mPage = mDoc.loadPage(mPageNum);
		}

		//  calculate zoom that makes page fit

		com.artifex.mupdf.fitz.Rect pageBounds = mPage.getBounds();

		float pagew = (pageBounds.x1 - pageBounds.x0)*mResolution/72f;
		float pageH = (pageBounds.y1 - pageBounds.y0)*mResolution/72f;

		mZoom = w/pagew;
		mSize = new Point((int)(pagew*mZoom), (int)(pageH*mZoom));
	}

	public void setNewScale(float scale) {
		mScale = scale;
	}

	public int getCalculatedWidth()
	{
		return (int)(mSize.x * mScale);
	}

	public int getCalculatedHeight()
	{
		return (int)(mSize.y * mScale);
	}

	//  a test for real visibility
	private static final Rect visRect = new Rect();
	public boolean isReallyVisible() {
		return getLocalVisibleRect(visRect);
	}

	//  This function renders colored rectangles and text in place of the page.
	//  Use it to test layouts.
	private void renderNoPage(Bitmap bitmap, final RenderListener listener, Rect localVisRect, Rect globalVisRect)
	{
		//  specify where to draw to and from
		mDrawBitmap = bitmap;
		mDrawSrcRect.set(globalVisRect);
		mDrawDstRect.set(localVisRect);

		//  make a rect representing the entire page in screen coordinates
		int[] locations = new int[2];
		getLocationOnScreen(locations);
		Rect pageRect = new Rect(locations[0], locations[1], locations[0]+getWidth(), locations[1]+getHeight());

		//  draw a yellow page with a red border containing the page number

		Paint p = new Paint();
		Canvas c = new Canvas(bitmap);
		p.setColor(Color.RED);
		p.setStyle(Paint.Style.FILL);
		c.drawRect(pageRect,p);

		Rect smaller = new Rect(pageRect);
		int inset = (int)(40*mScale);
		smaller.inset(inset, inset);
		p.setColor(Color.YELLOW);
		p.setStyle(Paint.Style.FILL);
		c.drawRect(smaller,p);

		String s = "" + (mPageNum+1);
		p.setColor(Color.BLACK);
		p.setTextSize(200.0f*mScale);
		c.drawText(s, pageRect.left+(90*mScale), pageRect.top+(290*mScale), p);

		invalidate();
		listener.progress(0);
	}

	public void render(Bitmap bitmap, final RenderListener listener, final boolean showAnnotations)
	{
		if (mFinished)
			return;

		//  get local visible rect
		Rect localVisRect = new Rect();
		if (!getLocalVisibleRect(localVisRect)) {
			listener.progress(0);
			return;  //  not visible
		}

		//  get global visible rect
		Rect globalVisRect = new Rect();
		if (!getGlobalVisibleRect(globalVisRect)) {
			listener.progress(0);
			return;  //  not visible
		}

		//  do the render.
		if (DEBUG_PAGE_RENDERING)
			renderNoPage(bitmap, listener, localVisRect, globalVisRect);
		else {
			cachePage();
			renderPage(bitmap, listener, localVisRect, globalVisRect, showAnnotations);
		}
	}

	//  This function renders the document's page.
	private void renderPage(final Bitmap bitmap, final RenderListener listener, final Rect localVisRect, final Rect globalVisRect, final boolean showAnnotations)
	{
		//  make a rect representing the entire page; this might be outside the bounds of the bitmap
		int[] locations = new int[2];
		getLocationOnScreen(locations);
		Rect pageRect = new Rect(locations[0], locations[1], locations[0] + getCalculatedWidth(), locations[1] + getCalculatedHeight());

		//  Set rects for rendering and display
		mPatchRect.set(globalVisRect);
		mDisplayRect.set(localVisRect);

		//  enlarge rendering and display rects to account for available margins
		int topMargin    = Math.min(Math.max(globalVisRect.top -pageRect.top,0),        bitmapMarginY);
		int bottomMargin = Math.min(Math.max(pageRect.bottom   -globalVisRect.bottom,0),bitmapMarginY);
		int leftMargin   = Math.min(Math.max(globalVisRect.left-pageRect.left,0),       bitmapMarginX);
		int rightMargin  = Math.min(Math.max(pageRect.right    -globalVisRect.right,0), bitmapMarginX);

		mPatchRect.top      -= topMargin;
		mDisplayRect.top    -= topMargin;
		mPatchRect.bottom   += bottomMargin;
		mDisplayRect.bottom += bottomMargin;

		mPatchRect.left     -= leftMargin;
		mDisplayRect.left   -= leftMargin;
		mPatchRect.right    += rightMargin;
		mDisplayRect.right  += rightMargin;

		//  ... but clip to the bitmap
		Rect oldPatch = new Rect(mPatchRect);
		mPatchRect.left   = Math.max(mPatchRect.left, 0);
		mPatchRect.top    = Math.max(mPatchRect.top, 0);
		mPatchRect.right  = Math.min(mPatchRect.right, bitmap.getWidth());
		mPatchRect.bottom = Math.min(mPatchRect.bottom, bitmap.getHeight());

		mDisplayRect.left   += (mPatchRect.left-oldPatch.left);
		mDisplayRect.top    += (mPatchRect.top-oldPatch.top);
		mDisplayRect.right  -= (mPatchRect.right-oldPatch.right);
		mDisplayRect.bottom -= (mPatchRect.bottom-oldPatch.bottom);

		//  set up the page and patch coordinates for the device
		int pageX0 = pageRect.left;
		int pageY0 = pageRect.top;
		int pageX1 = pageRect.right;
		int pageY1 = pageRect.bottom;

		int patchX0 = mPatchRect.left;
		int patchY0 = mPatchRect.top;
		int patchX1 = mPatchRect.right;
		int patchY1 = mPatchRect.bottom;

		//  set up a matrix for scaling
		Matrix ctm = Matrix.Identity();
		ctm.scale(mScale * mZoom * mResolution / 72f);

		//  remember the final values
		mRenderSrcRect.set(mPatchRect);
		mRenderDstRect.set(mDisplayRect);
		mRenderScale = mScale;
		mRenderBitmap = bitmap;

		// Render the page in the background
		RenderTaskParams params = new RenderTaskParams(new RenderListener() {
			@Override
			public void progress(int error) {
				//  specify where to draw to and from
				mDrawBitmap = mRenderBitmap;
				mDrawSrcRect.set(mRenderSrcRect);
				mDrawDstRect.set(mRenderDstRect);
				mDrawScale = mRenderScale;

				listener.progress(0);

			}
		}, ctm, mRenderBitmap, pageX0, pageY0, pageX1, pageY1, patchX0, patchY0, patchX1, patchY1, showAnnotations);

		new RenderTask().execute(params, null, null);
	}

	private void cachePage()
	{
		Cookie cookie = new Cookie();

		if (pageContents==null)
		{
			pageContents = new DisplayList();
			DisplayListDevice dispDev = new DisplayListDevice(pageContents);
			try {
				mPage.runPageContents(dispDev, new Matrix(1, 0, 0, 1, 0, 0), cookie);
			}
			catch (RuntimeException e) {
				pageContents.destroy();
				dispDev.destroy();
				throw(e);
			}
			finally {
				dispDev.destroy();
			}
		}

		if (annotContents==null)
		{
			//  run the annotation list
			annotContents = new DisplayList();
			DisplayListDevice annotDev = new DisplayListDevice(annotContents);
			try {
				Annotation annotations[] = mPage.getAnnotations();
				if (annotations != null)
				{
					for (Annotation annot : annotations)
					{
						annot.run(annotDev, new Matrix(1, 0, 0, 1, 0, 0), cookie);
					}
				}
			}
			catch (RuntimeException e) {
				annotContents.destroy();
				annotDev.destroy();
				throw(e);
			}
			finally {
				annotDev.destroy();
			}
		}
	}

	@Override
	public void onDraw(Canvas canvas)
	{
		if (mFinished)
			return;

		if (mDrawBitmap==null)
			return;  //  not yet rendered

		//  set rectangles for drawing
		mSrcRect.set(mDrawSrcRect);
		mDstRect.set(mDrawDstRect);

		//  if the scale has changed, adjust the destination
		if (mDrawScale != mScale)
		{
			double scale = (((double)mScale)/((double) mDrawScale));
			mDstRect.left   *= scale;
			mDstRect.top    *= scale;
			mDstRect.right  *= scale;
			mDstRect.bottom *= scale;
		}

		//  draw
		canvas.drawBitmap(mDrawBitmap, mSrcRect, mDstRect, mPainter);
	}

	public boolean onSingleTap(int x, int y) {
		//  NOTE: when double-tapping, a single-tap will also happen first.
		//  so that must be safe to do.
		return false;
	}

	public void onDoubleTap(int x, int y) {
	}

	private Point screenToPage(Point p)
	{
		return screenToPage(p.x, p.y);
	}

	private Point screenToPage(int screenX, int screenY)
	{
		//  convert to view-relative
		int viewX = screenX;
		int viewY = screenY;
		int loc[] = new int[2];
		getLocationOnScreen(loc);
		viewX -= loc[0];
		viewY -= loc[1];

		//  convert to page-relative
		double factor = mZoom * mScale;
		int pageX = (int)(((double)viewX)/factor);
		int pageY = (int)(((double)viewY)/factor);

		return new Point(pageX,pageY);
	}

	public Point pageToView(int pageX, int pageY)
	{
		double factor = mZoom * mScale;

		int viewX = (int)(((double)pageX)*factor);
		int viewY = (int)(((double)pageY)*factor);

		return new Point(viewX, viewY);
	}

	public Point viewToPage(int viewX, int viewY)
	{
		double factor = mZoom * mScale;

		int pageX = (int)(((double)viewX)/factor);
		int pageY = (int)(((double)viewY)/factor);

		return new Point(pageX, pageY);
	}

	public void finish()
	{
		mFinished = true;

		//  destroy the page
		if (mPage!=null) {
			mPage.destroy();
			mPage = null;
		}
	}

	//  during layout, a DocView-relative rect is calculated and stashed here.
	private final Rect mChildRect = new Rect();
	public void setChildRect(Rect r) {mChildRect.set(r);}
	public Rect getChildRect() {return mChildRect;}

	private class RenderTaskParams {
		RenderTaskParams(RenderListener listener, Matrix ctm, Bitmap bitmap,
						 int pageX0, int pageY0, int pageX1, int pageY1,
						 int patchX0, int patchY0, int patchX1, int patchY1, boolean showAnnotations)
		{
			this.listener = listener;
			this.ctm      = ctm;
			this.bitmap   = bitmap;
			this.pageX0   = pageX0;
			this.pageY0   = pageY0;
			this.pageX1   = pageX1;
			this.pageY1   = pageY1;
			this.patchX0  = patchX0;
			this.patchY0  = patchY0;
			this.patchX1  = patchX1;
			this.patchY1  = patchY1;
			this.showAnnotations = showAnnotations;
		}

		public RenderListener listener;
		public Matrix ctm;
		public Bitmap bitmap;
		public int pageX0;
		public int pageY0;
		public int pageX1;
		public int pageY1;
		public int patchX0;
		public int patchY0;
		public int patchX1;
		public int patchY1;
		public boolean showAnnotations;
	}

	// The definition of our task class
	private class RenderTask extends AsyncTask<RenderTaskParams, Void, Void>
	{
		private RenderTaskParams params = null;

		@Override
		protected void onPreExecute() {
			super.onPreExecute();
		}

		@Override
		protected Void doInBackground(RenderTaskParams... paramList)
		{
			params = paramList[0];

			AndroidDrawDevice dev = new AndroidDrawDevice(params.bitmap, params.pageX0, params.pageY0, params.pageX1, params.pageY1, params.patchX0, params.patchY0, params.patchX1, params.patchY1);
			try
			{
				Cookie cookie = new Cookie();
				if (pageContents != null) {
					pageContents.run(dev, params.ctm, cookie);
				}
				if (annotContents != null && params.showAnnotations) {
					annotContents.run(dev, params.ctm, cookie);
				}
			}
			catch (Exception e)
			{
				Log.e("mupdf", e.getMessage());
			}
			finally {
				dev.destroy();
			}

			return null;
		}

		@Override
		protected void onProgressUpdate(Void... values) {
			super.onProgressUpdate(values);
		}

		@Override
		protected void onPostExecute(Void result) {
			super.onPostExecute(result);
			params.listener.progress(0);
		}
	}

}
