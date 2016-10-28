package com.artifex.mupdf.android;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Point;
import android.graphics.PointF;
import android.graphics.Rect;
import android.graphics.RectF;
import android.os.AsyncTask;
import android.support.v4.content.ContextCompat;
import android.util.Log;
import android.util.TypedValue;
import android.view.KeyEvent.Callback;
import android.view.View;
import android.view.ViewGroup;

import com.artifex.mupdf.fitz.Annotation;
import com.artifex.mupdf.fitz.Cookie;
import com.artifex.mupdf.fitz.DisplayList;
import com.artifex.mupdf.fitz.DisplayListDevice;
import com.artifex.mupdf.fitz.Document;
import com.artifex.mupdf.fitz.Matrix;
import com.artifex.mupdf.fitz.Page;
import com.artifex.mupdf.fitz.R;
import com.artifex.mupdf.fitz.StructuredText;
import com.artifex.mupdf.fitz.android.AndroidDrawDevice;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.ListIterator;

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
	private final Paint mSelectionHighlightPainter;
	private final Paint mSearchHighlightPainter;
	private final Paint mBlankPainter;
	private final Paint mDotPainter;
	private final Rect mSrcRect = new Rect();
	private final Rect mDstRect = new Rect();

	private Rect mHighlightingRect = new Rect();

	//  cached display lists
	DisplayList pageContents = null;
	DisplayList annotContents = null;

	//  current size of this view
	private Point mSize;

	private static final boolean DEBUG_PAGE_RENDERING = false;

	private static final float mResolution = 160f;

	public static int bitmapMarginX = 0;
	public static int bitmapMarginY = 0;

	//  use this to control whether the blue dot is drawn in the upper left corner.
	private boolean isMostVisible = false;

	//  currently selected TextChars
	private ArrayList<StructuredText.TextChar> mSelection = null;

	//  current search hilight
	private com.artifex.mupdf.fitz.Rect mSearchHighlight = null;

	public DocPageView(Context context, Document theDoc)
	{
		super(context);
		setLayoutParams(new ViewGroup.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));

		mDoc = theDoc;

		mPainter = new Paint();

		mSelectionHighlightPainter = new Paint();
		mSelectionHighlightPainter.setColor(ContextCompat.getColor(context, R.color.text_highlight_color));
		mSelectionHighlightPainter.setStyle(Paint.Style.FILL);
		mSelectionHighlightPainter.setAlpha(getContext().getResources().getInteger(R.integer.text_highlight_alpha));

		mSearchHighlightPainter = new Paint();
		mSearchHighlightPainter.setStyle(Paint.Style.STROKE);
		mSearchHighlightPainter.setColor(ContextCompat.getColor(context, R.color.black));

		mBlankPainter = new Paint();
		mBlankPainter.setStyle(Paint.Style.FILL);
		mBlankPainter.setColor(Color.WHITE);

		mDotPainter = new Paint();
		mDotPainter.setStyle(Paint.Style.FILL);
		mDotPainter.setColor(ContextCompat.getColor(context, R.color.blue_dot_color));

		setFocusable(true);
		setFocusableInTouchMode(true);
	}

	public void setupPage(final int thePageNum, int w, int h)
	{
		//  if the page number has not yet been set, or has changed,
		//  make a new page object.
		if (thePageNum != mPageNum)
		{
			//  destroy current page and lists
			destroyPageAndLists();

			//  switch to the new page
			mPageNum = thePageNum;
			mPage = mDoc.loadPage(mPageNum);
		}

		//  calculate zoom that makes page fit

		com.artifex.mupdf.fitz.Rect pageBounds = mPage.getBounds();

		float pagew = (pageBounds.x1 - pageBounds.x0) * mResolution / 72f;
		float pageH = (pageBounds.y1 - pageBounds.y0) * mResolution / 72f;

		mZoom = w / pagew;
		mSize = new Point((int) (pagew * mZoom), (int) (pageH * mZoom));
	}

	private void destroyPageAndLists()
	{
		//  de-cache contents and annotations
		if (pageContents != null)
		{
			pageContents.destroy();
			pageContents = null;
		}
		if (annotContents != null)
		{
			annotContents.destroy();
			annotContents = null;
		}

		//  destroy the page before making a new one.
		if (mPage != null)
			mPage.destroy();
		mPage = null;
	}

	public Page getPage()
	{
		return mPage;
	}

	public int getPageNumber()
	{
		return mPageNum;
	}

	public void setNewScale(float scale)
	{
		mScale = scale;
	}

	public int getCalculatedWidth()
	{
		return (int) (mSize.x * mScale);
	}

	public int getCalculatedHeight()
	{
		return (int) (mSize.y * mScale);
	}

	//  a test for real visibility
	private static final Rect visRect = new Rect();

	public boolean isReallyVisible()
	{
		return getLocalVisibleRect(visRect);
	}

	//  for clipping
	private Rect clipRect = new Rect();
	private Path clipPath = new Path();

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
		Rect pageRect = new Rect(locations[0], locations[1], locations[0] + getWidth(), locations[1] + getHeight());

		//  draw a yellow page with a red border containing the page number

		Paint p = new Paint();
		Canvas c = new Canvas(bitmap);
		p.setColor(Color.RED);
		p.setStyle(Paint.Style.FILL);
		c.drawRect(pageRect, p);

		Rect smaller = new Rect(pageRect);
		int inset = (int) (40 * mScale);
		smaller.inset(inset, inset);
		p.setColor(Color.YELLOW);
		p.setStyle(Paint.Style.FILL);
		c.drawRect(smaller, p);

		String s = "" + (mPageNum + 1);
		p.setColor(Color.BLACK);
		p.setTextSize(200.0f * mScale);
		c.drawText(s, pageRect.left + (90 * mScale), pageRect.top + (290 * mScale), p);

		invalidate();
		listener.progress(0);
	}

	public void render(Bitmap bitmap, final RenderListener listener, final boolean showAnnotations)
	{
		if (mFinished)
			return;

		//  get local visible rect
		Rect localVisRect = new Rect();
		if (!getLocalVisibleRect(localVisRect))
		{
			listener.progress(0);
			return;  //  not visible
		}

		//  get global visible rect
		Rect globalVisRect = new Rect();
		if (!getGlobalVisibleRect(globalVisRect))
		{
			listener.progress(0);
			return;  //  not visible
		}

		//  do the render.
		if (DEBUG_PAGE_RENDERING)
			renderNoPage(bitmap, listener, localVisRect, globalVisRect);
		else
		{
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
		int topMargin = Math.min(Math.max(globalVisRect.top - pageRect.top, 0), bitmapMarginY);
		int bottomMargin = Math.min(Math.max(pageRect.bottom - globalVisRect.bottom, 0), bitmapMarginY);
		int leftMargin = Math.min(Math.max(globalVisRect.left - pageRect.left, 0), bitmapMarginX);
		int rightMargin = Math.min(Math.max(pageRect.right - globalVisRect.right, 0), bitmapMarginX);

		mPatchRect.top -= topMargin;
		mDisplayRect.top -= topMargin;
		mPatchRect.bottom += bottomMargin;
		mDisplayRect.bottom += bottomMargin;

		mPatchRect.left -= leftMargin;
		mDisplayRect.left -= leftMargin;
		mPatchRect.right += rightMargin;
		mDisplayRect.right += rightMargin;

		//  ... but clip to the bitmap
		Rect oldPatch = new Rect(mPatchRect);
		mPatchRect.left = Math.max(mPatchRect.left, 0);
		mPatchRect.top = Math.max(mPatchRect.top, 0);
		mPatchRect.right = Math.min(mPatchRect.right, bitmap.getWidth());
		mPatchRect.bottom = Math.min(mPatchRect.bottom, bitmap.getHeight());

		mDisplayRect.left += (mPatchRect.left - oldPatch.left);
		mDisplayRect.top += (mPatchRect.top - oldPatch.top);
		mDisplayRect.right -= (mPatchRect.right - oldPatch.right);
		mDisplayRect.bottom -= (mPatchRect.bottom - oldPatch.bottom);

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
		ctm.scale((float) getFactor());

		//  remember the final values
		mRenderSrcRect.set(mPatchRect);
		mRenderDstRect.set(mDisplayRect);
		mRenderScale = mScale;
		mRenderBitmap = bitmap;

		// Render the page in the background
		RenderTaskParams params = new RenderTaskParams(new RenderListener()
		{
			@Override
			public void progress(int error)
			{
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

	public void stopRender()
	{
		//  TODO ??
	}

	private void cachePage()
	{
		Cookie cookie = new Cookie();

		if (pageContents == null)
		{
			pageContents = new DisplayList();
			DisplayListDevice dispDev = new DisplayListDevice(pageContents);
			try
			{
				mPage.runPageContents(dispDev, new Matrix(1, 0, 0, 1, 0, 0), cookie);
			}
			catch (RuntimeException e)
			{
				pageContents.destroy();
				pageContents = null;
				dispDev.destroy();
				throw (e);
			}
			finally
			{
				dispDev.destroy();
			}
		}

		if (annotContents == null)
		{
			//  run the annotation list
			annotContents = new DisplayList();
			DisplayListDevice annotDev = new DisplayListDevice(annotContents);
			try
			{
				Annotation annotations[] = mPage.getAnnotations();
				if (annotations != null)
				{
					for (Annotation annot : annotations)
					{
						annot.run(annotDev, new Matrix(1, 0, 0, 1, 0, 0), cookie);
					}
				}
			}
			catch (RuntimeException e)
			{
				annotContents.destroy();
				annotContents = null;
				annotDev.destroy();
				throw (e);
			}
			finally
			{
				annotDev.destroy();
			}
		}
	}

	public Point getSelectionStart()
	{
		if (mSelection == null)
			return null;
		if (mSelection.size()==0)
			return null;

		StructuredText.TextChar tchar = mSelection.get(0);

		return new Point((int)tchar.bbox.x0, (int)tchar.bbox.y0);
	}

	public Point getSelectionEnd()
	{
		if (mSelection == null)
			return null;
		if (mSelection.size()==0)
			return null;

		StructuredText.TextChar tchar = mSelection.get(mSelection.size()-1);

		return new Point((int)tchar.bbox.x1, (int)tchar.bbox.y1);
	}

	//  Find the collection ot TextChars belonging to lines
	//  that intersect the rectangle define by two points.
	//  For the first line, include those to the right of upperLeft.x
	//  For the last line, include those to the left of lowerLeft.x
	//  ASSUMPTION: this algorith does not handle right-to-left languages.

	public void setSelection(Point upperLeft, Point lowerLeft)
	{
		mSelection = new ArrayList<>();

		//  get structured text and the block structure
		StructuredText structuredText = getPage().toStructuredText();
		StructuredText.TextBlock textBlocks[] = structuredText.getBlocks();

		for (StructuredText.TextBlock block : textBlocks)
		{
			for (StructuredText.TextLine line : block.lines)
			{
				boolean firstLine = false;
				boolean lastLine = false;
				boolean middleLine = false;
				if (line.bbox.contains(upperLeft.x, upperLeft.y))
					firstLine = true;
				if (line.bbox.contains(lowerLeft.x, lowerLeft.y))
					lastLine = true;
				if (line.bbox.y0 >= upperLeft.y && line.bbox.y1 <= lowerLeft.y)
					middleLine = true;

				for (StructuredText.TextSpan span : line.spans)
				{
					for (StructuredText.TextChar tchar : span.chars)
					{
						if (firstLine && lastLine)
						{
							if (tchar.bbox.x0 >= upperLeft.x && tchar.bbox.x1 <= lowerLeft.x)
								mSelection.add(tchar);
						}
						else if (firstLine)
						{
							if (tchar.bbox.x0 >= upperLeft.x)
								mSelection.add(tchar);
						}
						else if (lastLine)
						{
							if (tchar.bbox.x1 <= lowerLeft.x)
								mSelection.add(tchar);
						}
						else if (middleLine)
						{
							mSelection.add(tchar);
						}
					}
				}
			}
		}

		invalidate();
	}

	public void setSearchHighlight(com.artifex.mupdf.fitz.Rect r)
	{
		mSearchHighlight = r;
		invalidate();
	}

	public void removeSelection()
	{
		mSelection = new ArrayList<>();
		invalidate();
	}

	@Override
	public void onDraw(Canvas canvas)
	{
		//  clip
		canvas.save();
		getLocalVisibleRect(clipRect);
		clipPath.reset();
		clipPath.addRect(clipRect.left, clipRect.top, clipRect.right, clipRect.bottom, Path.Direction.CW);
		canvas.clipPath(clipPath);

		//  always start with a blank white background
		canvas.drawRect(clipRect, mBlankPainter);

		if (mFinished)
		{
			canvas.restore();
			return;
		}

		if (mDrawBitmap == null)
		{
			canvas.restore();
			return;  //  not yet rendered
		}

		//  set rectangles for drawing
		mSrcRect.set(mDrawSrcRect);
		mDstRect.set(mDrawDstRect);

		//  if the scale has changed, adjust the destination
		if (mDrawScale != mScale)
		{
			double scale = (((double) mScale) / ((double) mDrawScale));
			mDstRect.left *= scale;
			mDstRect.top *= scale;
			mDstRect.right *= scale;
			mDstRect.bottom *= scale;
		}

		//  draw
		canvas.drawBitmap(mDrawBitmap, mSrcRect, mDstRect, mPainter);

		//  highlights
		if (mSelection != null && !mSelection.isEmpty())
		{
			for (StructuredText.TextChar tchar : mSelection)
			{
				mHighlightingRect.set((int) tchar.bbox.x0, (int) tchar.bbox.y0, (int) tchar.bbox.x1, (int) tchar.bbox.y1);
				pageToView(mHighlightingRect, mHighlightingRect);
				canvas.drawRect(mHighlightingRect, mSelectionHighlightPainter);
			}
		}

		//  search highlight.  Same as the selection highlight, but with
		//  a thin black outline.
		if (mSearchHighlight != null)
		{
			mHighlightingRect.set((int) mSearchHighlight.x0, (int) mSearchHighlight.y0, (int) mSearchHighlight.x1, (int) mSearchHighlight.y1);
			pageToView(mHighlightingRect, mHighlightingRect);
			canvas.drawRect(mHighlightingRect, mSelectionHighlightPainter);
			canvas.drawRect(mHighlightingRect, mSearchHighlightPainter);
		}

		//  draw ink annotations
		if (mInkAnnots != null)
		{
			Iterator<InkAnnotation> it = mInkAnnots.iterator();
			while (it.hasNext())
			{
				InkAnnotation annot = it.next();
				annot.draw(canvas);
			}
		}

		//  draw blue dot
		if (isMostVisible)
		{
			canvas.drawCircle(30, 30, 15, mDotPainter);
		}

		canvas.restore();
	}

	public Rect selectWord(Point p)
	{
		//  in page units
		Point pPage = screenToPage(p.x, p.y);

		//  get structured text and the block structure
		StructuredText structuredText = getPage().toStructuredText();
		StructuredText.TextBlock textBlocks[] = structuredText.getBlocks();

		StructuredText.TextBlock block = blockContainingPoint(textBlocks, pPage);
		if (block == null)
			return null;

		StructuredText.TextLine line = lineContainingPoint(block.lines, pPage);
		if (line == null)
			return null;

		StructuredText.TextSpan span = spanContainingPoint(line.spans, pPage);
		if (span == null)
			return null;

		//  find the char containing my point
		int n = -1;
		int i;
		for (i = 0; i < span.chars.length; i++)
		{
			if (span.chars[i].bbox.contains(pPage.x, pPage.y))
			{
				n = i;
				break;
			}
		}
		//  not found
		if (n == -1)
			return null;
		//  must be non-blank
		if (span.chars[n].isWhitespace())
			return null;

		//  look forward for a space, or the end
		int nEnd = n;
		while (nEnd + 1 < span.chars.length && !span.chars[nEnd + 1].isWhitespace())
			nEnd++;

		//  look backward for a space, or the beginning
		int nStart = n;
		while (nStart - 1 >= 0 && !span.chars[nStart - 1].isWhitespace())
			nStart--;

		mSelection = new ArrayList<>();
		com.artifex.mupdf.fitz.Rect rWord = new com.artifex.mupdf.fitz.Rect();
		for (i = nStart; i <= nEnd; i++)
		{
			mSelection.add(span.chars[i]);
			rWord.union(span.chars[i].bbox);
		}

		return new Rect((int) rWord.x0, (int) rWord.y0, (int) rWord.x1, (int) rWord.y1);
	}

	private StructuredText.TextBlock blockContainingPoint(StructuredText.TextBlock blocks[], Point p)
	{
		if (blocks != null)
		{
			for (StructuredText.TextBlock block : blocks)
			{
				if (block.bbox.contains(p.x, p.y))
					return block;
			}
		}

		return null;
	}

	private StructuredText.TextLine lineContainingPoint(StructuredText.TextLine lines[], Point p)
	{
		if (lines != null)
		{
			for (StructuredText.TextLine line : lines)
			{
				if (line.bbox.contains(p.x, p.y))
					return line;
			}
		}

		return null;
	}

	private StructuredText.TextSpan spanContainingPoint(StructuredText.TextSpan spans[], Point p)
	{
		if (spans != null)
		{
			for (StructuredText.TextSpan span : spans)
			{
				if (span.bbox.contains(p.x, p.y))
					return span;
			}
		}

		return null;
	}

	private StructuredText.TextChar charContainingPoint(StructuredText.TextChar chars[], Point p)
	{
		if (chars != null)
		{
			for (StructuredText.TextChar tchar : chars)
			{
				if (tchar.bbox.contains(p.x, p.y))
					return tchar;
			}
		}

		return null;
	}

	public Point screenToPage(Point p)
	{
		return screenToPage(p.x, p.y);
	}

	public PointF screenToPage(PointF p)
	{
		Point pp = screenToPage(new Point((int)p.x, (int)p.y));
		return new PointF(pp.x, pp.y);
	}

	private double getFactor()
	{
		return mZoom * mScale * mResolution / 72f;
	}

	private double pageToScreen(double val)
	{
		double factor = getFactor();

		return factor * val;
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
		double factor = getFactor();

		int pageX = (int) (((double) viewX) / factor);
		int pageY = (int) (((double) viewY) / factor);

		return new Point(pageX, pageY);
	}

	public Point pageToView(int pageX, int pageY)
	{
		double factor = getFactor();

		int viewX = (int) (((double) pageX) * factor);
		int viewY = (int) (((double) pageY) * factor);

		return new Point(viewX, viewY);
	}

	public void pageToView(Point pageP, Point viewP)
	{
		double factor = getFactor();

		int x = (int) (((double) pageP.x) * factor);
		int y = (int) (((double) pageP.y) * factor);

		viewP.set(x, y);
	}

	public void pageToView(PointF pageP, PointF viewP)
	{
		double factor = getFactor();

		float x = (pageP.x * (float)factor);
		float y = (pageP.y * (float)factor);

		viewP.set(x, y);
	}

	private PointF pageToView(PointF pageP)
	{
		double factor = getFactor();

		float x = (pageP.x * (float)factor);
		float y = (pageP.y * (float)factor);

		return new PointF(x, y);
	}

	public void pageToView(Rect pageR, Rect viewR)
	{
		double factor = getFactor();

		int left = (int) (((double) pageR.left) * factor);
		int top = (int) (((double) pageR.top) * factor);
		int right = (int) (((double) pageR.right) * factor);
		int bottom = (int) (((double) pageR.bottom) * factor);

		viewR.set(left, top, right, bottom);
	}

	public Point viewToPage(int viewX, int viewY)
	{
		double factor = getFactor();

		int pageX = (int) (((double) viewX) / factor);
		int pageY = (int) (((double) viewY) / factor);

		return new Point(pageX, pageY);
	}

	public void finish()
	{
		mFinished = true;

		//  destroy page and lists
		destroyPageAndLists();
	}

	public boolean getMostVisible() {return isMostVisible;}

	public void setMostVisible(boolean val)
	{
		boolean wasMostVisible = isMostVisible;
		isMostVisible = val;
		if (isMostVisible != wasMostVisible)
		{
			//  "most visible" has changed, so redraw.
			invalidate();
		}
	}

	public boolean onSingleTap(int x, int y)
	{
		//  see if an ink annotation has been tapped on
		if (mInkAnnots != null)
		{
			boolean hit = false;

			//  switch to page coordinates
			Point pt = screenToPage(x, y);

			//  iterate in reverse order
			ListIterator<InkAnnotation> li = mInkAnnots.listIterator(mInkAnnots.size());
			while (li.hasPrevious())
			{
				InkAnnotation annot = li.previous();
				annot.setSelected(false);
				if(annot.hitTest(pt))
				{
					if (!hit)
						annot.setSelected(true);
					hit = true;
				}
			}

			if (hit)
			{
				invalidate();
				return true;
			}
		}

		//  NOTE: when double-tapping, a single-tap will also happen first.
		//  so that must be safe to do.

		requestFocus();
		return false;
	}

	public void onDoubleTap(int x, int y)
	{
		requestFocus();
	}

	//  during layout, a DocView-relative rect is calculated and stashed here.
	private final Rect mChildRect = new Rect();
	public void setChildRect(Rect r)
	{
		mChildRect.set(r);
	}
	public Rect getChildRect()
	{
		return mChildRect;
	}

	private ArrayList<InkAnnotation> mInkAnnots;

	public void startDraw(float x, float y, int color, float thickness)
	{
		//  create annotation list
		if (mInkAnnots == null)
			mInkAnnots = new ArrayList<>();

		//  add a new annotation to the list
		//  convert thickness from pt to pixels
		float px = thickness * (float)getFactor();
		InkAnnotation annot = new InkAnnotation(color, px);
		mInkAnnots.add(annot);

		//  add first point to the new annot, in page coords
		PointF pScreen = new PointF(x, y);
		PointF pPage = screenToPage(pScreen);
		annot.add(pPage);

		invalidate();
	}

	public void continueDraw(float x, float y)
	{
		if (mInkAnnots!=null && mInkAnnots.size()>0)
		{
			//  get the most recent annotation
			InkAnnotation annot = mInkAnnots.get(mInkAnnots.size()-1);

			//  add the point, in page coords
			PointF pScreen = new PointF(x, y);
			PointF pPage = screenToPage(pScreen);
			annot.add(pPage);

			invalidate();
		}
	}

	private class RenderTaskParams
	{
		RenderTaskParams(RenderListener listener, Matrix ctm, Bitmap bitmap,
						 int pageX0, int pageY0, int pageX1, int pageY1,
						 int patchX0, int patchY0, int patchX1, int patchY1, boolean showAnnotations)
		{
			this.listener = listener;
			this.ctm = ctm;
			this.bitmap = bitmap;
			this.pageX0 = pageX0;
			this.pageY0 = pageY0;
			this.pageX1 = pageX1;
			this.pageY1 = pageY1;
			this.patchX0 = patchX0;
			this.patchY0 = patchY0;
			this.patchX1 = patchX1;
			this.patchY1 = patchY1;
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
		protected void onPreExecute()
		{
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
				if (pageContents != null)
				{
					pageContents.run(dev, params.ctm, cookie);
				}
				if (annotContents != null && params.showAnnotations)
				{
					annotContents.run(dev, params.ctm, cookie);
				}
			}
			catch (Exception e)
			{
				Log.e("mupdf", e.getMessage());
			}
			finally
			{
				dev.destroy();
			}

			return null;
		}

		@Override
		protected void onProgressUpdate(Void... values)
		{
			super.onProgressUpdate(values);
		}

		@Override
		protected void onPostExecute(Void result)
		{
			super.onPostExecute(result);
			params.listener.progress(0);
		}
	}

	private InkAnnotation getSelectedInkAnnotation()
	{
		if (mInkAnnots != null)
		{
			//  iterate in reverse order
			ListIterator<InkAnnotation> li = mInkAnnots.listIterator(mInkAnnots.size());
			while (li.hasPrevious())
			{
				InkAnnotation annot = li.previous();
				if (annot.isSelected())
					return annot;
			}
		}

		return null;
	}

	public boolean hasInkAnnotationSelected()
	{
		return (getSelectedInkAnnotation() != null);
	}

	public void setSelectedInkLineColor(int val)
	{
		InkAnnotation annot = getSelectedInkAnnotation();
		if (annot != null)
		{
			annot.setLineColor(val);
			invalidate();
		}
	}

	public void setSelectedInkLineThickness(float val)
	{
		InkAnnotation annot = getSelectedInkAnnotation();
		if (annot != null)
		{
			float px = val * (float)getFactor();
			annot.setLineThickness(px);
			invalidate();
		}
	}

	public void deleteSelectedInkAnnotation()
	{
		InkAnnotation annot = getSelectedInkAnnotation();
		if (annot != null)
		{
			mInkAnnots.remove(annot);
			invalidate();
		}
	}

//-----------------------------------------------------

	public class InkAnnotation
	{
		private float mLineThickness;
		public void setLineThickness(float lineThickness) {mLineThickness = lineThickness;}

		private int mLineColor;
		public void setLineColor(int lineColor) {mLineColor = lineColor;}

		private boolean mSelected = false;
		public void setSelected(boolean sel) {mSelected = sel;}
		public boolean isSelected() {return mSelected;}

		private ArrayList<PointF> mArc;

		//  touch margin is 2mm either side of the arc
		private final float HIT_MARGIN = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_MM, 2,
				getResources().getDisplayMetrics());

		public InkAnnotation(int lineColor, float lineThickness)
		{
			mLineColor = lineColor;
			mLineThickness = lineThickness;
			mArc = new ArrayList<>();
		}

		public void add(PointF p)
		{
			mArc.add(p);
		}

		public boolean hitTest(Point pt)
		{
			PointF p1, p2;
			PointF ptf = new PointF(pt);

			if (mArc.size() >= 2)
			{
				Iterator<PointF> iit = mArc.iterator();
				p1 = iit.next();
				while (iit.hasNext())
				{
					p2 = iit.next();

					//  test
					double d = LineToPointDistance2D(p1, p2, ptf);
					d = pageToScreen(d);

					if (d <= HIT_MARGIN)
					{
						return true;
					}

					p1 = p2;
				}
			}
			else
			{
				p1 = mArc.get(0);

				//  test
				double d = Distance(p1, ptf);
				d = pageToScreen(d);

				if (d <= HIT_MARGIN)
				{
					return true;
				}

			}

			return false;
		}

		public void draw(Canvas canvas)
		{
			Path path = new Path();
			PointF pPage;
			PointF pView = new PointF();

			Paint paint = new Paint();
			paint.setAntiAlias(true);
			paint.setDither(true);
			paint.setStrokeJoin(Paint.Join.ROUND);
			paint.setStrokeCap(Paint.Cap.ROUND);
			paint.setStyle(Paint.Style.FILL);
			paint.setStrokeWidth(mLineThickness * mScale);
			paint.setColor(mLineColor);

			RectF bounds = new RectF();

			if (mArc.size() >= 2)
			{
				Iterator<PointF> iit = mArc.iterator();
				pPage = iit.next();
				pageToView(pPage, pView);
				float mX = pView.x;
				float mY = pView.y;
				path.moveTo(mX, mY);
				while (iit.hasNext())
				{
					pPage = iit.next();
					pageToView(pPage, pView);
					float x = pView.x;
					float y = pView.y;
					path.quadTo(mX, mY, (x + mX) / 2, (y + mY) / 2);
					mX = x;
					mY = y;
				}
				path.lineTo(mX, mY);
				paint.setStyle(Paint.Style.STROKE);
				canvas.drawPath(path, paint);

				path.computeBounds(bounds, true);
			}
			else
			{
				pPage = mArc.get(0);
				pageToView(pPage, pView);
				float r = mLineThickness * mScale / 2;
				bounds.set(pView.x-r, pView.y-r, pView.x+r, pView.y+r);
				canvas.drawCircle(pView.x, pView.y, r, paint);
			}

			if (isSelected())
			{
				//  expand the bounds to account for ine thickness
				float px = mLineThickness * mScale / 2;
				bounds.inset(-px, -px);

				mHighlightingRect.set((int)bounds.left, (int)bounds.top, (int)bounds.right, (int)bounds.bottom);
				canvas.drawRect(mHighlightingRect, mSelectionHighlightPainter);
			}
		}

		private double DotProduct(PointF pointA, PointF pointB, PointF pointC)
		{
			double[] AB = new double[2];
			double[] BC = new double[2];
			AB[0] = pointB.x - pointA.x;
			AB[1] = pointB.y - pointA.y;
			BC[0] = pointC.x - pointB.x;
			BC[1] = pointC.y - pointB.y;
			double dot = AB[0] * BC[0] + AB[1] * BC[1];

			return dot;
		}

		//Compute the cross product AB x AC
		private double CrossProduct(PointF pointA, PointF pointB, PointF pointC)
		{
			double[] AB = new double[2];
			double[] AC = new double[2];
			AB[0] = pointB.x - pointA.x;
			AB[1] = pointB.y - pointA.y;
			AC[0] = pointC.x - pointA.x;
			AC[1] = pointC.y - pointA.y;
			double cross = AB[0] * AC[1] - AB[1] * AC[0];

			return cross;
		}

		//Compute the distance from A to B
		double Distance(PointF pointA, PointF pointB)
		{
			double d1 = pointA.x - pointB.x;
			double d2 = pointA.y - pointB.y;

			return Math.sqrt(d1 * d1 + d2 * d2);
		}

		//Compute the distance from AB to C
		double LineToPointDistance2D(PointF pointA, PointF pointB, PointF pointC)
		{
			double dist = CrossProduct(pointA, pointB, pointC) / Distance(pointA, pointB);
			if (true)
			{
				double dot1 = DotProduct(pointA, pointB, pointC);
				if (dot1 > 0)
					return Distance(pointB, pointC);

				double dot2 = DotProduct(pointB, pointA, pointC);
				if (dot2 > 0)
					return Distance(pointA, pointC);
			}
			return Math.abs(dist);
		}
	}

}
