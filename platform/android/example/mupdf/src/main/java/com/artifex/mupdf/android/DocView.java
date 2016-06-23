package com.artifex.mupdf.android;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Point;
import android.graphics.Rect;
import android.graphics.RectF;
import android.os.Handler;
import android.util.AttributeSet;
import android.util.DisplayMetrics;
import android.util.SparseArray;
import android.view.GestureDetector;
import android.view.MotionEvent;
import android.view.ScaleGestureDetector;
import android.view.View;
import android.view.ViewTreeObserver;
import android.view.WindowManager;
import android.widget.Adapter;
import android.widget.AdapterView;
import android.widget.Scroller;

import com.artifex.mupdf.fitz.Document;

public class DocView
        extends AdapterView<Adapter>
        implements GestureDetector.OnGestureListener, ScaleGestureDetector.OnScaleGestureListener, Runnable
{
    private static final int  GAP = 20;

    private static final float MIN_SCALE = .15f;
    private static final float MAX_SCALE = 5.0f;

    private PageAdapter mAdapter;
    private boolean mFinished = false;

    private final SparseArray<View> mChildViews = new SparseArray<View>(3);

    private boolean           mScaling;    // Whether the user is currently pinch zooming
    private float             mScale     = 1.0f;
    private int               mXScroll;    // Scroll amounts recorded from events.
    private int               mYScroll;    // and then accounted for in onLayout

    private GestureDetector mGestureDetector;
    private ScaleGestureDetector mScaleGestureDetector;

    //  bitmaps for rendering
    //  these are created by the activity and set using setBitmaps()
    private final static double OVERSIZE_FACTOR = 1.1;
    private final Bitmap[] bitmaps = {null,null};

    private int bitmapIndex = 0;
    private boolean renderRequested = false;
    private int renderCount = 0;

    //  used during layout
    private final Rect mChildRect = new Rect();
    private final Rect mViewport = new Rect();
    private final Point mViewportOrigin = new Point();
    private final Rect mBlockRect = new Rect();
    private final Rect mLastBlockRect = new Rect();
    private int mLastLayoutColumns = 1;
    protected int mPageCollectionHeight;
    private int mPageCollectionWidth;

    //  for flinging
    private static final int  MOVING_DIAGONALLY = 0;
    private static final int  MOVING_LEFT       = 1;
    private static final int  MOVING_RIGHT      = 2;
    private static final int  MOVING_UP         = 3;
    private static final int  MOVING_DOWN       = 4;

    private static final float MIN_FLING_VELOCITY  = 1500.0f;
    private static final long  FLING_THROTTLE_TIME = 20;

    private Scroller          mScroller;
    private Stepper           mStepper;
    private int               mScrollerLastX;
    private int               mScrollerLastY;
    private long              mFlingStartTime;

    //  for single- and double-tapping
    private long mLastTapTime = 0;
    private float lastTapX;
    private float lastTapY;
    private int mTapStatus = 0;

    private static final int DOUBLE_TAP_TIME = 300;
    private static final int SHOW_KEYBOARD_TIME = 500;

    //  the document.
    private Document mDoc;

    private boolean mStarted = false;

    public DocView(Context context) {
        super(context);
        initialize(context);
    }

    public DocView(Context context, AttributeSet attrs) {
        super(context, attrs);
        initialize(context);
    }

    public DocView(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle);
        initialize(context);
    }

    protected Context mContext = null;

    protected void initialize(Context context)
    {
        mContext = context;
        mGestureDetector = new GestureDetector(context, this);
        mScaleGestureDetector = new ScaleGestureDetector(context, this);
        mScroller = new Scroller(context);
        mStepper = new Stepper(this, this);

        //  create bitmaps
        makeBitmaps();
    }

    private void makeBitmaps()
    {
        //  get current screen size
        WindowManager wm = (WindowManager) mContext.getSystemService(Context.WINDOW_SERVICE);
        DisplayMetrics metrics = new DisplayMetrics();
        wm.getDefaultDisplay().getMetrics(metrics);
        int screenW = metrics.widthPixels;
        int screenH = metrics.heightPixels;

        //  make two bitmaps.
        //  make them large enough for both screen orientations, so we don't have to
        //  change them when the orientation changes.

        int w = (int)(screenW*OVERSIZE_FACTOR);
        int h = (int)(screenH*OVERSIZE_FACTOR);
        int size = Math.max(w,h);
        for (int i=0;i<bitmaps.length;i++)
            bitmaps[i] = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888);
    }

    public void start(final String path)
    {
        //  wait for the layout to finish
        ViewTreeObserver observer = getViewTreeObserver();
        observer.addOnGlobalLayoutListener(new ViewTreeObserver.OnGlobalLayoutListener()
        {
            @Override
            public void onGlobalLayout()
            {
                getViewTreeObserver().removeOnGlobalLayoutListener(this);

                mAdapter = new PageAdapter(mContext);
                mAdapter.setWidth(getWidth());
                mDoc = new Document(path);
                mAdapter.setDocument(mDoc);
                mScale = 1.0f;
                mStarted = true;
                triggerRender();
            }
        });
    }

    private void onScaleChild(View v, Float scale)
    {
        ((DocPageView)v).setNewScale(scale);
    }

    public void onOrientationChange()
    {
        triggerRender();
    }

    private void onSizeChange(float factor)
    {
        mScale *= factor;
        scaleChildren();
        requestLayout();
    }

    public boolean onDown(MotionEvent arg0) {
        mScroller.forceFinished(true);
        return true;
    }

    public boolean onFling(MotionEvent e1, MotionEvent e2, float velocityX, float velocityY) {

        //  not while we're scaling
        if (mScaling)
            return true;

        //  not while a previous fling is underway
        if (!mScroller.isFinished())
            return true;

        //  must be really flinging
        float vel = Math.max(Math.abs(velocityX),Math.abs(velocityY));
        if (vel<MIN_FLING_VELOCITY)
            return false;

        //  what direction?
        int direction = directionOfTravel(velocityX,velocityY);

        mFlingStartTime = System.currentTimeMillis();

        switch (direction)
        {
            case MOVING_DOWN:
                smoothScrollBy(0, getHeight()/2);
                break;

            case MOVING_UP:
                smoothScrollBy(0, -getHeight()/2);
                break;

            default:
                break;
        }

        return true;
    }

    private static int directionOfTravel(float vx, float vy) {
        if (Math.abs(vx) > 2 * Math.abs(vy))
            return (vx > 0) ? MOVING_RIGHT : MOVING_LEFT;
        else if (Math.abs(vy) > 2 * Math.abs(vx))
            return (vy > 0) ? MOVING_DOWN : MOVING_UP;
        else
            return MOVING_DIAGONALLY;
    }

    public void onLongPress(MotionEvent e) {
    }

    public boolean onScroll(MotionEvent e1, MotionEvent e2, float distanceX, float distanceY) {

        //  not if we're scaling
        if (mScaling)
            return true;

        //  not if a previous fling is underway
        if (!mScroller.isFinished())
            return true;

        //  accumulate scrolling amount.
        mXScroll -= distanceX;
        mYScroll -= distanceY;

        requestLayout();

        return true;
    }

    public void onShowPress(MotionEvent e) {
    }

    protected DocPageView findPageViewContainingPoint(int x, int y, boolean includeMargin)
    {
        for (int i = 0; i < getChildCount(); i++)
        {
            //  get the rect for the page
            View child = getChildAt(i);
            Rect childRect = new Rect();
            child.getGlobalVisibleRect(childRect);

            //  add in the margin
            if (includeMargin)
            {
                childRect.left   -= GAP/2;
                childRect.right  += GAP/2;
                childRect.top    -= GAP/2;
                childRect.bottom += GAP/2;
            }

            //  see if the rect contains the point
            if (childRect.contains(x,y))
                return (DocPageView)child;
        }

        return null;
    }

    protected Point eventToScreen(float fx, float fy)
    {
        int x = Math.round(fx);
        int y = Math.round(fy);
        Rect docRect = new Rect();
        getGlobalVisibleRect(docRect);
        x += docRect.left;
        y += docRect.top;

        return new Point(x,y);
    }

    protected void doSingleTap(float fx, float fy)
    {
        //  find the page view that was tapped.
        Point p = eventToScreen(fx,fy);
        final DocPageView dpv = findPageViewContainingPoint(p.x, p.y, false);
        if (dpv==null)
            return;

        //  see if the age wants to handle the single tap
        boolean handled = dpv.onSingleTap(p.x,p.y);

        //  if not, ...
        if (!handled)
        {
            //  schedule a task in the near future to check if we're still a single-tap.
            final Handler handler = new Handler();
            final Point tappedPoint = p;
            handler.postDelayed(new Runnable()
            {
                @Override
                public void run()
                {
                    if (mTapStatus==1)
                    {
                        //  still single
                    }
                    else
                    {
                        //  double
                    }
                    mTapStatus = 0;
                }
            }, SHOW_KEYBOARD_TIME);
        }
    }

    protected void doDoubleTap(float fx, float fy)
    {
        Point p = eventToScreen(fx,fy);
        DocPageView v = findPageViewContainingPoint(p.x, p.y, false);
        if (v != null) {
            v.onDoubleTap(p.x,p.y);
        }
    }

    public boolean onSingleTapUp(final MotionEvent e)
    {
        long now = System.currentTimeMillis();
        if (mLastTapTime!=0 && ((now-mLastTapTime)<DOUBLE_TAP_TIME))
        {
            mTapStatus = 2;
            doDoubleTap(lastTapX,lastTapY);
            mLastTapTime = 0;
        }
        else
        {
            mLastTapTime = now;
            lastTapX = e.getX();
            lastTapY = e.getY();
            doSingleTap(lastTapX, lastTapY);
            mTapStatus = 1;
        }

        return false;
    }

    private void scaleChildren()
    {
        //  scale children
        for (int i=0; i<getPageCount(); i++)
        {
            DocPageView cv = (DocPageView)getOrCreateChild(i);
            cv.setNewScale(mScale);
        }
    }

    public boolean onScale(ScaleGestureDetector detector)
    {
        //  new scale factor
        float previousScale = mScale;
        mScale = Math.min(Math.max(mScale * detector.getScaleFactor(), MIN_SCALE), MAX_SCALE);

        //  did we really scale?
        if (mScale == previousScale)
            return true;

        //  scale children
        scaleChildren();

        //  maintain focus while scaling
        float currentFocusX = detector.getFocusX();
        float currentFocusY = detector.getFocusY();
        int viewFocusX = (int)currentFocusX + getScrollX();
        int viewFocusY = (int)currentFocusY + getScrollY();
        mXScroll += viewFocusX - viewFocusX * detector.getScaleFactor();
        mYScroll += viewFocusY - viewFocusY * detector.getScaleFactor();

        requestLayout();

        return true;
    }

    public boolean onScaleBegin(ScaleGestureDetector detector) {

        mScaling = true;

        //  Ignore any scroll amounts yet to be accounted for: the
        //  screen is not showing the effect of them, so they can
        //  only confuse the user
        mXScroll = mYScroll = 0;

        return true;
    }

    public void onScaleEnd(ScaleGestureDetector detector)
    {
        //  When a pinch-scale is done, we want to get n-across
        //  to fit properly.

        //  get current viewport
        Rect viewport = new Rect();
        getGlobalVisibleRect(viewport);

        //  if we're at one column and wider than the viewport,
        //  leave it alone.
        if (mLastLayoutColumns==0 && mPageCollectionWidth>=viewport.width())
        {
            mScaling = false;
            return;
        }

        //  ratio of the viewport width to layout width
        float ratio = ((float)(viewport.width()))/((float)(mPageCollectionWidth));

        //  set a new scale factor
        mScale *= ratio;
        scaleChildren();

        //  scroll so the left edged is flush to the viewport.
        mXScroll +=getScrollX();

        requestLayout();

        mScaling = false;
    }

    @Override
    public boolean onTouchEvent(MotionEvent event) {

        if ((event.getAction() & MotionEvent.ACTION_MASK) == MotionEvent.ACTION_DOWN) {
            //  do something when user interaction begins
        }

        if ((event.getAction() & MotionEvent.ACTION_MASK) == MotionEvent.ACTION_UP) {
            //  do something when user interaction ends
            triggerRender();
        }

        mScaleGestureDetector.onTouchEvent(event);
        mGestureDetector.onTouchEvent(event);

        return true;
    }

    protected int getPageCount()
    {
        return getAdapter().getCount();
    }

    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {

        super.onLayout(changed, left, top, right, bottom);

        if (!mStarted)
            return;

        //  not if there are no pages
        if (getPageCount()==0)
            return;

        int numDocPages = getPageCount();

        //  not if we've been finished
        if (finished())
            return;

        //  perform any pending scrolling
        scrollBy(-mXScroll, -mYScroll);
        mXScroll = mYScroll = 0;

        //  get current viewport
        mViewportOrigin.set(getScrollX(), getScrollY());
        getGlobalVisibleRect(mViewport);
        mViewport.offsetTo(mViewportOrigin.x, mViewportOrigin.y);

        //  find the widest child
        int maxw = 0;
        for (int i=0; i<getPageCount(); i++)
        {
            DocPageView cv = (DocPageView)getOrCreateChild(i);

            int childWidth = cv.getCalculatedWidth();
            if (childWidth>maxw)
                maxw = childWidth;
        }

        //  how many columns?
        double dcol = (double)(mViewport.width()+GAP)/(double)(maxw+GAP);
        int columns = (int) dcol;

        //  lay them out
        int mostVisibleChildHeight = -1;
        int childTop = 0;
        mPageCollectionHeight = 0;
        mPageCollectionWidth = 0;
        int column = 0;
        mBlockRect.setEmpty();

        for (int i=0; i<getPageCount(); i++)
        {
            DocPageView cv = (DocPageView)getOrCreateChild(i);
            int childWidth = cv.getCalculatedWidth();
            int childHeight = cv.getCalculatedHeight();
            int childLeft = column * (maxw + GAP);
            int childRight = childLeft + childWidth;
            int childBottom = childTop + childHeight;
            mChildRect.set(childLeft, childTop, childRight, childBottom);

            //  stash the rect in the page view for later use.
            cv.setChildRect(mChildRect);

            //  at each layout, we remember the entire width and height of the laid-out
            //  pages.  This is used in applying constraints to scrolling amounts.
            if (childBottom> mPageCollectionHeight)
                mPageCollectionHeight = childBottom;
            if (childRight>mPageCollectionWidth)
                mPageCollectionWidth = childRight;

            if (mBlockRect.isEmpty())
                mBlockRect.set(mChildRect);
            else
                mBlockRect.union(mChildRect);

            if (mChildRect.intersect(mViewport) && i<numDocPages)
            {
                //  visible, so include in layout
                if (cv.getParent()==null)
                    addChildToLayout(cv);
                cv.layout(childLeft, childTop, childRight, childBottom);
                cv.invalidate();
            }
            else
            {
                //  not visible, so remove from layout
                removeViewInLayout(cv);
            }

            column++;
            if (column >= columns) {
                column = 0;
                childTop += childHeight;
                childTop += GAP;
            }
        }

        //  if the number of columns has changed, do some scrolling to adjust
        if (mScaling && columns>=1 && mLastLayoutColumns>=1 && mLastLayoutColumns!=columns)
        {
            //  x - center in the viewport
            int dx = mBlockRect.centerX() - mViewport.centerX();
            scrollBy(dx,0);

            //  y - attempt to keep what's in the center of the viewport in view.
            int oldy = mViewport.centerY() - mLastBlockRect.top;
            int newy = (int)((float)oldy*mBlockRect.height()/mLastBlockRect.height());
            scrollBy(0,newy-oldy);
        }
        mLastLayoutColumns = columns;
        mLastBlockRect.set(mBlockRect);

        //  see if we're handling a start page
        handleStartPage();

        triggerRender();
    }

    //  start page, get and set.
    private int mStartPage = 0;
    public void setStartPage(int page) {
        mStartPage = page;
    }
    protected int getStartPage() {return mStartPage;}

    //  handle start page
    public void handleStartPage()
    {
        //  if we've been given a start page, go there.
        final int start = getStartPage();
        if (start>0)
        {
            setStartPage(0);  //  but just once

            //  post all of this so that we get an additional layout request
            final Handler handler = new Handler();
            handler.post(new Runnable() {
                @Override
                public void run() {
                    DocPageView cv = (DocPageView)getOrCreateChild(start-1);
                    Rect r = cv.getChildRect();
                    scrollBy(0,r.top);
                    requestLayout();
                }
            });
        }
    }

    //  override the view's scrollBy() function so we can
    //  take the opportunity to apply some constraints

    @Override
    public void scrollBy(int dx, int dy)
    {
        Point p = constrainScrollBy(dx, dy);
        super.scrollBy(p.x, p.y);
    }

    // apply contraints to every scroll request.

    protected Point constrainScrollBy(int dx, int dy)
    {
        int vph;
        int vpw;
        {
            Rect viewport = new Rect();
            getGlobalVisibleRect(viewport);
            vph = viewport.height();
            vpw = viewport.width();
        }
        int sx = getScrollX();
        int sy = getScrollY();

        if (mPageCollectionWidth <= vpw)
        {
            //  not too far to the right
            if (mPageCollectionWidth-sx-dx > vpw)
                dx = 0;

            //  not too far to the left
            if (sx+dx>0)
                dx = -sx;
        }
        else
        {
            //  not too far to the right
            if (mPageCollectionWidth < sx+vpw+dx)
                dx = 0;

            //  not too far to the left
            if (sx+dx < 0)
                dx = -sx;
        }

        if (mPageCollectionHeight <= vph)
        {
            // not too far down
            if (mPageCollectionHeight-sy-dy > vph)
                dy = 0;

            //  not too far up
            if (sy+dy>0)
                dy = -sy;
        }
        else
        {
            //  not too far down
            if (sy+dy < 0)
                dy = -sy;

            //  not too far up.
            if (mPageCollectionHeight+2*vph/3 < sy+vph+dy)
                dy = 0;
        }

        return new Point(dx, dy);
    }

    @Override
    public Adapter getAdapter() {
        return mAdapter;
    }

    @Override
    public View getSelectedView() {
        return null;
    }

    @Override
    public void setAdapter(Adapter adapter) {
        mAdapter = (PageAdapter)adapter;
        requestLayout();
    }

    @Override
    public void setSelection(int arg0) {
        throw new UnsupportedOperationException("setSelection is not supported");
    }

    private View getCached() {
        return null;
    }

    protected View getOrCreateChild(int i) {
        View v = mChildViews.get(i);
        if (v == null) {
            v = getViewFromAdapter(i);
            mChildViews.append(i, v); // Record the view against it's adapter index
            onScaleChild(v, mScale);
        }

        return v;
    }

    protected View getViewFromAdapter(int index)
    {
        return getAdapter().getView(index, getCached(), this);
    }

    private void addChildToLayout(View v) {
        LayoutParams params = v.getLayoutParams();
        if (params == null) {
            params = new LayoutParams(LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT);
        }
        addViewInLayout(v, 0, params, true);
    }

    private void triggerRender()
    {
        // Note that a render is needed
        renderRequested = true;

        // If the previous render has completed, start a new one. Otherwise
        // a new one will start as soon as the previous one completes.
        if (renderCount == 0)
            renderPages();
    }

    private void renderPages()
    {
        renderRequested = false;

        if (mFinished)
            return;

        if (bitmaps == null)
            return;

        // Rotate to the next bitmap
        bitmapIndex++;
        if (bitmapIndex>=bitmaps.length)
            bitmapIndex = 0;

        //  iterate through the children
        for (int i = 0; i < getPageCount(); i++) {

            if (mFinished)
                return;

            final DocPageView cv = (DocPageView) getOrCreateChild(i);
            if (cv.getParent()!=null && cv.isReallyVisible()) {
                // Count up as we kick off rendering of each visible page
                renderCount++;
                cv.render(bitmaps[bitmapIndex], new RenderListener() {
                    @Override
                    public void progress(int error) {

                        if (error==0)
                            cv.invalidate();

                        // Count down as they complete
                        renderCount--;

                        if (renderCount==0) {
                            if (renderRequested) {
                                // If this phase of rendering has completed and another has
                                // been requested, start it now
                                renderPages();
                            }
                        }
                    }
                });
            }
        }
    }

    @Override
    public void run()
    {
        if (!mScroller.isFinished())
        {
            mScroller.computeScrollOffset();
            int x = mScroller.getCurrX();
            int y = mScroller.getCurrY();
            mXScroll += x - mScrollerLastX;
            mYScroll += y - mScrollerLastY;
            mScrollerLastX = x;
            mScrollerLastY = y;

            //  limit the amount of repeated layouts.
            long tNow = System.currentTimeMillis();
            long diff = tNow - mFlingStartTime;
            if (diff>FLING_THROTTLE_TIME)
            {
                requestLayout();
                mFlingStartTime = tNow;
            }

            mStepper.prod();
        }
        else
        {
            //  one more
            long tNow = System.currentTimeMillis();
            if (tNow != mFlingStartTime)
                requestLayout();
        }
    }

    public void finish()
    {
        //  we're done with this view.
        mFinished = true;

        //  first, hide and remove all the children
        for (int i=0; i<getPageCount(); i++)
        {
            DocPageView cv = (DocPageView)getOrCreateChild(i);
            cv.setVisibility(GONE);
            removeViewInLayout(cv);
            cv.finish();
        }
    }

    public boolean finished() {return mFinished;}

    protected void smoothScrollBy(int dx, int dy)
    {
        mScrollerLastX = mScrollerLastY = 0;
        mScroller.startScroll(0, 0, dx, dy, 400);
        mStepper.prod();
    }

    public void scrollToPage(int pageNumber)
    {
        //  scroll to bring the page into view

        //  get current viewport
        Rect viewport = new Rect();
        getGlobalVisibleRect(viewport);

        //  offset it based on current scroll position
        Point viewportOrigin = new Point();
        viewportOrigin.set(getScrollX(), getScrollY());
        viewport.offsetTo(viewportOrigin.x, viewportOrigin.y);

        //  get page rect from last layout
        DocPageView cv = (DocPageView)getOrCreateChild(pageNumber);
        Rect childRect = cv.getChildRect();

        //  scroll
        if ((childRect.height()) > viewport.height())
        {
            //  put the top of the page at the top and the left at 0
            smoothScrollBy(getScrollX(),getScrollY()-childRect.top);
        }
        else
        {
            //  if the whole page is not visible, move the center of the page at the center
            if (childRect.top < viewport.top || childRect.bottom > viewport.bottom)
            {
                if (childRect.top==0)
                    smoothScrollBy(0, getScrollY());
                else
                    smoothScrollBy(0, getScrollY() + viewport.height() / 2 - (childRect.bottom + childRect.top) / 2);
            }
        }
    }

    private Point viewToScreen(Point p)
    {
        Point newPoint = new Point(p);

        Rect r = new Rect();
        this.getGlobalVisibleRect(r);

        newPoint.offset(r.left, r.top);

        return newPoint;
    }

    public void scrollBoxIntoView (int pageNum, RectF box)
    {
        //  get our viewport
        Rect viewport = new Rect();
        getGlobalVisibleRect(viewport);
        viewport.offset(0,-viewport.top);

        //  get the location of the box's lower left corner,
        //  relative to the viewport
        DocPageView cv = (DocPageView)getOrCreateChild(pageNum);
        Point point = cv.pageToView((int)box.left,(int)box.bottom);
        Rect childRect = cv.getChildRect();
        point.y += childRect.top;
        point.y -= getScrollY();

        //  if the point is outside the viewport, scroll so it is.
        if (point.y<viewport.top || point.y>viewport.bottom)
        {
            int diff = (viewport.top + viewport.bottom)/2 - point.y;
            smoothScrollBy(0,diff);
        }
    }
}
