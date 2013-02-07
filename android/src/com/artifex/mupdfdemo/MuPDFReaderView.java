package com.artifex.mupdfdemo;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.util.DisplayMetrics;
import android.view.MotionEvent;
import android.view.ScaleGestureDetector;
import android.view.View;

public class MuPDFReaderView extends ReaderView {
	private final Context mContext;
	private boolean mLinksEnabled = false;
	private boolean mSelecting = false;
	private boolean tapDisabled = false;
	private int tapPageMargin;

	protected void onTapMainDocArea() {}
	protected void onDocMotion() {}

	public void setLinksEnabled(boolean b) {
		mLinksEnabled = b;
		resetupChildren();
	}

	public void setSelectionMode(boolean b) {
		mSelecting = b;
	}

	public MuPDFReaderView(Activity act) {
		super(act);
		mContext = act;
		// Get the screen size etc to customise tap margins.
		// We calculate the size of 1 inch of the screen for tapping.
		// On some devices the dpi values returned are wrong, so we
		// sanity check it: we first restrict it so that we are never
		// less than 100 pixels (the smallest Android device screen
		// dimension I've seen is 480 pixels or so). Then we check
		// to ensure we are never more than 1/5 of the screen width.
		DisplayMetrics dm = new DisplayMetrics();
		act.getWindowManager().getDefaultDisplay().getMetrics(dm);
		tapPageMargin = (int)dm.xdpi;
		if (tapPageMargin < 100)
			tapPageMargin = 100;
		if (tapPageMargin > dm.widthPixels/5)
			tapPageMargin = dm.widthPixels/5;
	}

	public boolean onSingleTapUp(MotionEvent e) {
		LinkInfo link = null;

		if (!mSelecting && !tapDisabled) {
			MuPDFView pageView = (MuPDFView) getDisplayedView();
			if (MuPDFCore.javascriptSupported()
					&& pageView.passClickEvent(e.getX(), e.getY())) {
				// If the page consumes the event do nothing else
			} else if (mLinksEnabled && pageView != null
					&& (link = pageView.hitLink(e.getX(), e.getY())) != null) {
				link.acceptVisitor(new LinkInfoVisitor() {
					@Override
					public void visitInternal(LinkInfoInternal li) {
						// Clicked on an internal (GoTo) link
						setDisplayedViewIndex(li.pageNumber);
					}

					@Override
					public void visitExternal(LinkInfoExternal li) {
						Intent intent = new Intent(Intent.ACTION_VIEW, Uri
								.parse(li.url));
						mContext.startActivity(intent);
					}

					@Override
					public void visitRemote(LinkInfoRemote li) {
						// Clicked on a remote (GoToR) link
					}
				});
			} else if (e.getX() < tapPageMargin) {
				super.smartMoveBackwards();
			} else if (e.getX() > super.getWidth() - tapPageMargin) {
				super.smartMoveForwards();
			} else if (e.getY() < tapPageMargin) {
				super.smartMoveBackwards();
			} else if (e.getY() > super.getHeight() - tapPageMargin) {
				super.smartMoveForwards();
			} else {
				onTapMainDocArea();
			}
		}
		return super.onSingleTapUp(e);
	}

	public boolean onScroll(MotionEvent e1, MotionEvent e2, float distanceX,
			float distanceY) {
		if (!mSelecting) {
			if (!tapDisabled)
				onDocMotion();

			return super.onScroll(e1, e2, distanceX, distanceY);
		} else {
			MuPDFView pageView = (MuPDFView)getDisplayedView();
			if (pageView != null)
				pageView.selectText(e1.getX(), e1.getY(), e2.getX(), e2.getY());
			return true;
		}
	}

	@Override
	public boolean onFling(MotionEvent e1, MotionEvent e2, float velocityX,
			float velocityY) {
		if (!mSelecting)
			return super.onFling(e1, e2, velocityX, velocityY);
		else
			return true;
	}

	public boolean onScaleBegin(ScaleGestureDetector d) {
		// Disabled showing the buttons until next touch.
		// Not sure why this is needed, but without it
		// pinch zoom can make the buttons appear
		tapDisabled = true;
		return super.onScaleBegin(d);
	}

	public boolean onTouchEvent(MotionEvent event) {
		if (event.getActionMasked() == MotionEvent.ACTION_DOWN)
			tapDisabled = false;

		return super.onTouchEvent(event);
	}

	protected void onChildSetup(int i, View v) {
		if (SearchTaskResult.get() != null
				&& SearchTaskResult.get().pageNumber == i)
			((MuPDFView) v).setSearchBoxes(SearchTaskResult.get().searchBoxes);
		else
			((MuPDFView) v).setSearchBoxes(null);

		((MuPDFView) v).setLinkHighlighting(mLinksEnabled);

		((MuPDFView) v).setChangeReporter(new Runnable() {
			public void run() {
				applyToChildren(new ReaderView.ViewMapper() {
					@Override
					void applyToView(View view) {
						((MuPDFView) view).update();
					}
				});
			}
		});
	}

	protected void onMoveToChild(int i) {
		if (SearchTaskResult.get() != null
				&& SearchTaskResult.get().pageNumber != i) {
			SearchTaskResult.set(null);
			resetupChildren();
		}
	}

	protected void onSettle(View v) {
		// When the layout has settled ask the page to render
		// in HQ
		((MuPDFView) v).addHq(false);
	}

	protected void onUnsettle(View v) {
		// When something changes making the previous settled view
		// no longer appropriate, tell the page to remove HQ
		((MuPDFView) v).removeHq();
	}

	@Override
	protected void onNotInUse(View v) {
		((MuPDFView) v).releaseResources();
	}

	@Override
	protected void onScaleChild(View v, Float scale) {
		((MuPDFView) v).setScale(scale);
	}
}
