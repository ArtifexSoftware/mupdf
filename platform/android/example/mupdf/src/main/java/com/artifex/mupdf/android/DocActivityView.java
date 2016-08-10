package com.artifex.mupdf.android;

import android.content.Context;
import android.util.AttributeSet;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewTreeObserver;
import android.view.inputmethod.InputMethodManager;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TabHost;
import android.widget.TextView;

import com.artifex.mupdf.fitz.Link;
import com.artifex.mupdf.fitz.Outline;
import com.artifex.mupdf.fitz.R;

public class DocActivityView extends FrameLayout implements TabHost.OnTabChangeListener
{
	private DocView mDocView;
	private DocListPagesView mDocView2;
	private Context mContext = null;
	private boolean layoutAgain = false;

	//  tab tags
	private String mTagHidden;
	private String mTagFile;
	private String mTagAnnotate;
	private String mTagPages;

	public DocActivityView(Context context)
	{
		super(context);
		initialize(context);
	}

	public DocActivityView(Context context, AttributeSet attrs)
	{
		super(context, attrs);
		initialize(context);
	}

	public DocActivityView(Context context, AttributeSet attrs, int defStyle)
	{
		super(context, attrs, defStyle);
		initialize(context);
	}

	protected void initialize(Context context)
	{
		mContext = context;

		final LayoutInflater inflater = (LayoutInflater) mContext.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
		final LinearLayout view = (LinearLayout) inflater.inflate(R.layout.doc_view, null);
		addView(view);

		mDocView = (DocView) view.findViewById(R.id.doc_view_inner);

		if (usePagesView())
		{
			mDocView2 = new DocListPagesView(context);
			mDocView2.setMainView(mDocView);
		}

		if (usePagesView())
		{
			//  pages container
			LinearLayout layout2 = (LinearLayout) findViewById(R.id.pages_container);
			layout2.addView(mDocView2);
		}

		//  tabs
		setupTabs();

		//  selection handles
		View v = view.findViewById(R.id.doc_wrapper);
		RelativeLayout layout = (RelativeLayout) v;
		mDocView.setupHandles(layout);

		//  listen for layout changes on the main doc view, and
		//  copy the "most visible" value to the page list.
		ViewTreeObserver observer2 = mDocView.getViewTreeObserver();
		observer2.addOnGlobalLayoutListener(new ViewTreeObserver.OnGlobalLayoutListener()
		{
			@Override
			public void onGlobalLayout()
			{
				if (usePagesView())
				{
					int mvp = mDocView.getMostVisiblePage();
					mDocView2.setMostVisiblePage(mvp);
				}
			}
		});

		//  TODO: connect buttons to functions
	}

	protected boolean usePagesView()
	{
		return true;
	}

	protected void setupTabs()
	{
		TabHost tabHost = (TabHost) findViewById(R.id.tabhost);
		tabHost.setup();

		//  get the tab tags.
		mTagHidden = getResources().getString(R.string.hidden_tab);
		mTagFile = getResources().getString(R.string.file_tab);
		mTagAnnotate = getResources().getString(R.string.annotate_tab);
		mTagPages = getResources().getString(R.string.pages_tab);

		//  first tab is and stays hidden.
		//  when the search tab is selected, we programmatically "select" this hidden tab
		//  which results in NO tabs appearing selected in this tab host.
		setupTab(tabHost, mTagHidden, R.id.hiddenTab, R.layout.tab);
		tabHost.getTabWidget().getChildTabViewAt(0).setVisibility(View.GONE);

		//  these tabs are shown.
		setupTab(tabHost, mTagFile, R.id.fileTab, R.layout.tab_left);
		setupTab(tabHost, mTagAnnotate, R.id.annotateTab, R.layout.tab);
		setupTab(tabHost, mTagPages, R.id.pagesTab, R.layout.tab_right);

		//  start by showing the edit tab
		tabHost.setCurrentTabByTag(mTagFile);

		tabHost.setOnTabChangedListener(this);
	}

	protected void setupTab(TabHost tabHost, String text, int viewId, int tabId)
	{
		View tabview = LayoutInflater.from(tabHost.getContext()).inflate(tabId, null);
		TextView tv = (TextView) tabview.findViewById(R.id.tabText);
		tv.setText(text);

		TabHost.TabSpec tab = tabHost.newTabSpec(text);
		tab.setIndicator(tabview);
		tab.setContent(viewId);
		tabHost.addTab(tab);
	}

	@Override
	public void onTabChanged(String tabId)
	{
		//  hide the search tab
		findViewById(R.id.searchTab).setVisibility(View.GONE);

		//  show search is not selected
		showSearchSelected(false);

		//  show/hide the pages view
		handlePagesTab(tabId);

		hideKeyboard();
	}

	private void showSearchSelected(boolean selected)
	{

	}

	protected void handlePagesTab(String tabId)
	{
		if (tabId.equals(mTagPages))
			showPages();
		else
			hidePages();
	}

	protected void showPages()
	{
		LinearLayout pages = (LinearLayout) findViewById(R.id.pages_container);
		if (null == pages)
			return;

		if (pages.getVisibility() == View.VISIBLE)
			return;

		pages.setVisibility(View.VISIBLE);
		ViewTreeObserver observer = mDocView.getViewTreeObserver();
		observer.addOnGlobalLayoutListener(new ViewTreeObserver.OnGlobalLayoutListener()
		{
			@Override
			public void onGlobalLayout()
			{
				mDocView.getViewTreeObserver().removeOnGlobalLayoutListener(this);
				mDocView.onShowPages();
			}
		});
	}

	protected void hidePages()
	{
		LinearLayout pages = (LinearLayout) findViewById(R.id.pages_container);
		if (null == pages)
			return;

		if (pages.getVisibility() == View.GONE)
			return;

		pages.setVisibility(View.GONE);
		ViewTreeObserver observer = mDocView.getViewTreeObserver();
		observer.addOnGlobalLayoutListener(new ViewTreeObserver.OnGlobalLayoutListener()
		{
			@Override
			public void onGlobalLayout()
			{
				mDocView.getViewTreeObserver().removeOnGlobalLayoutListener(this);
				mDocView.onHidePages();
			}
		});
	}

	public boolean showKeyboard()
	{
		//  show keyboard
		InputMethodManager im = (InputMethodManager) mContext.getSystemService(Context.INPUT_METHOD_SERVICE);
		im.toggleSoftInput(InputMethodManager.SHOW_FORCED, InputMethodManager.HIDE_IMPLICIT_ONLY);

		return true;
	}

	public void hideKeyboard()
	{
		//  hide the keyboard
		InputMethodManager im = (InputMethodManager) mContext.getSystemService(Context.INPUT_METHOD_SERVICE);
		im.hideSoftInputFromWindow(mDocView.getWindowToken(), 0);
	}

	public void start(final String path)
	{
		//  wait for the first layout to finish
		ViewTreeObserver observer = getViewTreeObserver();
		observer.addOnGlobalLayoutListener(new ViewTreeObserver.OnGlobalLayoutListener()
		{
			@Override
			public void onGlobalLayout()
			{
				getViewTreeObserver().removeOnGlobalLayoutListener(this);

				//  signal that we want one more layout.  When the title bar get hidden,
				//  this view will get an additional layout, at which time we'll
				//  re-layout the inner view. (see below)
				//  I don't like this, but it seems to work.
				layoutAgain = true;
				mDocView.start(path);

				if (usePagesView())
				{
					mDocView2.clone(mDocView);
				}

			}
		});
	}

	protected void onLayout(boolean changed, int left, int top, int right, int bottom)
	{

		super.onLayout(changed, left, top, right, bottom);

		if (layoutAgain)
		{
			//  this is the additional layout.
			//  so now re-lay out the inner view.
			layoutAgain = false;
			mDocView.requestLayout();
		}
	}

	private void onOutline(final Outline[] outline, int level)
	{
		if (outline == null)
			return;

		for (Outline entry : outline)
		{
			int numberOfSpaces = (level) * 4;
			String spaces = "";
			if (numberOfSpaces > 0)
				spaces = String.format("%" + numberOfSpaces + "s", " ");
			Log.i("example", String.format("%d %s %s %s", entry.page + 1, spaces, entry.title, entry.uri));
			if (entry.down != null)
			{
				//  branch
				onOutline(entry.down, level + 1);
			}
		}
	}

	private void onLinks()
	{
		int numPages = mDocView.getPageCount();
		for (int pageNum = 0; pageNum < numPages; pageNum++)
		{
			DocPageView cv = (DocPageView) mDocView.getOrCreateChild(pageNum);

			Link links[] = cv.getPage().getLinks();
			if (links != null)
			{

				for (int i = 0; i < links.length; i++)
				{
					Link link = links[i];

					Log.i("example", String.format("links for page %d:", pageNum));
					Log.i("example", String.format("     link %d:", i));
					Log.i("example", String.format("          page = %d", link.page));
					Log.i("example", String.format("          uri = %s", link.uri));
					Log.i("example", String.format("          bounds = %f %f %f %f ",
							link.bounds.x0, link.bounds.y0, link.bounds.x1, link.bounds.y1));
				}
			}
			else
			{
				Log.i("example", String.format("no links for page %d", pageNum));
			}

		}
	}

	public void showUI(boolean show)
	{
		View tabHost = findViewById(R.id.tabhost);
		View footer = findViewById(R.id.footer);
		if (show)
		{
			tabHost.setVisibility(View.VISIBLE);
			footer.setVisibility(View.VISIBLE);
			requestLayout();
		}
		else
		{
			tabHost.setVisibility(View.GONE);
			footer.setVisibility(View.GONE);
			requestLayout();
		}
	}

	public void stop()
	{
		mDocView.finish();
		if (usePagesView())
		{
			mDocView2.finish();
		}
	}
}
