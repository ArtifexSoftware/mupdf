package com.artifex.mupdfdemo;

import java.io.UnsupportedEncodingException;

import android.content.Context;
import android.graphics.Point;
import android.graphics.PointF;
import android.graphics.RectF;
import android.util.Base64;
import android.view.MotionEvent;
import android.view.View;
import android.webkit.WebView;
import android.webkit.WebViewClient;

public class MuPDFReflowView extends WebView implements MuPDFView {
	private final MuPDFCore mCore;
	private final Point mParentSize;
	private int mPage;
	private int mContentHeight;
	AsyncTask<Void,Void,String> mLoadHTML;

	public MuPDFReflowView(Context c, MuPDFCore core, Point parentSize) {
		super(c);
		mCore = core;
		mParentSize = parentSize;
		mContentHeight = parentSize.y;
	}

	public void setPage(int page, PointF size) {
		mPage = page;
		getSettings().setJavaScriptEnabled(true);
		addJavascriptInterface(new Object(){
			public void reportContentHeight(String value) {
				mContentHeight = (int)Float.parseFloat(value);
			}
		}, "HTMLOUT");
		setWebViewClient(new WebViewClient() {
			@Override
			public void onPageFinished(WebView view, String url) {
				// Get the webview to report the content height via the interface setup
				// above. Workaround for getContentHeight not working
				view.loadUrl("javascript:elem=document.getElementsByTagName('html')[0];window.HTMLOUT.reportContentHeight("+mParentSize.x+"*elem.offsetHeight/elem.offsetWidth)");
			}
		});
		mLoadHTML = new AsyncTask<Void,Void,String>() {
			@Override
			protected String doInBackground(Void... params) {
				return mCore.html(mPage);
			}
			@Override
			protected void onPostExecute(String result) {
				byte [] utf8;
				try {
					utf8 = result.getBytes("UTF-8");
				} catch (UnsupportedEncodingException e) {
					utf8 = result.getBytes();
				}
				String b64 = Base64.encodeToString(utf8, Base64.DEFAULT);
				loadData(b64, "text/html; charset=utf-8", "base64");
			}
		};
		mLoadHTML.execute();
	}

	public int getPage() {
		return mPage;
	}

	public void blank(int page) {
	}

	public boolean passClickEvent(float x, float y) {
		return false;
	}

	public LinkInfo hitLink(float x, float y) {
		return null;
	}

	public void selectText(float x0, float y0, float x1, float y1) {
	}

	public void deselectText() {
	}

	public boolean copySelection() {
		return false;
	}

	public void strikeOutSelection() {
	}

	public void setSearchBoxes(RectF[] searchBoxes) {
	}

	public void setLinkHighlighting(boolean f) {
	}

	public void setChangeReporter(Runnable reporter) {
	}

	public void update() {
	}

	public void addHq(boolean update) {
	}

	public void removeHq() {
	}

	public void releaseResources() {
	}

	@Override
	protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
		int x, y;
		switch(View.MeasureSpec.getMode(widthMeasureSpec)) {
		case View.MeasureSpec.UNSPECIFIED:
			x = mParentSize.x;
			break;
		default:
			x = View.MeasureSpec.getSize(widthMeasureSpec);
		}
		switch(View.MeasureSpec.getMode(heightMeasureSpec)) {
		case View.MeasureSpec.UNSPECIFIED:
			y = mContentHeight;
			break;
		default:
			y = View.MeasureSpec.getSize(heightMeasureSpec);
		}

		setMeasuredDimension(x, y);
	}

	@Override
	public boolean onTouchEvent(MotionEvent ev) {
		// TODO Auto-generated method stub
		return false;
	}
}
