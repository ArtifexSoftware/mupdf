package com.artifex.mupdf.android;

import android.content.Context;
import android.os.Build;
import android.util.AttributeSet;
import android.util.Base64;
import android.view.MotionEvent;
import android.webkit.WebView;
import android.webkit.WebViewClient;

public class DocReflowView extends WebView
{
	private float mScale;
	private float mStartScale;

	public DocReflowView(Context context)
	{
		super(context);
		initialize(context);
	}

	public DocReflowView(Context context, AttributeSet attrs)
	{
		super(context, attrs);
		initialize(context);
	}

	public DocReflowView(Context context, AttributeSet attrs, int defStyle)
	{
		super(context, attrs, defStyle);
		initialize(context);
	}

	private void initialize(Context context)
	{
		getSettings().setJavaScriptEnabled(true);
		getSettings().setBuiltInZoomControls(true);
		getSettings().setDisplayZoomControls(false);
		getSettings().setUseWideViewPort(true);

		mScale = getResources().getDisplayMetrics().density;

		setWebViewClient(new MyWebViewClient());
	}

	public void setHTML(byte bytes[])
	{
		//  preserve zoom level between pages

		int zoom = (int)(100 * mScale);

		String b64 = Base64.encodeToString(bytes, Base64.DEFAULT);
		loadData(b64, "text/html; charset=utf-8", "base64");

		setInitialScale(zoom);
		scrollTo(0, 0);
	}

	private void doJavaScript(String javaScript)
	{
		if (Build.VERSION.SDK_INT >= 19)
		{
			evaluateJavascript(javaScript, null);
		}
		else
		{
			loadUrl("javascript:" + javaScript);
		}
	}

	@Override
	public boolean onTouchEvent(MotionEvent event)
	{
		if ((event.getAction() & MotionEvent.ACTION_MASK) == MotionEvent.ACTION_DOWN)
		{
			//  do something when user interaction begins
			mStartScale = mScale;
		}

		if ((event.getAction() & MotionEvent.ACTION_MASK) == MotionEvent.ACTION_UP)
		{
			//  do something when user interaction ends
			if (mScale != mStartScale)
			{
				scrollTo(0, getScrollY());
				doJavaScript("document.getElementById('content').style.width = window.innerWidth;");
			}
			mStartScale = mScale;
		}

		return super.onTouchEvent(event);
	}

	public class MyWebViewClient extends WebViewClient
	{
		@Override
		public void onScaleChanged(final WebView webView, float oldScale, float newScale)
		{
			mScale = newScale;
		}
	}

}
