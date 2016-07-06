package com.artifex.mupdf.example;

import android.app.Activity;
import android.net.Uri;
import android.os.Bundle;

import com.artifex.mupdf.android.DocView;

public class DocViewActivity extends Activity
{
	private DocView mDocView;

	@Override
	protected void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);

		//  set up UI
		setContentView(R.layout.activity_doc_view);
		mDocView = (DocView)findViewById(R.id.doc_view);

		//  get the file path
		Uri uri = getIntent().getData();
		final String path = Uri.decode(uri.getEncodedPath());

		//  start the view
		mDocView.start(path);
	}
}
