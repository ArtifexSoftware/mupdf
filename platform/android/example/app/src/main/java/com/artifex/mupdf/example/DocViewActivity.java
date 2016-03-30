package com.artifex.mupdf.example;

import android.app.Activity;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;

import com.artifex.mupdf.fitz.ColorSpace;
import com.artifex.mupdf.fitz.Document;
import com.artifex.mupdf.fitz.Matrix;
import com.artifex.mupdf.fitz.Page;
import com.artifex.mupdf.fitz.Pixmap;

public class DocViewActivity extends Activity
{
	private int mPageCount;
	private int mCurrentPage;

	Document mDocument;
	Page mPage;
	Bitmap mBitmap = null;

	ImageView mImageView;
	TextView mTextView;

	@Override
	protected void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_doc_view);

		mImageView = (ImageView)findViewById(R.id.image_view);
		mTextView = (TextView)findViewById(R.id.page_text);

		// load the doc
		Uri uri = getIntent().getData();
		String path = Uri.decode(uri.getEncodedPath());
		mDocument = new Document(path);
		mPageCount = mDocument.countPages();

		// show the first page
		mCurrentPage = 0;
		displayCurrentPage();
	}

	public void onFirstPageButton(final View v)
	{
		mCurrentPage = 0;
		displayCurrentPage();
	}

	public void onPreviousPageButton(final View v)
	{
		if (mCurrentPage > 0)
		{
			mCurrentPage--;
			displayCurrentPage();
		}
	}

	public void onNextPageButton(final View v)
	{
		if (mCurrentPage < mPageCount-1)
		{
			mCurrentPage++;
			displayCurrentPage();
		}
	}

	public void onLastPageButton(final View v)
	{
		mCurrentPage = mPageCount-1;
		displayCurrentPage();
	}

	private void displayCurrentPage()
	{
		// report the page number
		mTextView.setText(String.format("page %d of %d",mCurrentPage+1,mPageCount));

		// get the page
		mPage = mDocument.loadPage(mCurrentPage);

		// create a matrix that renders at 300 DPI
		Matrix m = new Matrix();
		m.scale(300.0f/72.0f);

		// create a new bitmap for the page
		Bitmap old = mBitmap;
		Pixmap pixmap = mPage.toPixmap(m, ColorSpace.DeviceBGR);
		mBitmap = Bitmap.createBitmap(pixmap.getWidth(), pixmap.getHeight(), Bitmap.Config.ARGB_8888);
		int [] pixels = pixmap.getPixels();
		mBitmap.setPixels(pixels, 0, pixmap.getWidth(), 0, 0, pixmap.getWidth(), pixmap.getHeight());

		// set the bitmap in the UI
		mImageView.setImageBitmap(mBitmap);

		// recycle the old bitmap
		if (old!=null)
			old.recycle();
	}
}
