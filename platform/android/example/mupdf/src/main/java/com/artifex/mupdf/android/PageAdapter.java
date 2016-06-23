package com.artifex.mupdf.android;

import android.app.Activity;
import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;

import com.artifex.mupdf.fitz.Document;

public class PageAdapter extends BaseAdapter
{
    private final Context mContext;
    private Document mDoc;

    public PageAdapter(Context c) {
        mContext = c;
    }

    public void setDocument(Document doc) {
        mDoc = doc;
    }
    private int mWidth;
    public void setWidth(int w) {mWidth=w;}

    @Override
    public int getCount() {
        return mDoc.countPages();
    }

    public Object getItem(int position) {
        return null;  //  not used
    }

    public long getItemId(int position) {
        return 0;  //  not used
    }

    public View getView(final int position, View convertView, ViewGroup parent)
    {
        //  make or reuse a view
        DocPageView pageView;

        final Activity activity = (Activity)mContext;
        if (convertView == null)
        {
            //  make a new one
            pageView = new DocPageView(activity, mDoc);
        }
        else
        {
            //  reuse an existing one
            pageView = (DocPageView) convertView;
        }

        //  set up the page
        pageView.setupPage(position, mWidth, 1);

        return pageView;
    }
}
