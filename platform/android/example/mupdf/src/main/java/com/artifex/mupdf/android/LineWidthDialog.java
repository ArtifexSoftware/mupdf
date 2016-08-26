package com.artifex.mupdf.android;

import android.content.Context;
import android.database.DataSetObserver;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.PopupWindow;
import android.widget.TextView;

import com.artifex.mupdf.fitz.R;

import kankan.wheel.widget.OnWheelScrollListener;
import kankan.wheel.widget.WheelView;
import kankan.wheel.widget.adapters.WheelViewAdapter;

public class LineWidthDialog
{
	private static final int POPUP_OFFSET = 30;

	private static final float values[] = new float[] {0.25f, 0.5f, 1, 1.5f, 3, 4.5f, 6, 8, 12, 18, 24};

	public static void show(Context context, View anchor, float val, final WidthChangedListener listener)
	{
		float currentValue = val;

		View layout = View.inflate(context, R.layout.line_width_dialog, null);

		View wv = layout.findViewById(R.id.wheel);
		WheelView wheel = (WheelView)wv;

		final LineWidthAdapter adapter = new LineWidthAdapter(context, values);

		wheel.setViewAdapter(adapter);
		wheel.setVisibleItems(5);

		wheel.setCurrentItem(0);
		for (int i=0;i<values.length;i++)
		{
			if (values[i] == currentValue)
				wheel.setCurrentItem(i);
		}

		wheel.addScrollingListener(new OnWheelScrollListener() {
			@Override
			public void onScrollingStarted(WheelView wheel) {}

			@Override
			public void onScrollingFinished(WheelView wheel) {
				listener.onWidthChanged(values[wheel.getCurrentItem()]);
			}
		});

		//  make a popup window
		final PopupWindow popup = new PopupWindow(layout,
				ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
		popup.setFocusable(true);

		//  now show the popup
		popup.showAsDropDown(anchor,POPUP_OFFSET,POPUP_OFFSET);
	}

	public static class LineWidthAdapter implements WheelViewAdapter
	{
		public LineWidthAdapter(Context context, float values[]) {
			super();
			mValues = values;
			mContext = context;
		}

		private Context mContext;
		private float mValues[];

		@Override
		public View getItem(int position, View convertView, ViewGroup parent)
		{
			//  make a View if needed.
			if (convertView == null)
			{
				LayoutInflater inflater = (LayoutInflater) mContext.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
				convertView = inflater.inflate(R.layout.line_width_item, parent, false);
			}

			//  get the value
			float value = values[position];

			//  set the text string
			TextView tv = ((TextView)convertView.findViewById(R.id.value));
			if(value == (int) value)
				tv.setText(String.format("%d pt",(int)value));
			else
				tv.setText(String.format("%s pt",value));

			//  adjust the height of the line
			int h = (int)(value*3f/2f);
			if (h<1)
				h = 1;
			View bar = ((View)convertView.findViewById(R.id.bar));
			bar.getLayoutParams().height = h;
			bar.setLayoutParams(bar.getLayoutParams());

			return convertView;
		}

		@Override
		public int getItemsCount() {
			return mValues.length;
		}

		@Override
		public View getEmptyItem(View convertView, ViewGroup parent) {
			return null;
		}

		@Override
		public void registerDataSetObserver(DataSetObserver observer) {
		}

		@Override
		public void unregisterDataSetObserver(DataSetObserver observer) {
		}
	}

	public interface WidthChangedListener {
		void onWidthChanged(float value);
	}

}
