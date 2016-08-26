package com.artifex.mupdf.android;


import android.content.Context;
import android.graphics.Color;
import android.graphics.Point;
import android.util.DisplayMetrics;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.PopupWindow;
import android.widget.TextView;

import com.artifex.mupdf.fitz.R;

public class ColorDialog implements View.OnTouchListener, PopupWindow.OnDismissListener {

	//  these are set in the constructor.
	private final Context mContext;
	private final View mAnchor;
	private final ColorChangedListener mListener;
	private final int mDialogType;
	private boolean mAutoDismiss = false;

	//  only one ColorDialog at a time please.
	private static ColorDialog singleton = null;

	//  a popup window for us.
	private PopupWindow popupWindow;

	//  two different variants of this dilog
	public static final int FG_COLORS = 1;
	public static final int BG_COLORS = 2;

	//  allowable foreground colors.  These come from UE2FileViewerApp
	private final String mFgColors[] = {"#000000", "#FFFFFF", "#D8D8D8", "#808080", "#EEECE1", "#1F497D",
			"#0070C0", "#C0504D", "#9BBB59", "#8064A2", "#4BACC6", "#F79646", "#FF0000",
			"#FFFF00", "#DBE5F1", "#F2DCDB", "#EBF1DD", "#00B050"};

	//  constructor
	public ColorDialog(int dialogType, Context context, View anchor, ColorChangedListener listener, boolean autoDismiss)
	{
		mContext = context;
		mAnchor = anchor;
		mListener = listener;
		mDialogType = dialogType;
		mAutoDismiss = autoDismiss;
	}

	//  whether or not to show the title
	private boolean mShowTitle = true;
	public void setShowTitle(boolean val) {mShowTitle = val;}

	//  time to show the dialog
	public void show()
	{
		//  remember us
		singleton = this;

		//  get the layout
		View popupView = LayoutInflater.from(mContext).inflate(R.layout.colors, null);

		//  set the title
		TextView tv = (TextView)popupView.findViewById(R.id.color_dialog_title);
		if (mShowTitle) {
			if (mDialogType == BG_COLORS)
				tv.setText(mContext.getString(R.string.background));
			else
				tv.setText(mContext.getString(R.string.color));
		}
		else {
			tv.setVisibility(View.GONE);
		}

		//  choose the list of colors to use
		String colors[] = mFgColors;

		//  get the three rows of buttons from the layout
		LinearLayout rows[] = new LinearLayout[3];
		rows[0] = (LinearLayout)popupView.findViewById(R.id.fontcolors_row1);
		rows[1] = (LinearLayout)popupView.findViewById(R.id.fontcolors_row2);
		rows[2] = (LinearLayout)popupView.findViewById(R.id.fontcolors_row3);

		//  Set up a button for each color.
		//  Hide buttons for which there are no colors.
		int icolor = 0;
		int irow;
		for (irow=0; irow<rows.length; irow++) {
			LinearLayout row = rows[irow];
			int count = row.getChildCount();
			for (int i=0; i<count; i++) {
				Button button = (Button)row.getChildAt(i);
				if (icolor+1 <= colors.length) {
					button.setVisibility(View.VISIBLE);
					button.setBackgroundColor(Color.parseColor(colors[icolor]));
					button.setTag(colors[icolor]);
					button.setOnClickListener(new Button.OnClickListener() {
						@Override
						public void onClick(View v)
						{
							mListener.onColorChanged((String)v.getTag());
							if (mAutoDismiss)
								dismiss();
						}
					});
				}
				else {
					button.setVisibility(View.GONE);
				}
				icolor++;
			}
		}

		//  Set up the transaparent button if we're doing background colors.
		Button tpb = (Button) popupView.findViewById(R.id.transparent_color_button);
		if (mDialogType==ColorDialog.BG_COLORS) {
			tpb.setVisibility(View.VISIBLE);
			tpb.setOnClickListener(new Button.OnClickListener() {
				@Override
				public void onClick(View v)
				{
					mListener.onColorChanged((String)v.getTag());
				}
			});
		}
		else
			tpb.setVisibility(View.GONE);

		//  get screen width
		WindowManager wm = (WindowManager) mContext.getSystemService(Context.WINDOW_SERVICE);
		DisplayMetrics metrics = new DisplayMetrics();
		wm.getDefaultDisplay().getMetrics(metrics);
		int screenWidth = metrics.widthPixels;

		//  put everything in a popup window and show it.
		//  by default that's the upper right corner, but the dialog is draggable.
		popupWindow = new PopupWindow(popupView, ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
		popupWindow.setFocusable(true);
		popupView.measure(View.MeasureSpec.UNSPECIFIED, View.MeasureSpec.UNSPECIFIED);
		popupWindow.showAtLocation(mAnchor, Gravity.TOP|Gravity.LEFT, screenWidth-popupView.getMeasuredWidth()-15, 100);
		popupWindow.setClippingEnabled(false);
		//  this enables dragging
		popupView.setOnTouchListener(this);
		//  this allows us to know when the popup is being dismissed
		popupWindow.setOnDismissListener(this);
	}

	//  internal function to dismiss the popup.
	public void dismiss()
	{
		popupWindow.dismiss();
		singleton = null;
	}

	//  static function to dismiss the popup.
	static public void finish()
	{
		if (singleton!=null)
			singleton.dismiss();
	}

	//  this function is called when the user taps outside the popup.
	//  we make sure to dismiss it properly.
	@Override
	public void onDismiss() {
		dismiss();
	}

	//  we're an onTouch listener for the popup window.
	//  we use that to allow for dragging the popup around.

	private int start[];
	private final Point down = new Point();

	@Override
	public boolean onTouch(View v, MotionEvent event) {
		switch (event.getAction()) {
			case MotionEvent.ACTION_DOWN:

				start = new int[2];
				popupWindow.getContentView().getLocationOnScreen(start);
				down.set((int) event.getRawX(), (int) event.getRawY());
				break;

			case MotionEvent.ACTION_MOVE:

				int dx = down.x - (int)event.getRawX();
				int dy = down.y - (int)event.getRawY();
				popupWindow.update(start[0]-dx, start[1]-dy,-1, -1, true);
				break;
		}
		return true;
	}

	public interface ColorChangedListener {
		void onColorChanged(String color);
	}

}
