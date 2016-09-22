package com.artifex.mupdf.android;


import android.app.Activity;
import android.app.ProgressDialog;
import android.content.Context;
import android.graphics.drawable.ColorDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.view.WindowManager;
import android.view.animation.Animation;
import android.view.animation.TranslateAnimation;
import android.widget.Adapter;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.FrameLayout;
import android.widget.ImageButton;
import android.widget.ListView;
import android.widget.TextView;

import com.artifex.mupdf.fitz.Document;
import com.artifex.mupdf.fitz.Page;
import com.artifex.mupdf.fitz.R;
import com.artifex.mupdf.fitz.Separation;

import java.io.File;
import java.io.FileFilter;
import java.util.LinkedList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ProofActivity extends Activity implements View.OnClickListener, DocViewBase.IdleRenderListener
{
	private DocProofView mDocView;
	private Document mDoc=null;
	private String mPath;

	private ToolbarButton mFirstPageButton;
	private ToolbarButton mPreviousPageButton;
	private ToolbarButton mNextPageButton;
	private ToolbarButton mLastPageButton;
	private ToolbarButton mColorsUpButton;
	private ToolbarButton mColorsDownButton;
	private ImageButton mBackButton;
	private Button mApplyButton;

	@Override
	protected void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);

		//  get the file path
		Uri uri = getIntent().getData();
		final String path = Uri.decode(uri.getEncodedPath());
		mPath = path;

		//  get the starting page
		final int startingPage = getIntent().getIntExtra("startingPage", 0);

		//  set up UI
		setContentView(R.layout.activity_proof_view);
		mDocView = (DocProofView) findViewById(R.id.proof_view);

		mFirstPageButton = (ToolbarButton)findViewById(R.id.proof_first_page);
		mFirstPageButton.setOnClickListener(this);

		mPreviousPageButton = (ToolbarButton)findViewById(R.id.proof_previous_page);
		mPreviousPageButton.setOnClickListener(this);

		mNextPageButton = (ToolbarButton)findViewById(R.id.proof_next_page);
		mNextPageButton.setOnClickListener(this);

		mLastPageButton = (ToolbarButton)findViewById(R.id.proof_last_page);
		mLastPageButton.setOnClickListener(this);

		mBackButton = (ImageButton) findViewById(R.id.proof_back_button);
		mBackButton.setOnClickListener(this);

		mColorsUpButton = (ToolbarButton) findViewById(R.id.proof_colors_button_up);
		mColorsUpButton.setOnClickListener(this);

		mColorsDownButton = (ToolbarButton) findViewById(R.id.proof_colors_button_down);
		mColorsDownButton.setOnClickListener(this);

		mApplyButton = (Button) findViewById(R.id.proof_apply_button);
		mApplyButton.setOnClickListener(this);
		mApplyButton.setEnabled(false);

		//  wait for layout to open the document
		final ProofActivity activity = this;
		mDocView.getViewTreeObserver().addOnGlobalLayoutListener(new ViewTreeObserver.OnGlobalLayoutListener() {
			public void onGlobalLayout() {
				mDocView.getViewTreeObserver().removeOnGlobalLayoutListener(this);

				spinner = createAndShowWaitSpinner(activity);

				mDocView.post(new Runnable() {
					@Override
					public void run()
					{
						//  Go!
						mWaitingForIdle = true;
						mDoc = new Document(path);
						mDocView.start(mDoc);
						mDocView.setIdleRenderListener(activity);
						mDocView.setCurrentPage(startingPage);
					}
				});
			}
		});
	}

	private ProgressDialog spinner = null;

	@Override
	public void finish()
	{
		//  stop the view
		mDocView.finish();

		//  kill the document
		mDoc.destroy();

		//  delete the .gproof file
		Utilities.deleteFile(mPath);

		//  delete temp files left by the proofing.
		//  these are of the form gprf_n_xxxxxx
		File dir = new File(mPath).getParentFile();
		final Pattern pattern = Pattern.compile("gprf_.*_.*");
		File[] files = dir.listFiles(new FileFilter()
		{
			public boolean accept(File file)
			{
				Matcher matcher = pattern.matcher(file.getName());
				return matcher.matches();
			}
		});
		for (File file:files)
		{
			System.out.println(String.format("deleting %s", file.getAbsolutePath()));
			file.delete();
		}

		super.finish();
	}

	@Override
	public void onClick(View v)
	{
		int pageCount = mDocView.getDoc().countPages();  //  the real page count
		int currentPage = mDocView.getCurrentPage();

		if (v == mFirstPageButton)
		{
			if (currentPage != 0)
				gotoPage(v, 0);
		}
		else if (v == mPreviousPageButton)
		{
			if (currentPage>0)
				gotoPage(v, currentPage-1);
		}
		else if (v == mNextPageButton)
		{
			if (currentPage+1<pageCount)
				gotoPage(v, currentPage+1);
		}
		else if (v == mLastPageButton)
		{
			if (currentPage != pageCount-1)
				gotoPage(v, pageCount-1);
		}
		else if (v == mBackButton)
		{
			finish();
		}
		else if (v == mColorsUpButton || v == mColorsDownButton )
		{
			onColorsButton();
		}
		else if (v == mApplyButton)
		{
			mApplyButton.setEnabled(false);
			updateColors();
		}
	}


	private int colorsWidth = -1;
	private void onColorsButton()
	{
		//  toggle the colors panel
		final View v = findViewById(R.id.proof_color_host);
		int vis = v.getVisibility();
		if (colorsWidth ==-1)
			colorsWidth = v.getWidth();

		if (vis == View.VISIBLE)
		{
			mColorsDownButton.setVisibility(View.GONE);
			mColorsUpButton.setVisibility(View.VISIBLE);

			Animation anim = new TranslateAnimation(0, colorsWidth, 0, 0);
			anim.setDuration(350);
			anim.setAnimationListener(new Animation.AnimationListener() {
				public void onAnimationStart(Animation animation) {
					v.setVisibility(View.INVISIBLE);
				}
				public void onAnimationRepeat(Animation animation) {}
				public void onAnimationEnd(Animation animation) {}
			});
			v.startAnimation(anim);
		}
		else
		{
			mColorsDownButton.setVisibility(View.VISIBLE);
			mColorsUpButton.setVisibility(View.GONE);

			Animation anim = new TranslateAnimation(colorsWidth, 0, 0, 0);
			anim.setDuration(350);
			anim.setAnimationListener(new Animation.AnimationListener() {
				public void onAnimationStart(Animation animation) {
					v.setVisibility(View.VISIBLE);
				}
				public void onAnimationRepeat(Animation animation) {}
				public void onAnimationEnd(Animation animation) {}
			});
			v.startAnimation(anim);
		}
	}

	private void gotoPage(View v, final int pageNum)
	{
		spinner = createAndShowWaitSpinner(this);
		mWaitingForIdle = true;
		v.post(new Runnable() {
			@Override
			public void run() {
				mDocView.setCurrentPage(pageNum);
			}
		});
	}

	private void setPageLabel()
	{
		int page = mDocView.getCurrentPage()+1;
		int count = mDocView.getDoc().countPages();
		String s = String.format("Page %d of %d", page, count);
		TextView tv = (TextView) findViewById(R.id.proof_page_n_of_n);
		tv.setText(s);
	}

	private boolean mWaitingForIdle = false;
	private boolean mWaitingForSpinner = false;
	private ListView mColorList = null;
	private ChooseColorAdapter mColorAdapter = null;

	@Override
	public void onIdle()
	{
		//  called when page rendering has become idle

		if (mWaitingForSpinner)
		{
			spinner.dismiss();
			mWaitingForSpinner = false;
		}

		if (mWaitingForIdle)
		{
			spinner.dismiss();
			setPageLabel();

			//  get the current page
			DocPageView dpv = (DocPageView)mDocView.getViewFromAdapter(mDocView.getCurrentPage());
			Page page = dpv.getPage();

			//  count the separations
			int numSeparations = page.countSeparations();

			//  set up the list
			mColorList = (ListView)findViewById(R.id.proof_color_list);
			mColorAdapter = new ChooseColorAdapter(getLayoutInflater(), new ColorChangeListener() {
				@Override
				public void onColorChange() {
					mApplyButton.setEnabled(true);
				}
			});
			mColorList.setAdapter(mColorAdapter);

			//  get each one
			for (int i=0; i<numSeparations; i++)
			{
				//  get it
				Separation sep = page.getSeparation(i);
				String name = sep.name;

				//  transform to a color that can be used to colorize icons
				int alpha = (sep.bgra >> 24) & 0xFF;
				int red   = (sep.bgra >> 16) & 0xFF;
				int green = (sep.bgra >> 8 ) & 0xFF;
				int blue  = (sep.bgra >> 0 ) & 0xFF;
				int color = (alpha << 24) | (red << 16) | (green << 8) | (blue << 0);

				mColorAdapter.add(new ChooseColorItem(sep.name, color, true, sep));
			}

			mColorList.getLayoutParams().width = getWidestView(getBaseContext(), mColorAdapter);

		}
		mWaitingForIdle = false;
	}

	public void updateColors()
	{
		//  get the current page
		DocPageView dpv = (DocPageView)mDocView.getViewFromAdapter(mDocView.getCurrentPage());
		Page page = dpv.getPage();

		int numSeparations = mColorAdapter.getCount();
		for (int i=0; i<numSeparations; i++)
		{
			ChooseColorItem item = (ChooseColorItem)mColorAdapter.getItem(i);
			Separation sep = item.separation;
			boolean checked = item.checked;
			String name = item.name;

			page.enableSeparation(i, checked);
		}

		spinner = createAndShowWaitSpinner(this);
		mWaitingForSpinner = true;
		mDocView.triggerRender();
	}

	private static int getWidestView(Context context, Adapter adapter)
	{
		int maxWidth = 0;
		View view = null;
		FrameLayout fakeParent = new FrameLayout(context);
		for (int i=0, count=adapter.getCount(); i<count; i++) {
			view = adapter.getView(i, view, fakeParent);
			view.measure(View.MeasureSpec.UNSPECIFIED, View.MeasureSpec.UNSPECIFIED);
			int width = view.getMeasuredWidth();
			if (width > maxWidth) {
				maxWidth = width;
			}
		}
		return maxWidth;
	}

	private static ProgressDialog createAndShowWaitSpinner(Context mContext)
	{
		ProgressDialog dialog = new ProgressDialog(mContext);
		try {
			dialog.show();
		}
		catch (WindowManager.BadTokenException e) {
		}
		dialog.setCancelable(false);
		dialog.setIndeterminate(true);
		dialog.getWindow().setBackgroundDrawable(new ColorDrawable(android.graphics.Color.TRANSPARENT));
		dialog.setContentView(R.layout.wait_spinner);
		return dialog;
	}

	//---------------------------------------------------------------------------------------------------------

	public class ChooseColorItem
	{
		public String name;
		public int color;
		public boolean checked;
		Separation separation;

		public ChooseColorItem(String name, int color, boolean checked, Separation separation)
		{
			this.checked = checked;
			this.name = name;
			this.color = color;
			this.separation = separation;
		}
	}

	//---------------------------------------------------------------------------------------------------------

	public interface ColorChangeListener
	{
		void onColorChange();
	}

	public class ChooseColorAdapter extends BaseAdapter
	{
		private final LinkedList<ChooseColorItem> mItems;
		private final LayoutInflater mInflater;
		ColorChangeListener mColorChangeListener = null;

		public ChooseColorAdapter(LayoutInflater inflater, ColorChangeListener listener)
		{
			mInflater = inflater;
			mColorChangeListener = listener;
			mItems = new LinkedList<>();
		}

		public void clear()
		{
			mItems.clear();
		}

		public void add(ChooseColorItem item)
		{
			mItems.add(item);
			notifyDataSetChanged();
		}

		public int getCount()
		{
			return mItems.size();
		}

		public Object getItem(int i)
		{
			return mItems.get(i);
		}

		public long getItemId(int arg0)
		{
			return 0;
		}

		public View getView(int position, View convertView, ViewGroup parent)
		{
			View v;
			if (convertView == null)
			{
				v = mInflater.inflate(R.layout.proof_color_list_entry, null);
			}
			else
			{
				v = convertView;
			}

			final ChooseColorItem item = mItems.get(position);

			v.setTag(item);

			View swatch = v.findViewById(R.id.proof_entry_color_swatch);
			swatch.setBackgroundColor(item.color);

			((CheckBox) v.findViewById(R.id.proof_entry_checkbox)).setChecked(item.checked);

			((CheckBox) v.findViewById(R.id.proof_entry_checkbox)).setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener()
			{
				@Override
				public void onCheckedChanged(CompoundButton buttonView, boolean isChecked)
				{
					item.checked = isChecked;
					if (mColorChangeListener!=null)
						mColorChangeListener.onColorChange();
				}
			});

			((TextView) v.findViewById(R.id.proof_entry_label)).setText(item.name);

			return v;
		}

	}


}
