package com.artifex.mupdfdemo;

import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.graphics.RectF;
import android.os.Handler;

class ProgressDialogX extends ProgressDialog {
	public ProgressDialogX(Context context) {
		super(context);
	}

	private boolean mCancelled = false;

	public boolean isCancelled() {
		return mCancelled;
	}

	@Override
	public void cancel() {
		mCancelled = true;
		super.cancel();
	}
}

public abstract class SearchTask {
	private static final int SEARCH_PROGRESS_DELAY = 200;
	private final Context mContext;
	private final MuPDFCore mCore;
	private final Handler mHandler;
	private final AlertDialog.Builder mAlertBuilder;
	private AsyncTask<Void,Integer,SearchTaskResult> mSearchTask;

	public SearchTask(Context context, MuPDFCore core) {
		mContext = context;
		mCore = core;
		mHandler = new Handler();
		mAlertBuilder = new AlertDialog.Builder(context);
	}

	protected abstract void onTextFound(SearchTaskResult result);

	public void stop() {
		if (mSearchTask != null) {
			mSearchTask.cancel(true);
			mSearchTask = null;
		}
	}

	public void go(final String text, int direction, int displayPage, int searchPage) {
		if (mCore == null)
			return;
		stop();

		final int increment = direction;
		final int startIndex = searchPage == -1 ? displayPage : searchPage + increment;

		final ProgressDialogX progressDialog = new ProgressDialogX(mContext);
		progressDialog.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL);
		progressDialog.setTitle(mContext.getString(R.string.searching_));
		progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() {
			public void onCancel(DialogInterface dialog) {
				stop();
			}
		});
		progressDialog.setMax(mCore.countPages());

		mSearchTask = new AsyncTask<Void,Integer,SearchTaskResult>() {
			@Override
			protected SearchTaskResult doInBackground(Void... params) {
				int index = startIndex;

				while (0 <= index && index < mCore.countPages() && !isCancelled()) {
					publishProgress(index);
					RectF searchHits[] = mCore.searchPage(index, text);

					if (searchHits != null && searchHits.length > 0)
						return new SearchTaskResult(text, index, searchHits);

					index += increment;
				}
				return null;
			}

			@Override
			protected void onPostExecute(SearchTaskResult result) {
				progressDialog.cancel();
				if (result != null) {
					onTextFound(result);
				} else {
					mAlertBuilder.setTitle(SearchTaskResult.get() == null ? R.string.text_not_found : R.string.no_further_occurrences_found);
					AlertDialog alert = mAlertBuilder.create();
					alert.setButton(AlertDialog.BUTTON_POSITIVE, mContext.getString(R.string.dismiss),
							(DialogInterface.OnClickListener)null);
					alert.show();
				}
			}

			@Override
			protected void onCancelled() {
				progressDialog.cancel();
			}

			@Override
			protected void onProgressUpdate(Integer... values) {
				progressDialog.setProgress(values[0].intValue());
			}

			@Override
			protected void onPreExecute() {
				super.onPreExecute();
				mHandler.postDelayed(new Runnable() {
					public void run() {
						if (!progressDialog.isCancelled())
						{
							progressDialog.show();
							progressDialog.setProgress(startIndex);
						}
					}
				}, SEARCH_PROGRESS_DELAY);
			}
		};

		mSearchTask.execute();
	}
}
