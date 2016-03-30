package com.artifex.mupdfdemo;

import android.annotation.SuppressLint;
import android.os.Build;
import android.view.View;

public class Stepper {
	protected final View mPoster;
	protected final Runnable mTask;
	protected boolean mPending;

	public Stepper(View v, Runnable r) {
		mPoster = v;
		mTask = r;
		mPending = false;
	}

	@SuppressLint("NewApi")
	public void prod() {
		if (!mPending) {
			mPending = true;
			if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
				mPoster.postOnAnimation(new Runnable() {
					@Override
					public void run() {
						mPending = false;
						mTask.run();
					}
				});
			} else {
				mPoster.post(new Runnable() {
					@Override
					public void run() {
						mPending = false;
						mTask.run();
					}
				});

			}
		}
	}
}
