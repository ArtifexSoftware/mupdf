package com.artifex.mupdf.android;

import android.annotation.SuppressLint;
import android.os.Build;
import android.view.View;

public class Stepper {
    private final View mPoster;
    private final Runnable mTask;
    private boolean mPending;

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
