package com.artifex.mupdfdemo;

import android.net.Uri;

public abstract class FilePicker {
	public interface FilePickerSupport {
		void performPickFor(FilePicker picker);
	}

	private final FilePickerSupport support;

	FilePicker(FilePickerSupport _support) {
		support = _support;
	}

	void pick() {
		support.performPickFor(this);
	}

	abstract void onPick(Uri uri);
}
