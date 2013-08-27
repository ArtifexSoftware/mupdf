package com.artifex.mupdfdemo;

import android.net.Uri;

interface FilePickerSupport {
	void performPickFor(FilePicker picker);
}

public abstract class FilePicker {
	private final FilePickerSupport support;

	FilePicker(FilePickerSupport _support) {
		support = _support;
	}

	void pick() {
		support.performPickFor(this);
	}

	abstract void onPick(Uri uri);
}
