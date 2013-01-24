package com.artifex.mupdfdemo;
import java.util.ArrayList;

import android.graphics.Bitmap;
import android.graphics.Bitmap.Config;
import android.graphics.PointF;
import android.graphics.RectF;

public class MuPDFCore
{
	/* load our native library */
	static {
		System.loadLibrary("mupdf");
	}

	/* Readable members */
	private int numPages = -1;
	private float pageWidth;
	private float pageHeight;
	private long globals;
	private byte fileBuffer[];

	/* The native functions */
	private native long openFile(String filename);
	private native long openBuffer();
	private native int countPagesInternal();
	private native void gotoPageInternal(int localActionPageNum);
	private native float getPageWidth();
	private native float getPageHeight();
	private native void drawPage(Bitmap bitmap,
			int pageW, int pageH,
			int patchX, int patchY,
			int patchW, int patchH);
	private native void updatePageInternal(Bitmap bitmap,
			int page,
			int pageW, int pageH,
			int patchX, int patchY,
			int patchW, int patchH);
	private native RectF[] searchPage(String text);
	private native TextChar[][][][] text();
	private native int passClickEventInternal(int page, float x, float y);
	private native void setFocusedWidgetChoiceSelectedInternal(String [] selected);
	private native String [] getFocusedWidgetChoiceSelected();
	private native String [] getFocusedWidgetChoiceOptions();
	private native int setFocusedWidgetTextInternal(String text);
	private native String getFocusedWidgetTextInternal();
	private native int getFocusedWidgetTypeInternal();
	private native LinkInfo [] getPageLinksInternal(int page);
	private native RectF[] getWidgetAreasInternal(int page);
	private native OutlineItem [] getOutlineInternal();
	private native boolean hasOutlineInternal();
	private native boolean needsPasswordInternal();
	private native boolean authenticatePasswordInternal(String password);
	private native MuPDFAlertInternal waitForAlertInternal();
	private native void replyToAlertInternal(MuPDFAlertInternal alert);
	private native void startAlertsInternal();
	private native void stopAlertsInternal();
	private native void destroying();
	private native boolean hasChangesInternal();
	private native void saveInternal();

	public static native boolean javascriptSupported();

	public MuPDFCore(String filename) throws Exception
	{
		globals = openFile(filename);
		if (globals == 0)
		{
			throw new Exception("Failed to open "+filename);
		}
	}

	public MuPDFCore(byte buffer[]) throws Exception
	{
		fileBuffer = buffer;
		globals = openBuffer();
		if (globals == 0)
		{
			throw new Exception("Failed to open buffer");
		}
	}

	public  int countPages()
	{
		if (numPages < 0)
			numPages = countPagesSynchronized();

		return numPages;
	}

	private synchronized int countPagesSynchronized() {
		return countPagesInternal();
	}

	/* Shim function */
	private void gotoPage(int page)
	{
		if (page > numPages-1)
			page = numPages-1;
		else if (page < 0)
			page = 0;
		gotoPageInternal(page);
		this.pageWidth = getPageWidth();
		this.pageHeight = getPageHeight();
	}

	public synchronized PointF getPageSize(int page) {
		gotoPage(page);
		return new PointF(pageWidth, pageHeight);
	}

	public MuPDFAlert waitForAlert() {
		MuPDFAlertInternal alert = waitForAlertInternal();
		return alert != null ? alert.toAlert() : null;
	}

	public void replyToAlert(MuPDFAlert alert) {
		replyToAlertInternal(new MuPDFAlertInternal(alert));
	}

	public void stopAlerts() {
		stopAlertsInternal();
	}

	public void startAlerts() {
		startAlertsInternal();
	}

	public synchronized void onDestroy() {
		destroying();
		globals = 0;
	}

	public synchronized Bitmap drawPage(int page,
			int pageW, int pageH,
			int patchX, int patchY,
			int patchW, int patchH) {
		gotoPage(page);
		Bitmap bm = Bitmap.createBitmap(patchW, patchH, Config.ARGB_8888);
		drawPage(bm, pageW, pageH, patchX, patchY, patchW, patchH);
		return bm;
	}

	public synchronized Bitmap updatePage(BitmapHolder h, int page,
			int pageW, int pageH,
			int patchX, int patchY,
			int patchW, int patchH) {
		Bitmap bm = null;
		Bitmap old_bm = h.getBm();

		if (old_bm == null)
			return null;

		bm = old_bm.copy(Bitmap.Config.ARGB_8888, false);
		old_bm = null;

		updatePageInternal(bm, page, pageW, pageH, patchX, patchY, patchW, patchH);
		return bm;
	}

	public synchronized PassClickResult passClickEvent(int page, float x, float y) {
		boolean changed = passClickEventInternal(page, x, y) != 0;

		switch (WidgetType.values()[getFocusedWidgetTypeInternal()])
		{
		case TEXT:
			return new PassClickResultText(changed, getFocusedWidgetTextInternal());
		case LISTBOX:
		case COMBOBOX:
			return new PassClickResultChoice(changed, getFocusedWidgetChoiceOptions(), getFocusedWidgetChoiceSelected());
		default:
			return new PassClickResult(changed);
		}

	}

	public synchronized boolean setFocusedWidgetText(int page, String text) {
		boolean success;
		gotoPage(page);
		success = setFocusedWidgetTextInternal(text) != 0 ? true : false;

		return success;
	}

	public synchronized void setFocusedWidgetChoiceSelected(String [] selected) {
		setFocusedWidgetChoiceSelectedInternal(selected);
	}

	public synchronized LinkInfo [] getPageLinks(int page) {
		return getPageLinksInternal(page);
	}

	public synchronized RectF [] getWidgetAreas(int page) {
		return getWidgetAreasInternal(page);
	}

	public synchronized RectF [] searchPage(int page, String text) {
		gotoPage(page);
		return searchPage(text);
	}

	public synchronized TextWord [][] textLines(int page) {
		gotoPage(page);
		TextChar[][][][] chars = text();

		// The text of the page held in a hierarchy (blocks, lines, spans).
		// Currently we don't need to distinguish the blocks level or
		// the spans, and we need to collect the text into words.
		ArrayList<TextWord[]> lns = new ArrayList<TextWord[]>();

		for (TextChar[][][] bl: chars) {
			for (TextChar[][] ln: bl) {
				ArrayList<TextWord> wds = new ArrayList<TextWord>();
				TextWord wd = new TextWord();

				for (TextChar[] sp: ln) {
					for (TextChar tc: sp) {
						if (tc.c != ' ') {
							wd.Add(tc);
						} else if (wd.w.length() > 0) {
							wds.add(wd);
							wd = new TextWord();
						}
					}
				}

				if (wd.w.length() > 0)
					wds.add(wd);

				if (wds.size() > 0)
					lns.add(wds.toArray(new TextWord[wds.size()]));
			}
		}

		return lns.toArray(new TextWord[lns.size()][]);
	}

	public synchronized boolean hasOutline() {
		return hasOutlineInternal();
	}

	public synchronized OutlineItem [] getOutline() {
		return getOutlineInternal();
	}

	public synchronized boolean needsPassword() {
		return needsPasswordInternal();
	}

	public synchronized boolean authenticatePassword(String password) {
		return authenticatePasswordInternal(password);
	}

	public synchronized boolean hasChanges() {
		return hasChangesInternal();
	}

	public synchronized void save() {
		saveInternal();
	}
}
