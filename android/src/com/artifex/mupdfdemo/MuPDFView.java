package com.artifex.mupdfdemo;

import android.graphics.PointF;
import android.graphics.Rect;
import android.graphics.RectF;

public interface MuPDFView {
	public void setPage(int page, PointF size);
	public void setScale(float scale);
	public int getPage();
	public void blank(int page);
	public boolean passClickEvent(float x, float y);
	public LinkInfo hitLink(float x, float y);
	public void selectText(float x0, float y0, float x1, float y1);
	public void deselectText();
	public boolean copySelection();
	public void strikeOutSelection();
	public void setSearchBoxes(RectF searchBoxes[]);
	public void setLinkHighlighting(boolean f);
	public void setChangeReporter(Runnable reporter);
	public void update();
	public void addHq(boolean update);
	public void removeHq();
	public void releaseResources();
}
