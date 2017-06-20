package com.artifex.mupdf.fitz;

public class Separations
{
	private long pointer;

	protected native void finalize();

	public void destroy() {
		finalize();
		pointer = 0;
	}

	protected Separations(long p) {
		pointer = p;
	}

	public native int getNumberOfSeparations();

	public native Separation getSeparation(int separation);

	public native boolean areSeparationsControllable();

	public native boolean disableSeparation(int separation, boolean disable);

	public native boolean isSeparationDisabled(int separation);
}
