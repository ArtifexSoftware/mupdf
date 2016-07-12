package com.artifex.mupdf.fitz;

public class PDFDocument
{
	static {
		Context.init();
	}

	private long pointer;

	protected native void finalize();

	public void destroy() {
		finalize();
		pointer = 0;
	}

	private PDFDocument(long p) {
		pointer = p;
	}

	public native Document toDocument();

	public native int countPages();
	public native PDFObject findPage(int at);

	public native PDFObject getTrailer();
	public native int countObjects();

	public native PDFObject newNull();
	public native PDFObject newBoolean(boolean b);
	public native PDFObject newInteger(int i);
	public native PDFObject newReal(float f);
	public native PDFObject newString(String s);
	public native PDFObject newName(String name);
	public native PDFObject newIndirect(int num, int gen);
	public native PDFObject newArray();
	public native PDFObject newDictionary();

	public native PDFObject addObject(PDFObject obj);
	public native PDFObject createObject();
	public native void deleteObject(int i);

	public native PDFObject addStream(Buffer buf);

	public native PDFObject addPage(Rect mediabox, int rotate, PDFObject resources, Buffer contents);
	public native void insertPage(int at, PDFObject page);
	public native void deletePage(int at);
	public native PDFObject addImage(Image image);
	public native PDFObject addSimpleFont(Font font);
	public native PDFObject addFont(Font font);
	public native void save(String filename, String options);

	public void deleteObject(PDFObject obj) {
		deleteObject(obj.toIndirect());
	}
}
