package com.artifex.mupdf.fitz;

public class PDFObject
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

	private PDFObject(long p) {
		pointer = p;
	}

	public native boolean isIndirect();
	public native boolean isNull();
	public native boolean isBoolean();
	public native boolean isInteger();
	public native boolean isReal();
	public native boolean isNumber();
	public native boolean isString();
	public native boolean isName();
	public native boolean isArray();
	public native boolean isDictionary();
	public native boolean isStream();

	public native boolean toBoolean();
	public native int toInteger();
	public native float toFloat();
	public native byte[] toByteString();
	public native int toIndirect();
	public native String toString(boolean tight);

	public String toString() {
		return toString(false);
	}

	public native PDFObject resolve();

	public native byte[] readStream();
	public native byte[] readRawStream();

	public native PDFObject getArray(int index);
	public native PDFObject getDictionary(String name);

	public PDFObject get(int index) {
		return getArray(index);
	}

	public PDFObject get(String name) {
		return getDictionary(name);
	}

	public native void putArrayBoolean(int index, boolean b);
	public native void putArrayInteger(int index, int i);
	public native void putArrayFloat(int index, float f);
	public native void putArrayString(int index, String str);
	public native void putArrayPDFObject(int index, PDFObject obj);

	public native void putDictionaryStringBoolean(String name, boolean b);
	public native void putDictionaryStringInteger(String name, int i);
	public native void putDictionaryStringFloat(String name, float f);
	public native void putDictionaryStringString(String name, String str);
	public native void putDictionaryStringPDFObject(String name, PDFObject obj);

	public native void putDictionaryPDFObjectBoolean(PDFObject name, boolean b);
	public native void putDictionaryPDFObjectInteger(PDFObject name, int i);
	public native void putDictionaryPDFObjectFloat(PDFObject name, float f);
	public native void putDictionaryPDFObjectString(PDFObject name, String str);
	public native void putDictionaryPDFObjectPDFObject(PDFObject name, PDFObject obj);


	public void put(int index, boolean b) {
		putArrayBoolean(index, b);
	}

	public void put(int index, int i) {
		putArrayInteger(index, i);
	}

	public void put(int index, float f) {
		putArrayFloat(index, f);
	}

	public void put(int index, String s) {
		putArrayString(index, s);
	}

	public void put(int index, PDFObject obj) {
		putArrayPDFObject(index, obj);
	}

	public void put(String name, boolean b) {
		putDictionaryStringBoolean(name, b);
	}

	public void put(String name, int i) {
		putDictionaryStringInteger(name, i);
	}

	public void put(String name, float f) {
		putDictionaryStringFloat(name, f);
	}

	public void put(String name, String str) {
		putDictionaryStringString(name, str);
	}

	public void put(String name, PDFObject obj) {
		putDictionaryStringPDFObject(name, obj);
	}

	public void put(PDFObject name, boolean b) {
		putDictionaryPDFObjectBoolean(name, b);
	}

	public void put(PDFObject name, int i) {
		putDictionaryPDFObjectInteger(name, i);
	}

	public void put(PDFObject name, float f) {
		putDictionaryPDFObjectFloat(name, f);
	}

	public void put(PDFObject name, String str) {
		putDictionaryPDFObjectString(name, str);
	}

	public void put(PDFObject name, PDFObject obj) {
		putDictionaryPDFObjectPDFObject(name, obj);
	}

	public native void deleteArray(int index);
	public native void deleteDictionaryString(String name);
	public native void deleteDictionaryPDFObject(PDFObject name);

	public void delete(int index) {
		deleteArray(index);
	}

	public void delete(String name) {
		deleteDictionaryString(name);
	}

	public void delete(PDFObject name) {
		deleteDictionaryPDFObject(name);
	}
}
