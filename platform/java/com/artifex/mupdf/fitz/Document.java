package com.artifex.mupdf.fitz;

import java.lang.ref.WeakReference;

public class Document
{
	// Private data
	private long nativeDocument = 0;

	// Construction
	public Document(String filename) throws Exception
	{
		nativeDocument = newNative(filename);
		if (nativeDocument == 0)
			throw(new Exception("Failed to load Document"));
	}
	private native final long newNative(String filename);

	// FIXME: Should support opening java streams and from byte buffers etc.
	// Streams would need to be seekable.
	public Document(byte buffer[], String magic) throws Exception
	{
		nativeDocument = 0;//newFromBufferNative(buffer, magic);
		if (nativeDocument == 0)
			throw(new Exception("Failed to load Document"));
	}
	//private native final long newFromBufferNative(byte buffer[], String magic);

	//public Document(SeekableStream stream, String magic) throws Exception
	//{
	//	nativeDocument = newFromStreamNative(stream, magic);
	//	if (nativeDocument == 0)
	//		throw(new Exception("Failed to load Document"));
	//}
	//private native final long newFromBufferNative(SeekableStream stream, String magic);

	// Operation
	public native boolean needsPassword();

	public native boolean authenticatePassword(String password);

	public native int countPages();

	public native Page getPage(int n);

	public native String getFileFormat();

	public native boolean isUnencryptedPDF();

	public native Outline getOutline();

	// Destruction
	public void destroy()
	{
		finalize();
		nativeDocument = 0;
	}

	protected native void finalize();
}
