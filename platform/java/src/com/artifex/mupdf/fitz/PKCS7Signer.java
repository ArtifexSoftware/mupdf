package com.artifex.mupdf.fitz;

import java.nio.ByteBuffer;

public abstract class PKCS7Signer
{
	static {
		Context.init();
	}

	private long pointer;

	private native boolean create(ByteBuffer transferBuffer);

	/* Begin the signing process */
	public boolean createSigner(ByteBuffer transferBuffer)
	{
		buffer = transferBuffer;
		return create(buffer);
	}

	/* Implementation of interface required by mupdf's pdf_pkcs7_signer	 */

	/* Called to get the signers designated name */
	public abstract PKCS7DesignatedName name();

	// The signing flow should be as follows:
	//  - The caller creates a PKCS7Signer-derived object implementing the
	//    begin, data and sign methods.
	//  - The caller calls the 'createSigner' method passing a ByteBuffer
	//    to be used to transfer the potential large content data in chunks
	//    to the signer
	//  - The caller calls the PDFWidget.sign() method, passing the signer object.
	//  - The mupdf core then sends the PDF content to be signed using
	//    the following approach:
	//       pkcs7signer.begin()
	//       while(content remaining)
	//           copy next chunk of content to transferBuffer
	//           pkcs7signer.data(transferBuffer)
	//       digest = pkcs7signer.sign()
	//  The caller should implement the sign() method using the required certificate store
	//  and content signing algorithms, returning a ByteBuffer containing the signing digest.

	// Allow the caller to prepare to receive the document content to be signed.
	// This method should be overridden to prepare to receive the data to be signed,
	// for example allocating any required buffers or creating a stream to aggregate the
	// content received in the data() method, initialise certificate store access etc.
	public abstract void begin();

	// Handle a chunk of data from the content to be signed.
	// This method may be called multiple times by the mupdf core.
	// This method should be overridden by the caller and should append
	// the buffer to the existing data being aggregated.
	public abstract void data(ByteBuffer buffer, int numBytes);

	// Announce the end of the data and request signing of the content
	// This method should be overriden and should use the appropriate certificate store
	// and PKCS7 signing algorithms to sign the aggregated content and return a digest.
	public abstract ByteBuffer sign();

	// Returns a value equal to at least the number of bytes required to store the signing digest.
	// This should be based on the chosen signing certificate (and any associated auxiliary
	// certificates required)
	public abstract int maxDigest();

	// PRIVATE implementation detail

	/* private transfer buffer for data aggregation */
	private ByteBuffer buffer;
}
