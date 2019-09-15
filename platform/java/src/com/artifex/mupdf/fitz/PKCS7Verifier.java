package com.artifex.mupdf.fitz;

import java.nio.ByteBuffer;
import java.util.Map;

public abstract class PKCS7Verifier
{
	// Define possible values for signature verification results
	public final static int PKCS7VerifierOK                = 0;
	public final static int PKCS7VerifierNoSignature       = 1;
	public final static int PKCS7VerifierNoCertificate     = 2;
	public final static int PKCS7VerifierDigestFailure     = 3;
	public final static int PKCS7VerifierSelfSigned        = 4;
	public final static int PKCS7VerifierSelfSignedInChain = 5;
	public final static int PKCS7VerifierNotTrusted        = 6;
	public final static int PKCS7VerifierUnknown           = -1;

	static {
		Context.init();
	}

	private long pointer;

	// native
	private native boolean create( ByteBuffer transferBuffer );


	// Begin the verification process. The transferBuffer parameter
	// should be allocated by the caller and should be a direct
	// ByteBuffer for best performance.
	public boolean createVerifier( ByteBuffer transferBuffer )
	{
		buffer = transferBuffer;
		return create( buffer );
	}

	// Implementation of methods required by mupdf signature verification

	// Get the signers designated name from the signature
	public abstract PKCS7DesignatedName name( ByteBuffer signature );

	// The verification flow should be as follows:
	//  - The caller creates a PKCS7Verifier-derived object implementing the
	//    begin, data and verify methods.
	//  - The caller calls the 'createVerifier' method passing a ByteBuffer
	//    to be used to transfer the potential large content data in chunks
	//    to the verifier
	//  - The caller calls the PDFWidget.verify() method, passing the newly
	//    created verifier object.
	//  - The mupdf core then sends the PDF content to be verified using
	//    the following approach:
	//       pkcs7verifier.begin()
	//       while( content remaining )
	//           copy next chunk of content to transferBuffer
	//           pkcs7verifier.data( transferBuffer )
	//       get the signature from the widget
	//       pkcs7verifier.verify( signature, signature_length, modified_since_signed )
	//  The caller should implement the verify() method using the required certificate store
	//  and content verification algorithms, presenting the results as required.

	// Allow the caller to prepare to receive the document content which is to be verified.
	// This method should be overridden to prepare to receive the data to be verified,
	// for example allocating any required buffers or creating a stream to aggregate the
	// content received in the data() method, initialise certificate store access etc.
	public abstract void begin();

	// Handle a chunk of data from the content to be verified.
	// This method may be called multiple times by the mupdf core.
	// This method should be overridden by the caller and should append
	// the buffer to the existing data being aggregated.
	public abstract void data( ByteBuffer buffer, int numBytes );

	// Announce the end of the data and request verification
	// This method should be overriden and should use the appropriate certificate store
	// and verification algorithms to verify the aggregated content using the
	// signature supplied.
	public abstract void verify( ByteBuffer signature, int signatureLen, int modified );

	// PRIVATE implementation detail

	/* private transfer buffer for data aggregation */
	private ByteBuffer buffer;
}
