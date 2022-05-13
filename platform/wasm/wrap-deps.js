// The content of this file is added at the beginning of libmupdf.js when the
// project is linked.
//
// JS functions and classes shoud be added to this file to be available from C code.

class MupdfError extends Error {
	constructor(message) {
	  super(message);
	  this.name = "MupdfError";
	}
}

class MupdfTryLaterError extends MupdfError {
	constructor(message) {
	  super(message);
	  this.name = "MupdfTryLaterError";
	}
}
