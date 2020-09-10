"use strict";

// Import the WASM module
importScripts("libmupdf.js");

let mupdf = {};
let ready = false;

Module.onRuntimeInitialized = function () {
	Module.ccall('initContext');
	mupdf.openDocumentFromBuffer = Module.cwrap('openDocumentFromBuffer', 'number', ['string', 'number', 'number']);
	mupdf.freeDocument = Module.cwrap('freeDocument', 'null', ['number']);
	mupdf.documentTitle = Module.cwrap('documentTitle', 'string', ['number']);
	mupdf.countPages = Module.cwrap('countPages', 'number', ['number']);
	mupdf.pageWidth = Module.cwrap('pageWidth', 'number', ['number', 'number', 'number']);
	mupdf.pageHeight = Module.cwrap('pageHeight', 'number', ['number', 'number', 'number']);
	mupdf.drawPageAsPNG = Module.cwrap('drawPageAsPNG', 'string', ['number', 'number', 'number']);
	mupdf.pageLinksJSON = Module.cwrap('pageLinks', 'string', ['number', 'number', 'number']);
	mupdf.pageTextJSON = Module.cwrap('pageText', 'string', ['number', 'number', 'number']);
	mupdf.loadOutline = Module.cwrap('loadOutline', 'number', ['number']);
	mupdf.freeOutline = Module.cwrap('freeOutline', null, ['number']);
	mupdf.outlineTitle = Module.cwrap('outlineTitle', 'string', ['number']);
	mupdf.outlinePage = Module.cwrap('outlinePage', 'number', ['number']);
	mupdf.outlineDown = Module.cwrap('outlineDown', 'number', ['number']);
	mupdf.outlineNext = Module.cwrap('outlineNext', 'number', ['number']);
	postMessage("READY");
	ready = true;
};

mupdf.openDocument = function (data, magic) {
	let n = data.byteLength;
	let ptr = Module._malloc(n);
	let src = new Uint8Array(data);
	Module.HEAPU8.set(src, ptr);
	return mupdf.openDocumentFromBuffer(magic, ptr, n);
}

mupdf.documentOutline = function (doc) {
	function makeOutline(node) {
		let list = [];
		while (node) {
			let entry = {
				title: mupdf.outlineTitle(node),
				page: mupdf.outlinePage(node),
			}
			let down = mupdf.outlineDown(node);
			if (down)
				entry.down = makeOutline(down);
			list.push(entry);
			node = mupdf.outlineNext(node);
		}
		return list;
	}
	let root = mupdf.loadOutline(doc);
	if (root) {
		let list = null;
		try {
			list = makeOutline(root);
		} finally {
			mupdf.freeOutline(root);
		}
		return list;
	}
	return null;
}

mupdf.pageSizes = function (doc, dpi) {
	let list = [];
	let n = mupdf.countPages(doc);
	for (let i = 1; i <= n; ++i) {
		let w = mupdf.pageWidth(doc, i, dpi);
		let h = mupdf.pageHeight(doc, i, dpi);
		list[i] = [w, h];
	}
	return list;
}

mupdf.pageLinks = function (doc, page, dpi) {
	return JSON.parse(mupdf.pageLinksJSON(doc, page, dpi));
}

mupdf.pageText = function (doc, page, dpi) {
	return JSON.parse(mupdf.pageTextJSON(doc, page, dpi));
}

onmessage = function (event) {
	let [ func, args, id ] = event.data;
	if (!ready) {
		postMessage(["ERROR", id, {name: "NotReadyError", message: "WASM module is not ready yet"}]);
		return;
	}
	try {
		let result = mupdf[func](...args);
		if (result instanceof ArrayBuffer)
			postMessage(["RESULT", id, result], [result]);
		else
			postMessage(["RESULT", id, result]);
	} catch (error) {
		console.log(error);
		postMessage(["ERROR", id, {name: error.name, message: error.message}]);
	}
}
