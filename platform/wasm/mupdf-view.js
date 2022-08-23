// Copyright (C) 2004-2022 Artifex Software, Inc.
//
// This file is part of MuPDF.
//
// MuPDF is free software: you can redistribute it and/or modify it under the
// terms of the GNU Affero General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// MuPDF is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
// details.
//
// You should have received a copy of the GNU Affero General Public License
// along with MuPDF. If not, see <https://www.gnu.org/licenses/agpl-3.0.en.html>
//
// Alternative licensing terms are available from the licensor.
// For commercial licensing, see <https://www.artifex.com/> or contact
// Artifex Software, Inc., 1305 Grant Avenue - Suite 200, Novato,
// CA 94945, U.S.A., +1(415)492-9861, for further information.

"use strict";

var mupdfView = {};

const worker = new Worker("mupdf-view-worker.js");
// TODO - use Map
const messagePromises = {};
let lastPromiseId = 0;

// eslint-disable-next-line no-unused-vars
mupdfView.ready = new Promise((resolve, reject) => {
	worker.onmessage = function (event) {
		if (event.data[0] !== "READY") {
			reject(new Error(`Unexpected first message: ${event.data}`));
		} else {
			worker.onmessage = onWorkerMessage;
			resolve();
		}
	};
});

function onWorkerMessage(event) {
	let [ type, id, result ] = event.data;
	if (type === "RESULT")
		messagePromises[id].resolve(result);
	else if (type === "RENDER")
		mupdfView.onRender(result.pageNumber, result.png);
	else if (type === "READY")
		messagePromises[id].reject(new Error("Unexpected READY message"));
	else if (type === "ERROR") {
		let error = new Error(result.message);
		error.name = result.name;
		error.stack = result.stack;
		messagePromises[id].reject(error);
	}
	else
		messagePromises[id].reject(new Error(`Unexpected result type '${type}'`));
	delete messagePromises[id];
}


function wrap(func) {
	return function(...args) {
		return new Promise(function (resolve, reject) {
			let id = lastPromiseId++;
			messagePromises[id] = { resolve, reject };
			if (args[0] instanceof ArrayBuffer)
				worker.postMessage([func, id, args], [args[0]]);
			else
				worker.postMessage([func, id, args]);
		});
	};
}

const wrap_openStreamFromUrl = wrap("openStreamFromUrl");
const wrap_openDocumentFromStream = wrap("openDocumentFromStream");

mupdfView.openDocumentFromUrl = async function (url, contentLength, progressive, prefetch, magic) {
	await wrap_openStreamFromUrl(url, contentLength, progressive, prefetch);
	return await wrap_openDocumentFromStream(magic);
};

mupdfView.openDocumentFromBuffer = wrap("openDocumentFromBuffer");
mupdfView.freeDocument = wrap("freeDocument");

mupdfView.documentTitle = wrap("documentTitle");
mupdfView.documentOutline = wrap("documentOutline");
mupdfView.countPages = wrap("countPages");
mupdfView.getPageSizes = wrap("getPageSizes");
mupdfView.getPageWidth = wrap("getPageWidth");
mupdfView.getPageHeight = wrap("getPageHeight");
mupdfView.getPageLinks = wrap("getPageLinks");
mupdfView.getPageText = wrap("getPageText");
mupdfView.search = wrap("search");
mupdfView.drawPageAsPNG = wrap("drawPageAsPNG");

mupdfView.mouseDownOnPage = wrap("mouseDownOnPage");
mupdfView.mouseDragOnPage = wrap("mouseDragOnPage");
mupdfView.mouseMoveOnPage = wrap("mouseMoveOnPage");
mupdfView.mouseUpOnPage = wrap("mouseUpOnPage");
mupdfView.setEditionTool = wrap("setEditionTool");

mupdfView.onRender = () => {};

mupdfView.terminate = function () { worker.terminate(); };
