"use strict";

function initMuPDF() {
	let worker = new Worker("mupdf-worker.js");

	worker.onmessage = function (event) {
		worker.promises = {};
		worker.promiseId = 0;
		worker.onmessage = function (event) {
			let [ type, id, result ] = event.data;
			if (type === "RESULT")
				worker.promises[id].resolve(result);
			else
				worker.promises[id].reject(result);
			delete worker.promises[id];
		}
		main();
	}

	function wrap(func) {
		return function(...args) {
			return new Promise(function (resolve, reject) {
				let id = worker.promiseId++;
				worker.promises[id] = { resolve: resolve, reject: reject };
				if (args[0] instanceof ArrayBuffer)
					worker.postMessage([func, args, id], [args[0]]);
				else
					worker.postMessage([func, args, id]);
			});
		}
	}

	return {
		openDocument: wrap("openDocument"),
		freeDocument: wrap("freeDocument"),
		documentTitle: wrap("documentTitle"),
		documentOutline: wrap("documentOutline"),
		countPages: wrap("countPages"),
		pageSizes: wrap("pageSizes"),
		pageWidth: wrap("pageWidth"),
		pageHeight: wrap("pageHeight"),
		pageLinks: wrap("pageLinks"),
		drawPageAsPNG: wrap("drawPageAsPNG"),
		drawPageAsHTML: wrap("drawPageAsHTML"),
		terminate: function () { worker.terminate(); }
	}
}

let mupdf = initMuPDF();
