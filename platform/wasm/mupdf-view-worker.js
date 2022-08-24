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

/*global mupdf */

"use strict";

// Import the WASM module
importScripts("libmupdf.js");
importScripts("lib/mupdf.js");

mupdf.ready.then(() => {
	postMessage(["READY"]);
});

onmessage = async function (event) {
	let [ func, id, args ] = event.data;
	await mupdf.ready;

	try {
		if (func == "drawPageAsPNG") {
			drawPageAsPNG(id, ...args);
			return;
		}

		let result = workerMethods[func](...args);
		postMessage(["RESULT", id, result]);
	} catch (error) {
		if (error instanceof mupdf.MupdfTryLaterError) {
			trylaterQueue.push(event);
		} else {
			postMessage(["ERROR", id, {name: error.name, message: error.message, stack: error.stack}]);
		}
	}
};

let trylaterScheduled = false;
let trylaterQueue = [];
mupdf.onFetchCompleted = function (_id) {
	if (!trylaterScheduled) {
		trylaterScheduled = true;

		setTimeout(() => {
			trylaterScheduled = false;
			let currentQueue = trylaterQueue;
			trylaterQueue = [];
			currentQueue.forEach(onmessage);
		}, 0);
	}
};

const workerMethods = {};

let openStream = null;
let openDocument = null;

workerMethods.openStreamFromUrl = function (url, contentLength, progressive, prefetch) {
	openStream = mupdf.Stream.fromUrl(url, contentLength, Math.max(progressive << 10, 1 << 16), prefetch);
	// TODO - close stream?
};

workerMethods.openDocumentFromBuffer = function (buffer, magic) {
	// TODO - check types
	openDocument = mupdf.Document.openFromJsBuffer(buffer, magic);
};

workerMethods.openDocumentFromStream = function (magic) {
	if (openStream == null) {
		throw new Error("openDocumentFromStream called but no stream has been open");
	}
	openDocument = mupdf.Document.openFromStream(openStream, magic);
};

workerMethods.freeDocument = function () {
	openDocument?.free();
	openDocument = null;
};

workerMethods.documentTitle = function () {
	return openDocument.title();
};

workerMethods.documentOutline = function () {
	const root = openDocument.loadOutline();

	if (root == null)
		return null;

	function makeOutline(node) {
		let list = [];
		while (node) {
			let entry = {
				title: node.title(),
				page: node.pageNumber(openDocument),
			};
			let down = node.down();
			if (down)
				entry.down = makeOutline(down);
			list.push(entry);
			node = node.next();
		}
		return list;
	}

	try {
		return makeOutline(root);
	} finally {
		root.free();
	}
};

workerMethods.countPages = function() {
	return openDocument.countPages();
};

// TODO - use hungarian notation for coord spaces
// TODO - currently this loads every single page. Not very efficient?
workerMethods.getPageSizes = function (dpi) {
	let list = [];
	let n = openDocument.countPages();
	for (let i = 0; i < n; ++i) {
		let page;
		try {
			page = openDocument.loadPage(i);
			let width = page.width() * dpi / 72;
			let height = page.height() * dpi / 72;
			list.push({width, height});
		}
		finally {
			page.free();
		}
	}
	return list;
};

// TODO - document the "- 1" better
// TODO - keep page loaded?
workerMethods.getPageWidth = function (pageNumber, dpi) {
	let page = openDocument.loadPage(pageNumber - 1);
	return page.width() * dpi / 72;
};

workerMethods.getPageHeight = function (pageNumber, dpi) {
	let page = openDocument.loadPage(pageNumber - 1);
	return page.height() * dpi / 72;
};

workerMethods.getPageLinks = function(pageNumber, dpi) {
	const doc_to_screen = mupdf.Matrix.scale(dpi / 72, dpi / 72);
	let page;
	let links_ptr;

	try {
		page = openDocument.loadPage(pageNumber - 1);
		links_ptr = page.loadLinks();

		return links_ptr.links.map(link => {
			const { x0, y0, x1, y1 } = doc_to_screen.transformRect(link.rect());

			let href;
			if (link.isExternalLink()) {
				href = link.uri();
			} else {
				const linkPageNumber = link.resolve(openDocument).pageNumber(openDocument);
				// TODO - document the "+ 1" better
				href = `#page${linkPageNumber + 1}`;
			}

			return {
				x: x0,
				y: y0,
				w: x1 - x0,
				h: y1 - y0,
				href
			};
		});
	}
	finally {
		page?.free();
		links_ptr?.free();
	}
};

workerMethods.getPageText = function(pageNumber, dpi) {
	let page;
	let stextPage;

	let buffer;
	let output;

	try {
		page = openDocument.loadPage(pageNumber - 1);
		stextPage = page.toSTextPage();

		buffer = mupdf.Buffer.empty();
		output = mupdf.Output.withBuffer(buffer);

		stextPage.printAsJson(output, dpi / 72);
		output.close();

		let text = buffer.toJsString();
		return JSON.parse(text);
	}
	finally {
		output?.free();
		buffer?.free();
		stextPage?.free();
		page?.free();
	}
};

workerMethods.search = function(pageNumber, dpi, needle) {
	let page;

	try {
		page = openDocument.loadPage(pageNumber - 1);
		const doc_to_screen = mupdf.Matrix.scale(dpi / 72, dpi / 72);
		const hits = page.search(needle);
		return hits.map(searchHit => {
			const  { x0, y0, x1, y1 } = doc_to_screen.transformRect(searchHit);

			return {
				x: x0,
				y: y0,
				w: x1 - x0,
				h: y1 - y0,
			};
		});
	}
	finally {
		page?.free();
	}
};

workerMethods.getPageAnnotations = function(pageNumber, dpi) {
	let pdfPage;

	try {
		pdfPage = openDocument.loadPage(pageNumber - 1);

		if (pdfPage == null) {
			return [];
		}

		const annotations = pdfPage.annotations();
		const doc_to_screen = mupdf.Matrix.scale(dpi / 72, dpi / 72);

		return annotations.annotations.map(annotation => {
			const { x0, y0, x1, y1 } = doc_to_screen.transformRect(annotation.bounds());

			return {
				x: x0,
				y: y0,
				w: x1 - x0,
				h: y1 - y0,
				type: annotation.annotType(),
				ref: annotation.pointer,
			};
		});
	}
	finally {
		pdfPage?.free();
	}
};

let currentTool = null;
let currentSelection = null;

// TODO - Use mupdf instead
// TODO - Use Map
const pageWasRendered = {};
function drawPageAsPNG(id, pageNumber, dpi) {
	if (pageWasRendered[pageNumber]) {
		return;
	}

	const doc_to_screen = mupdf.Matrix.scale(dpi / 72, dpi / 72);
	let page;
	let pixmap;

	// TODO - draw annotations
	// TODO - use canvas?

	try {
		page = openDocument.loadPage(pageNumber - 1);
		pixmap = page.toPixmap(doc_to_screen, mupdf.DeviceRGB, false);

		// TODO - draw points on hover/select
		let points = currentTool?.points ?? [];
		for (let point of points) {
			pixmap.drawGrabHandle(point.x * dpi / 72, point.y * dpi / 72);
		}

		let png = pixmap.toPNG();

		postMessage(["RENDER", id, { pageNumber, png }]);
		pageWasRendered[pageNumber] = true;
	}
	finally {
		pixmap?.free();
		page?.free();
	}
}

workerMethods.mouseDownOnPage = function(pageNumber, dpi, x, y) {
	let pdfPage = openDocument.loadPage(pageNumber - 1);

	if (pdfPage == null) {
		return;
	}

	// transform mouse pos from screen coordinates to document coordinates.
	x = x / (dpi / 72);
	y = y / (dpi / 72);

	if (currentTool != null) {
		let newAnnot = currentTool.mouseDown(pdfPage, x, y);
		if (newAnnot) {
			currentTool = null;
			//currentSelection = newAnnot;
		}
		pageWasRendered[pageNumber] = false;
		return true;
	}

	// TODO - multi-selection
	// TODO - differentiate between hovered, selected, held

	const clickedAnnotation = pdfPage.annotations().annotations.find(annotation => {
		const bbox = annotation.bound();
		return (x >= bbox.x0 && x <= bbox.x1 && y >= bbox.y0 && y <= bbox.y1);
	});
	if (clickedAnnotation != null) {
		currentSelection = new SelectedAnnotation(pdfPage, clickedAnnotation, clickedAnnotation.bound(), x, y);
		pageWasRendered[pageNumber] = false;
		return true;
	}

	return false;
};

// TODO - handle crossing pages
workerMethods.mouseDragOnPage = function(pageNumber, dpi, x, y) {
	// transform mouse pos from screen coordinates to document coordinates.
	x = x / (dpi / 72);
	y = y / (dpi / 72);

	let wasChanged = currentSelection?.mouseDrag(x, y) ?? false;
	pageWasRendered[pageNumber] = !wasChanged;
	return wasChanged;
};

// eslint-disable-next-line no-unused-vars
workerMethods.mouseMoveOnPage = function(pageNumber, dpi, x, y) {
	return false;
};

workerMethods.mouseUpOnPage = function(pageNumber, dpi, x, y) {
	// transform mouse pos from screen coordinates to document coordinates.
	x = x / (dpi / 72);
	y = y / (dpi / 72);

	try {
		let wasChanged = currentSelection?.mouseUp(x, y) ?? false;
		pageWasRendered[pageNumber] = !wasChanged;
		return wasChanged;
	}
	finally {
		currentSelection = null;
	}
};

class SelectedAnnotation {
	constructor(pdfPage, annotation, startRect, mouse_x, mouse_y) {
		this.pdfPage = pdfPage;
		this.annotation = annotation;
		this.startRect = startRect;
		this.currentRect = startRect;
		this.initial_x = mouse_x;
		this.initial_y = mouse_y;
	}

	mouseDrag(x, y) {
		this.currentRect = this.startRect.translated(x - this.initial_x, y - this.initial_y);
		this.annotation.rect();
		// TODO - setRect doesn't quite do what we want
		this.annotation.setRect(this.currentRect);
		return true;
	}

	mouseUp(x, y) {
		this.currentRect = this.startRect.translated(x - this.initial_x, y - this.initial_y);
		// TODO - setRect doesn't quite do what we want
		this.annotation.setRect(this.currentRect);
		this.pdfPage.free();
		return true;
	}
}

function inSquare(squarePoint, x, y) {
	return (
		x >= squarePoint.x - 5 &&
		x < squarePoint.x + 5 &&
		y >= squarePoint.y - 5 &&
		y < squarePoint.y + 5
	);
}

class CreateText {
	constructor() {}

	mouseDown(pdfPage, x, y) {
		let annot = pdfPage.createAnnot(mupdf.PDF_ANNOT_TEXT);
		annot.setRect(new mupdf.Rect(x, y, x + 20, y + 20));
		//pdf_annot_icon_name
		pdfPage.update();
		return annot;
	}

	mouseDrag(_x, _y) {
		// move last point
	}

	mouseMove(_x, _y) {
		// update hovered
	}

	mouseUp(_x, _y) {
		// do nothing
	}
}

// TODO - CreateLink

class CreateFreeText {
	constructor() {}

	mouseDown(pdfPage, x, y) {
		let annot = pdfPage.createAnnot(mupdf.PDF_ANNOT_FREE_TEXT);
		annot.setRect(new mupdf.Rect(x, y, x + 200, y + 100));
		pdfPage.update();
		return annot;
	}

	mouseDrag(_x, _y) {
		// move last point
	}

	mouseMove(_x, _y) {
		// update hovered
	}

	mouseUp(_x, _y) {
		// do nothing
	}
}

class CreateLine {
	constructor() {
		this.points = [];
	}

	mouseDown(pdfPage, x, y) {
		this.points.push(new mupdf.Point(x, y));

		if (this.points.length == 2) {
			let annot = pdfPage.createAnnot(mupdf.PDF_ANNOT_LINE);
			annot.setLine(this.points[0], this.points[1]);
			// pdf_set_annot_interior_color
			// pdf_set_annot_line_ending_styles
			pdfPage.update();
			return annot;
		}

		return null;
	}

	mouseDrag(_x, _y) {
		// move last point
	}

	mouseMove(_x, _y) {
		// update hovered
	}

	mouseUp(_x, _y) {
		// do nothing
	}
}

class CreateSquare {
	constructor() {
		this.points = [];
	}

	mouseDown(pdfPage, x, y) {
		this.points.push(new mupdf.Point(x, y));

		if (this.points.length == 2) {
			let annot = pdfPage.createAnnot(mupdf.PDF_ANNOT_SQUARE);
			annot.setRect(new mupdf.Rect(this.points[0].x, this.points[0].y, this.points[1].x, this.points[1].y));
			// pdf_set_annot_interior_color
			pdfPage.update();
			return annot;
		}

		return null;
	}

	mouseDrag(_x, _y) {
		// move last point
	}

	mouseMove(_x, _y) {
		// update hovered
	}

	mouseUp(_x, _y) {
		// do nothing
	}
}

class CreateCircle {
	constructor() {
		this.points = [];
	}

	mouseDown(pdfPage, x, y) {
		this.points.push(new mupdf.Point(x, y));

		if (this.points.length == 2) {
			let annot = pdfPage.createAnnot(mupdf.PDF_ANNOT_CIRCLE);
			annot.setRect(new mupdf.Rect(this.points[0].x, this.points[0].y, this.points[1].x, this.points[1].y));
			// pdf_set_annot_interior_color
			pdfPage.update();
			return annot;
		}

		return null;
	}

	mouseDrag(_x, _y) {
		// move last point
	}

	mouseMove(_x, _y) {
		// update hovered
	}

	mouseUp(_x, _y) {
		// do nothing
	}
}

class CreatePolygon {
	constructor() {
		this.points = [];
	}

	mouseDown(pdfPage, x, y) {
		if (this.points[0] != null && inSquare(this.points[0], x, y)) {
			let annot = pdfPage.createAnnot(mupdf.PDF_ANNOT_POLYGON);
			for (const point of this.points) {
				annot.addVertex(point);
			}
			pdfPage.update();
			//pdf_annot_interior_color
			//pdf_annot_line_ending_styles
			return annot;
		}

		this.points.push(new mupdf.Point(x, y));
		return false;
	}

	mouseDrag(_x, _y) {
		// move last point
	}

	mouseMove(_x, _y) {
		// update hovered
	}

	mouseUp(_x, _y) {
		// do nothing
	}
}

class CreatePolyLine {
	constructor() {
		this.points = [];
	}

	mouseDown(pdfPage, x, y) {
		if (this.points[0] != null && inSquare(this.points[0], x, y)) {
			let annot = pdfPage.createAnnot(mupdf.PDF_ANNOT_POLYLINE);
			for (const point of this.points) {
				annot.addVertex(point);
			}
			pdfPage.update();
			//pdf_annot_interior_color
			//pdf_annot_line_ending_styles
			return annot;
		}

		this.points.push(new mupdf.Point(x, y));
		return false;
	}

	mouseDrag(_x, _y) {
		// move last point
	}

	mouseMove(_x, _y) {
		// update hovered
	}

	mouseUp(_x, _y) {
		// do nothing
	}
}

class CreateStamp {
	constructor() {}

	mouseDown(pdfPage, x, y) {
		let annot = pdfPage.createAnnot(mupdf.PDF_ANNOT_STAMP);
		annot.setRect(new mupdf.Rect(x, y, x + 190, y + 50));
		//pdf_annot_icon_name
		pdfPage.update();
		return annot;
	}

	mouseDrag(_x, _y) {
		// move last point
	}

	mouseMove(_x, _y) {
		// update hovered
	}

	mouseUp(_x, _y) {
		// do nothing
	}
}

class CreateCaret {
	constructor() {}

	mouseDown(pdfPage, x, y) {
		let annot = pdfPage.createAnnot(mupdf.PDF_ANNOT_CARET);
		annot.setRect(new mupdf.Rect(x, y, x + 18, y + 15));
		pdfPage.update();
		return annot;
	}

	mouseDrag(_x, _y) {
		// move last point
	}

	mouseMove(_x, _y) {
		// update hovered
	}

	mouseUp(_x, _y) {
		// do nothing
	}
}


class CreateFileAttachment {
	constructor() {}

	mouseDown(pdfPage, x, y) {
		let annot = pdfPage.createAnnot(mupdf.PDF_ANNOT_FILE_ATTACHMENT);
		annot.setRect(new mupdf.Rect(x, y, x + 20, y + 20));
		//pdf_annot_icon_name
		//pdf_annot_filespec
		pdfPage.update();
		return annot;
	}

	mouseDrag(_x, _y) {
		// move last point
	}

	mouseMove(_x, _y) {
		// update hovered
	}

	mouseUp(_x, _y) {
		// do nothing
	}
}

class CreateSound {
	constructor() {}

	mouseDown(pdfPage, x, y) {
		let annot = pdfPage.createAnnot(mupdf.PDF_ANNOT_SOUND);
		annot.setRect(new mupdf.Rect(x, y, x + 20, y + 20));
		//pdf_annot_icon_name
		pdfPage.update();
		return annot;
	}

	mouseDrag(_x, _y) {
		// move last point
	}

	mouseMove(_x, _y) {
		// update hovered
	}

	mouseUp(_x, _y) {
		// do nothing
	}
}

// TODO - Use Map
const editionTools = {
	CreateText,
	CreateFreeText,
	CreateLine,
	CreateSquare,
	CreateCircle,
	CreatePolygon,
	CreatePolyLine,
	CreateStamp,
	CreateCaret,
	CreateFileAttachment,
	CreateSound,
};

workerMethods.setEditionTool = function(toolName) {
	// TODO - warn if missing
	currentTool = new (editionTools[toolName]);
	console.log("new tool:", toolName, " - ", currentTool);
};
