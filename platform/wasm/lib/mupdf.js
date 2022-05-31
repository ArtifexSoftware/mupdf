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

var mupdf = {};

mupdf.onInitialized = function () {
	throw new Error("MuPDF is initialized and ready to use");
};

// If running in Node.js environment
if (typeof require === "function") {
	var libmupdf = require("../libmupdf.js");
	if (typeof module === "object")
		module.exports = mupdf;
}

libmupdf().then(m => {
	libmupdf = m;

	console.log("WASM MODULE READY");

	libmupdf._wasm_init_context();

	mupdf.DeviceGray = new mupdf.ColorSpace(libmupdf._wasm_device_gray());
	mupdf.DeviceRGB = new mupdf.ColorSpace(libmupdf._wasm_device_rgb());
	mupdf.DeviceBGR = new mupdf.ColorSpace(libmupdf._wasm_device_bgr());
	mupdf.DeviceCMYK = new mupdf.ColorSpace(libmupdf._wasm_device_cmyk());

	// Call the user callback to let them know we're ready!
	mupdf.onInitialized();
});

mupdf._to_rect = function (ptr) {
	ptr = ptr >> 2;
	return [
		libmupdf.HEAPF32[ptr],
		libmupdf.HEAPF32[ptr+1],
		libmupdf.HEAPF32[ptr+2],
		libmupdf.HEAPF32[ptr+3],
	];
};

mupdf._to_irect = function (ptr) {
	ptr = ptr >> 2;
	return [
		libmupdf.HEAP32[ptr],
		libmupdf.HEAP32[ptr+1],
		libmupdf.HEAP32[ptr+2],
		libmupdf.HEAP32[ptr+3],
	];
};

mupdf._to_matrix = function (ptr) {
	ptr = ptr >> 2;
	return [
		libmupdf.HEAPF32[ptr],
		libmupdf.HEAPF32[ptr+1],
		libmupdf.HEAPF32[ptr+2],
		libmupdf.HEAPF32[ptr+3],
		libmupdf.HEAPF32[ptr+4],
		libmupdf.HEAPF32[ptr+5],
	];
};

// TODO - better handle matrices.
// TODO - write Rect and Matrix classes
mupdf.scale_matrix = function(scale_x, scale_y) {
	return mupdf._to_matrix(libmupdf._wasm_scale(scale_x, scale_y));
};

mupdf.transform_rect = function(rect, matrix) {
	return mupdf._to_rect(libmupdf._wasm_transform_rect(
		rect[0], rect[1], rect[2], rect[3],
		matrix[0], matrix[1], matrix[2], matrix[3], matrix[4], matrix[5],
	));
};

const finalizer = new FinalizationRegistry(callback => callback());

mupdf._Wrapper = class _Wrapper {
	constructor(pointer, dropFunction) {
		this.pointer = pointer;
		this.dropFunction = dropFunction;
		finalizer.register(this, () => dropFunction(pointer), this);
	}
	free() {
		finalizer.unregister(this);
		this.dropFunction(this.pointer);
		this.pointer = 0;
	}
	valueOf() {
		return this.pointer;
	}
	toString() {
		return `[${this.constructor.name} ${this.pointer}]`;
	}
};

mupdf.Document = class Document extends mupdf._Wrapper {
	constructor(data, magic) {
		let n = data.byteLength;
		let pointer = libmupdf._malloc(n);
		let src = new Uint8Array(data);
		libmupdf.HEAPU8.set(src, pointer);
		// TODO - remove ccall
		super(
			libmupdf.ccall(
				"wasm_open_document_with_buffer",
				"number",
				["number", "number", "string"],
				[pointer, n, magic]
			),
			libmupdf._wasm_drop_document
		);
	}

	countPages() {
		return libmupdf._wasm_count_pages(this.pointer);
	}

	loadPage(pageNumber) {
		// TODO - document "-1" better
		return new mupdf.Page(libmupdf._wasm_load_page(this.pointer, pageNumber - 1));
	}

	title() {
		// TODO - handle alloc
		return libmupdf.UTF8ToString(libmupdf._wasm_document_title(this.pointer));
	}

	loadOutline() {
		return new mupdf.Outline(libmupdf._wasm_load_outline(this.pointer));
	}
};

mupdf.Page = class Page extends mupdf._Wrapper {
	constructor(pointer) {
		super(pointer, libmupdf._wasm_drop_page);
	}

	bounds() {
		return mupdf._to_rect(libmupdf._wasm_bound_page(this.pointer));
	}
	toPixmap(m, colorspace, alpha) {
		return new mupdf.Pixmap(
			libmupdf._wasm_new_pixmap_from_page(
				this.pointer,
				m[0], m[1], m[2], m[3], m[4], m[5],
				colorspace,
				alpha
			)
		);
	}

	toSTextPage() {
		return new mupdf.STextPage(
			libmupdf._wasm_new_stext_page_from_page(this.pointer)
		);
	}

	toPdfPage() {
		const pointer = libmupdf._wasm_pdf_page_from_fz_page(this.pointer);
		if (pointer == 0)
			return null;
		else
			return new mupdf.PdfPage(pointer);
	}

	loadLinks() {
		let links = [];

		for (let link = libmupdf._wasm_load_links(this.pointer); link !== 0; link = libmupdf._wasm_next_link(link)) {
			links.push(new mupdf.Link(link));
		}

		return new mupdf.Links(links);
	}

	search(needle) {
		const MAX_HIT_COUNT = 500;
		let needle_ptr = 0;
		let hits_ptr = 0;

		try {
			// TODO - use fz_malloc instead
			hits_ptr = libmupdf._malloc(libmupdf._wasm_size_of_quad() * MAX_HIT_COUNT);

			// TODO - write conversion method
			let needle_size = libmupdf.lengthBytesUTF8(needle) + 1;
			needle_ptr = libmupdf._malloc(needle_size);
			libmupdf.stringToUTF8(needle, needle_ptr, needle_size);

			let hitCount = libmupdf._wasm_search_page(
				this.pointer, needle_ptr, hits_ptr, MAX_HIT_COUNT
			);

			let rects = [];
			for (let i = 0; i < hitCount; ++i) {
				let hit = hits_ptr + i * libmupdf._wasm_size_of_quad();
				let rect = mupdf._to_rect(libmupdf._wasm_rect_from_quad(hit));
				rects.push(rect);
			}

			return rects;
		}
		finally {
			libmupdf._free(needle_ptr);
			libmupdf._free(hits_ptr);
		}
	}
};

mupdf.Links = class Links extends mupdf._Wrapper {
	constructor(links) {
		// TODO drop
		super(links[0] || 0, () => {});
		this.links = links;
	}
};

mupdf.Link = class Link extends mupdf._Wrapper {
	constructor(pointer) {
		// TODO
		super(pointer, () => {});
	}

	rect() {
		return mupdf._to_rect(libmupdf._wasm_link_rect(this.pointer));
	}

	isExternalLink() {
		return libmupdf._wasm_is_external_link(this.pointer);
	}

	uri() {
		return libmupdf.UTF8ToString(libmupdf._wasm_link_uri(this.pointer));
	}

	resolve() {
		return new mupdf.Location(
			libmupdf._wasm_resolve_link_chapter(this.pointer),
			libmupdf._wasm_resolve_link_page(this.pointer),
		);
	}
};

mupdf.Location = class Location {
	constructor(chapter, page) {
		this.chapter = chapter;
		this.page = page;
	}

	pageNumber(document) {
		return libmupdf._wasm_page_number_from_location(document.pointer, this.chapter, this.page);
	}
};

function new_outline(pointer) {
	if (pointer === 0)
		return null;
	else
		return new mupdf.Outline(pointer);
}

// FIXME - This is pretty non-idiomatic
mupdf.Outline = class Outline extends mupdf._Wrapper {
	constructor(pointer) {
		// TODO
		super(pointer, () => {});
	}

	pageNumber(document) {
		return libmupdf._wasm_outline_page(document.pointer, this.pointer);
	}

	title() {
		return libmupdf.UTF8ToString(libmupdf._wasm_outline_title(this.pointer));
	}

	down() {
		return new_outline(libmupdf._wasm_outline_down(this.pointer));
	}

	next() {
		return new_outline(libmupdf._wasm_outline_next(this.pointer));
	}
};

mupdf.PdfPage = class PdfPage extends mupdf._Wrapper {
	constructor(pointer) {
		// TODO
		super(pointer, () => {});
	}

	annotations() {
		let annotations = [];

		for (let annot = libmupdf._wasm_pdf_first_annot(this.pointer); annot !== 0; annot = libmupdf._wasm_pdf_next_annot(annot)) {
			annotations.push(new mupdf.Annotation(annot));
		}

		return new mupdf.Annotations(annotations);
	}
};

mupdf.Annotations = class Annotations extends mupdf._Wrapper {
	constructor(annotations) {
		super(annotations[0] || 0, () => {});
		this.annotations = annotations;
	}
};

mupdf.Annotation = class Annotation extends mupdf._Wrapper {
	// TODO - the lifetime handling of this is actually complicated
	constructor(pointer) {
		super(pointer, () => {});
	}

	bounds() {
		return mupdf._to_rect(libmupdf._wasm_pdf_bound_annot(this.pointer));
	}

	annotType() {
		return libmupdf.UTF8ToString(libmupdf._wasm_pdf_annot_type_string(this.pointer));
	}
};

mupdf.ColorSpace = class ColorSpace extends mupdf._Wrapper {
	constructor(pointer) {
		super(pointer, libmupdf._wasm_drop_colorspace);
	}
};

mupdf.Pixmap = class Pixmap extends mupdf._Wrapper {
	constructor(pointer) {
		super(pointer, libmupdf._wasm_drop_pixmap);
		this.bbox = mupdf._to_irect(libmupdf._wasm_pixmap_bbox(this.pointer));
	}
	get width() {
		return this.bbox[2] - this.bbox[0];
	}
	get height() {
		return this.bbox[3] - this.bbox[1];
	}
	get samples() {
		let stride = libmupdf._wasm_pixmap_stride(this.pointer);
		let n = stride * this.height;
		let p = libmupdf._wasm_pixmap_samples(this.pointer);
		return libmupdf.HEAPU8.subarray(p, p + n);
	}
	toPNG() {
		let buf = libmupdf._wasm_new_buffer_from_pixmap_as_png(this.pointer);
		try {
			let data = libmupdf._wasm_buffer_data(buf);
			let size = libmupdf._wasm_buffer_size(buf);
			return libmupdf.HEAPU8.slice(data, data + size);
		} finally {
			libmupdf._wasm_drop_buffer(buf);
		}
	}
};

mupdf.Buffer = class Buffer extends mupdf._Wrapper {
	// TODO drop function
	constructor(data) {
		// TODO - multiple constructors?
		if (data == null) {
			super(libmupdf._wasm_new_buffer(0), () => {});
		} else {
			let pointer = libmupdf._malloc(data.byteLength);
			libmupdf.HEAPU8.set(new Uint8Array(data), pointer);
			super(libmupdf._wasm_new_buffer_from_data(pointer, data.byteLength), () => {});
		}
	}

	resize(capacity) {
		libmupdf._wasm_resize_buffer(this.pointer, capacity);
	}

	grow() {
		libmupdf._wasm_grow_buffer(this.pointer);
	}

	trim() {
		libmupdf._wasm_trim_buffer(this.pointer);
	}

	clear() {
		libmupdf._wasm_clear_buffer(this.pointer);
	}

	toUint8Array() {
		let data = libmupdf._wasm_buffer_data(this.pointer);
		let size = libmupdf._wasm_buffer_size(this.pointer);
		return libmupdf.HEAPU8.slice(data, data + size);
	}

	toJsString() {
		let data = libmupdf._wasm_buffer_data(this.pointer);
		let size = libmupdf._wasm_buffer_size(this.pointer);

		return libmupdf.UTF8ToString(data, size);
	}
};

mupdf.Output = class Output extends mupdf._Wrapper {
	constructor(buffer) {
		// TODO
		super(libmupdf._wasm_new_output_with_buffer(buffer.pointer), () => {});
	}

	close() {
		libmupdf._wasm_close_output(this.pointer);
	}
};

mupdf.STextPage = class STextPage extends mupdf._Wrapper {
	constructor(pointer) {
		// TODO
		super(pointer, () => {});
	}

	printAsJson(output, scale) {
		libmupdf._wasm_print_stext_page_as_json(output.pointer, this.pointer, scale);
	}
};




// --- copied from previous C code

// TODO - keep page loaded

mupdf.drawPageAsPng = function(document, pageNumber, dpi) {
	const doc_to_screen = mupdf.scale_matrix(dpi / 72, dpi / 72);
	let page;
	let pixmap;

	// TODO - draw annotations
	// TODO - use canvas?

	try {
		page = document.loadPage(pageNumber);
		pixmap = page.toPixmap(doc_to_screen, mupdf.DeviceRGB, false);
		return pixmap.toPNG();
	}
	finally {
		pixmap?.free();
		page?.free();
	}
};

mupdf.getPageText = function(document, pageNumber, dpi) {
	let page;
	let stextPage;

	let buffer;
	let output;

	try {
		page = document.loadPage(pageNumber);
		stextPage = page.toSTextPage();

		buffer = new mupdf.Buffer();
		output = new mupdf.Output(buffer);

		stextPage.printAsJson(output, dpi / 72);
		output.close();

		return JSON.parse(buffer.toJsString());
	}
	finally {
		output?.free();
		buffer?.free();
		stextPage?.free();
		page?.free();
	}
};

mupdf.getPageLinks = function(document, pageNumber, dpi) {
	const doc_to_screen = mupdf.scale_matrix(dpi / 72, dpi / 72);
	let page;
	let links_ptr;

	try {
		page = document.loadPage(pageNumber);
		links_ptr = page.loadLinks();

		return links_ptr.links.map(link => {
			const [x0, y0, x1, y1] = mupdf.transform_rect(link.rect(), doc_to_screen);

			let href;
			if (link.isExternalLink()) {
				href = link.uri();
			} else {
				const pageNumber = link.resolve().pageNumber();
				href = `#${pageNumber + 1}`;
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

mupdf.getPageAnnotations = function(document, pageNumber, dpi) {
	let page;
	let pdfPage;

	try {
		page = document.loadPage(pageNumber);
		pdfPage = page.toPdfPage();

		if (pdfPage == null) {
			return [];
		}

		const annotations = pdfPage.annotations();
		const doc_to_screen = mupdf.scale_matrix(dpi / 72, dpi / 72);

		return annotations.annotations.map(annotation => {
			const [x0, y0, x1, y1] = mupdf.transform_rect(annotation.bounds(), doc_to_screen);

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
		page?.free();
	}
};


mupdf.search = function(document, pageNumber, dpi, needle) {
	let page;

	try {
		page = document.loadPage(pageNumber);
		return page.search(needle);
	}
	finally {
		page?.free();
	}
}
