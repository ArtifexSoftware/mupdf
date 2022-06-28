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

// If running in Node.js environment
if (typeof require === "function") {
	var libmupdf = require("../libmupdf.js");
}

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

class Rect {
	constructor(x0, y0, x1, y1) {
		this.x0 = x0;
		this.y0 = y0;
		this.x1 = x1;
		this.y1 = y1;
	}

	static fromFloatRectPtr(ptr) {
		ptr = ptr >> 2;
		return new Rect(
			libmupdf.HEAPF32[ptr],
			libmupdf.HEAPF32[ptr+1],
			libmupdf.HEAPF32[ptr+2],
			libmupdf.HEAPF32[ptr+3],
		);
	}

	static fromIntRectPtr(ptr) {
		ptr = ptr >> 2;
		return new Rect(
			libmupdf.HEAP32[ptr],
			libmupdf.HEAP32[ptr+1],
			libmupdf.HEAP32[ptr+2],
			libmupdf.HEAP32[ptr+3],
		);
	}

	width() {
		return this.x1 - this.x0;
	}

	height() {
		return this.y1 - this.y0;
	}
}

class Matrix {
	constructor(a, b, c, d, e, f) {
		this.a = a;
		this.b = b;
		this.c = c;
		this.d = d;
		this.e = e;
		this.f = f;
	}

	static fromPtr(ptr) {
		ptr = ptr >> 2;
		return new Matrix(
			libmupdf.HEAPF32[ptr],
			libmupdf.HEAPF32[ptr+1],
			libmupdf.HEAPF32[ptr+2],
			libmupdf.HEAPF32[ptr+3],
			libmupdf.HEAPF32[ptr+4],
			libmupdf.HEAPF32[ptr+5],
		);
	}

	static scale(scale_x, scale_y) {
		return Matrix.fromPtr(libmupdf._wasm_scale(scale_x, scale_y));
	}

	transformRect(rect) {
		return Rect.fromFloatRectPtr(libmupdf._wasm_transform_rect(
			rect.x0, rect.y0, rect.x1, rect.y1,
			this.a, this.b, this.c, this.d, this.e, this.f,
		));
	}
}

// TODO - All constructors should take a pointer, plus a private token

const finalizer = new FinalizationRegistry(callback => callback());

class Wrapper {
	constructor(pointer, dropFunction) {
		this.pointer = pointer;
		this.dropFunction = dropFunction;

		// TODO - Fix error types and messages - log values
		if (typeof pointer !== "number" || pointer === 0)
			throw new Error("invalid pointer param");
		if (dropFunction == null)
			throw new Error("dropFunction is null");
		if (typeof dropFunction !== "function")
			throw new Error("dropFunction is not a function");

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
}

// TODO - Add PdfDocument class

class Document extends Wrapper {
	constructor(pointer) {
		super(pointer, libmupdf._wasm_drop_document);
	}

	static openFromData(data, magic) {
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

	static openFromStream(stream, magic) {
		let pointer = libmupdf.ccall(
			"wasm_open_document_with_stream",
			"number",
			["number", "string"],
			[stream.pointer, magic]
		);
		return new Document(pointer);
	}

	countPages() {
		return libmupdf._wasm_count_pages(this.pointer);
	}

	loadPage(pageNumber) {
		let page_ptr = libmupdf._wasm_load_page(this.pointer, pageNumber);
		let pdfPage_ptr = libmupdf._wasm_pdf_page_from_fz_page(page_ptr);

		if (pdfPage_ptr !== 0) {
			return new PdfPage(page_ptr, pdfPage_ptr);
		} else {
			return new Page(page_ptr);
		}
	}

	title() {
		// Note - the underlying function uses static memory; we don't need to free
		return libmupdf.UTF8ToString(libmupdf._wasm_document_title(this.pointer));
	}

	loadOutline() {
		return new_outline(libmupdf._wasm_load_outline(this.pointer));
	}
}

class Page extends Wrapper {
	constructor(pointer) {
		super(pointer, libmupdf._wasm_drop_page);
	}

	bounds() {
		return Rect.fromFloatRectPtr(libmupdf._wasm_bound_page(this.pointer));
	}

	width() {
		return this.bounds().width();
	}

	height() {
		return this.bounds().height();
	}

	toPixmap(transformMatrix, colorspace, alpha = false) {
		if (!(transformMatrix instanceof Matrix)) {
			throw new TypeError("transformMatrix argument isn't an instance of Matrix class");
		}
		let m = transformMatrix;
		return new Pixmap(
			libmupdf._wasm_new_pixmap_from_page(
				this.pointer,
				m.a, m.b, m.c, m.d, m.e, m.f,
				colorspace,
				alpha
			)
		);
	}

	toSTextPage() {
		return new STextPage(
			libmupdf._wasm_new_stext_page_from_page(this.pointer)
		);
	}

	loadLinks() {
		let links = [];

		for (let link = libmupdf._wasm_load_links(this.pointer); link !== 0; link = libmupdf._wasm_next_link(link)) {
			links.push(new Link(link));
		}

		return new Links(links);
	}

	search(needle) {
		const MAX_HIT_COUNT = 500;
		let needle_ptr = 0;
		let hits_ptr = 0;

		try {
			// TODO - use fz_malloc instead
			hits_ptr = libmupdf._malloc(libmupdf._wasm_size_of_quad() * MAX_HIT_COUNT);

			// TODO - write conversion method
			let needle_size = libmupdf.lengthBytesUTF8(needle);
			needle_ptr = libmupdf._malloc(needle_size) + 1;
			libmupdf.stringToUTF8(needle, needle_ptr, needle_size + 1);

			let hitCount = libmupdf._wasm_search_page(
				this.pointer, needle_ptr, hits_ptr, MAX_HIT_COUNT
			);

			let rects = [];
			for (let i = 0; i < hitCount; ++i) {
				let hit = hits_ptr + i * libmupdf._wasm_size_of_quad();
				let rect = Rect.fromFloatRectPtr(libmupdf._wasm_rect_from_quad(hit));
				rects.push(rect);
			}

			return rects;
		}
		finally {
			libmupdf._free(needle_ptr);
			libmupdf._free(hits_ptr);
		}
	}
}

class PdfPage extends Page {
	constructor(pagePointer, pdfPagePointer) {
		super(pagePointer);
		this.pdfPagePointer = pdfPagePointer;
	}

	annotations() {
		let annotations = [];

		for (let annot = libmupdf._wasm_pdf_first_annot(this.pdfPagePointer); annot !== 0; annot = libmupdf._wasm_pdf_next_annot(annot)) {
			annotations.push(new Annotation(annot));
		}

		return new Annotations(annotations);
	}
}

// TODO destructor
class Links {
	constructor(links) {
		this.links = links;
	}
}

class Link extends Wrapper {
	constructor(pointer) {
		// TODO
		super(pointer, () => {});
	}

	rect() {
		return Rect.fromFloatRectPtr(libmupdf._wasm_link_rect(this.pointer));
	}

	isExternalLink() {
		return libmupdf._wasm_is_external_link(this.pointer) !== 0;
	}

	uri() {
		return libmupdf.UTF8ToString(libmupdf._wasm_link_uri(this.pointer));
	}

	resolve(doc) {
		const uri_string_ptr = libmupdf._wasm_link_uri(this.pointer);
		return new Location(
			libmupdf._wasm_resolve_link_chapter(doc.pointer, uri_string_ptr),
			libmupdf._wasm_resolve_link_page(doc.pointer, uri_string_ptr),
		);
	}
}

class Location {
	constructor(chapter, page) {
		this.chapter = chapter;
		this.page = page;
	}

	pageNumber(doc) {
		return libmupdf._wasm_page_number_from_location(doc.pointer, this.chapter, this.page);
	}
}

function new_outline(pointer) {
	if (pointer === 0)
		return null;
	else
		return new Outline(pointer);
}

// FIXME - This is pretty non-idiomatic
class Outline extends Wrapper {
	constructor(pointer) {
		// TODO
		super(pointer, () => {});
	}

	pageNumber(doc) {
		return libmupdf._wasm_outline_page(doc.pointer, this.pointer);
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
}

// TODO destructor
class Annotations {
	constructor(annotations) {
		this.annotations = annotations;
	}
}

class Annotation extends Wrapper {
	// TODO - the lifetime handling of this is actually complicated
	constructor(pointer) {
		super(pointer, () => {});
	}

	bounds() {
		return Rect.fromFloatRectPtr(libmupdf._wasm_pdf_bound_annot(this.pointer));
	}

	annotType() {
		return libmupdf.UTF8ToString(libmupdf._wasm_pdf_annot_type_string(this.pointer));
	}
}

class ColorSpace extends Wrapper {
	constructor(pointer) {
		super(pointer, libmupdf._wasm_drop_colorspace);
	}
}

class Pixmap extends Wrapper {
	constructor(pointer) {
		super(pointer, libmupdf._wasm_drop_pixmap);
		this.bbox = Rect.fromIntRectPtr(libmupdf._wasm_pixmap_bbox(this.pointer));
	}

	width() {
		return this.bbox.width();
	}

	height() {
		return this.bbox.height();
	}

	samples() {
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
}

class Buffer extends Wrapper {
	constructor(pointer) {
		super(pointer, libmupdf._wasm_drop_buffer);
	}

	static empty(capacity = 0) {
		let pointer = libmupdf._wasm_new_buffer(capacity);
		return new Buffer(pointer);
	}

	static fromJsBuffer(buffer) {
		let pointer = libmupdf._malloc(buffer.byteLength);
		libmupdf.HEAPU8.set(new Uint8Array(buffer), pointer);
		return new Buffer(libmupdf._wasm_new_buffer_from_data(pointer, buffer.byteLength));
	}

	static fromJsString(string) {
		let string_size = libmupdf.lengthBytesUTF8(string);
		let string_ptr = libmupdf._malloc(string_size) + 1;
		libmupdf.stringToUTF8(string, string_ptr, string_size + 1);
		return new Buffer(libmupdf._wasm_new_buffer_from_data(string_ptr, string_size));
	}

	size() {
		return libmupdf._wasm_buffer_size(this.pointer);
	}

	capacity() {
		return libmupdf._wasm_buffer_capacity(this.pointer);
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

	sameContentAs(otherBuffer) {
		return libmupdf._wasm_buffers_eq(this.pointer, otherBuffer.pointer) !== 0;
	}
}

class Stream extends Wrapper {
	constructor(pointer) {
		super(pointer, libmupdf._wasm_drop_stream);
	}

	static fromBuffer(buffer) {
		return new Stream(libmupdf._wasm_new_stream_from_buffer(buffer.pointer));
	}

	static fromJsBuffer(buffer) {
		let pointer = libmupdf._malloc(buffer.byteLength);
		libmupdf.HEAPU8.set(new Uint8Array(buffer), pointer);
		return new Stream(libmupdf._wasm_new_stream_from_data(pointer, buffer.byteLength));
	}

	static fromJsString(string) {
		let string_size = libmupdf.lengthBytesUTF8(string);
		let string_ptr = libmupdf._malloc(string_size) + 1;
		libmupdf.stringToUTF8(string, string_ptr, string_size + 1);
		return new Stream(libmupdf._wasm_new_stream_from_data(string_ptr, string_size));
	}

	readAll(suggestedCapacity = 0) {
		return new Buffer(libmupdf._wasm_read_all(this.pointer, suggestedCapacity));
	}
}

class Output extends Wrapper {
	constructor(pointer) {
		super(pointer, libmupdf._wasm_drop_output);
	}

	static withBuffer(buffer) {
		return new Output(libmupdf._wasm_new_output_with_buffer(buffer.pointer));
	}

	close() {
		libmupdf._wasm_close_output(this.pointer);
	}
}

class STextPage extends Wrapper {
	constructor(pointer) {
		super(pointer, libmupdf._wasm_drop_stext_page);
	}

	printAsJson(output, scale) {
		libmupdf._wasm_print_stext_page_as_json(output.pointer, this.pointer, scale);
	}
}



// --- EXPORTS ---

const mupdf = {
	MupdfError,
	MupdfTryLaterError,
	Rect,
	Matrix,
	Document,
	Page,
	Links,
	Link,
	Location,
	Outline,
	PdfPage,
	Annotations,
	Annotation,
	ColorSpace,
	Pixmap,
	Buffer,
	Stream,
	Output,
	STextPage,
};

const libmupdf_injections = {
	MupdfError,
	MupdfTryLaterError,
};

mupdf.ready = libmupdf(libmupdf_injections).then(m => {
	libmupdf = m;

	console.log("WASM MODULE READY");

	libmupdf._wasm_init_context();

	mupdf.DeviceGray = new ColorSpace(libmupdf._wasm_device_gray());
	mupdf.DeviceRGB = new ColorSpace(libmupdf._wasm_device_rgb());
	mupdf.DeviceBGR = new ColorSpace(libmupdf._wasm_device_bgr());
	mupdf.DeviceCMYK = new ColorSpace(libmupdf._wasm_device_cmyk());
});

// If running in Node.js environment
if (typeof require === "function") {
	module.exports = mupdf;
}
