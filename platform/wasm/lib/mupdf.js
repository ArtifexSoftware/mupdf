// Copyright (C) 2004-2023 Artifex Software, Inc.
//
// This file is part of MuPDF WASM Library.
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

"use strict"

var libmupdf

// If running in Node.js environment
if (typeof require === "function")
	libmupdf = require("./mupdf-wasm.js")

function checkType(value, type) {
	if (typeof type === "string" && typeof value !== type)
		throw new TypeError("expected " + type)
	if (typeof type === "function" && !(value instanceof type))
		throw new TypeError("expected " + type.name)
}

function checkPoint(value) {
	if (!Array.isArray(value) || value.length !== 2)
		throw new TypeError("expected point")
}

function checkRect(value) {
	if (!Array.isArray(value) || value.length !== 4)
		throw new TypeError("expected rectangle")
}

function checkMatrix(value) {
	if (!Array.isArray(value) || value.length !== 6)
		throw new TypeError("expected matrix")
}

function checkQuad(value) {
	if (!Array.isArray(value) || value.length !== 8)
		throw new TypeError("expected quad")
}

function checkColor(value) {
	if (!Array.isArray(value) || (value.length !== 1 && value.length !== 3 && value.length !== 4))
		throw new TypeError("expected color array")
}

function allocateUTF8(str) {
	var size = libmupdf.lengthBytesUTF8(str) + 1
	var pointer = libmupdf._wasm_malloc(size)
	libmupdf.stringToUTF8(str, pointer, size)
	return pointer
}

let _wasm_point = 0
let _wasm_rect = 0
let _wasm_quad = 0
let _wasm_matrix = 0
let _wasm_color = 0
let _wasm_string = [ 0, 0 ]

function STRING_N(s,i) {
	if (_wasm_string[i]) {
		libmupdf._wasm_free(_wasm_string[i])
		_wasm_string[i] = i
	}
	_wasm_string[i] = allocateUTF8(s)
	return _wasm_string[i]
}

function STRING(s) {
	return STRING_N(s, 0)
}

function STRING2(s) {
	return STRING_N(s, 1)
}

function POINT(p) {
	libmupdf.HEAPF32[_wasm_point + 0] = p[0]
	libmupdf.HEAPF32[_wasm_point + 1] = p[1]
	return _wasm_point << 2
}

function RECT(r) {
	libmupdf.HEAPF32[_wasm_rect + 0] = r[0]
	libmupdf.HEAPF32[_wasm_rect + 1] = r[1]
	libmupdf.HEAPF32[_wasm_rect + 2] = r[2]
	libmupdf.HEAPF32[_wasm_rect + 3] = r[3]
	return _wasm_rect << 2
}

function RECT2(r) {
	libmupdf.HEAPF32[_wasm_rect + 4] = r[0]
	libmupdf.HEAPF32[_wasm_rect + 5] = r[1]
	libmupdf.HEAPF32[_wasm_rect + 6] = r[2]
	libmupdf.HEAPF32[_wasm_rect + 7] = r[3]
	return (_wasm_rect + 4) << 2
}

function MATRIX(m) {
	libmupdf.HEAPF32[_wasm_matrix + 0] = m[0]
	libmupdf.HEAPF32[_wasm_matrix + 1] = m[1]
	libmupdf.HEAPF32[_wasm_matrix + 2] = m[2]
	libmupdf.HEAPF32[_wasm_matrix + 3] = m[3]
	libmupdf.HEAPF32[_wasm_matrix + 4] = m[4]
	libmupdf.HEAPF32[_wasm_matrix + 5] = m[5]
	return _wasm_matrix << 2
}

function QUAD(q) {
	libmupdf.HEAPF32[_wasm_quad + 0] = q[0]
	libmupdf.HEAPF32[_wasm_quad + 1] = q[1]
	libmupdf.HEAPF32[_wasm_quad + 2] = q[2]
	libmupdf.HEAPF32[_wasm_quad + 3] = q[3]
	libmupdf.HEAPF32[_wasm_quad + 4] = q[4]
	libmupdf.HEAPF32[_wasm_quad + 5] = q[5]
	libmupdf.HEAPF32[_wasm_quad + 6] = q[6]
	libmupdf.HEAPF32[_wasm_quad + 7] = q[7]
	return _wasm_quad << 2
}

function COLOR(c) {
	for (let i = 0; i < c.length; ++i)
		libmupdf.HEAPF32[_wasm_color + i] = c[i]
	return _wasm_color << 2
}

function fromString(ptr) {
	return libmupdf.UTF8ToString(ptr)
}

function fromStringFree(ptr) {
	let str = libmupdf.UTF8ToString(ptr)
	libmupdf._wasm_free(ptr)
	return str
}

function fromPoint(ptr) {
	ptr = ptr >> 2
	return [
		libmupdf.HEAPF32[ptr + 0],
		libmupdf.HEAPF32[ptr + 1],
	]
}

function fromRect(ptr) {
	ptr = ptr >> 2
	return [
		libmupdf.HEAPF32[ptr + 0],
		libmupdf.HEAPF32[ptr + 1],
		libmupdf.HEAPF32[ptr + 2],
		libmupdf.HEAPF32[ptr + 3],
	]
}

function fromMatrix(ptr) {
	ptr = ptr >> 2
	return [
		libmupdf.HEAPF32[ptr + 0],
		libmupdf.HEAPF32[ptr + 1],
		libmupdf.HEAPF32[ptr + 2],
		libmupdf.HEAPF32[ptr + 3],
		libmupdf.HEAPF32[ptr + 4],
		libmupdf.HEAPF32[ptr + 5],
	]
}

function fromQuad(ptr) {
	ptr = ptr >> 2
	return [
		libmupdf.HEAPF32[ptr + 0],
		libmupdf.HEAPF32[ptr + 1],
		libmupdf.HEAPF32[ptr + 2],
		libmupdf.HEAPF32[ptr + 3],
		libmupdf.HEAPF32[ptr + 4],
		libmupdf.HEAPF32[ptr + 5],
		libmupdf.HEAPF32[ptr + 6],
		libmupdf.HEAPF32[ptr + 7],
	]
}

function fromBuffer(buf) {
	let data = libmupdf._wasm_buffer_get_data(buf)
	let size = libmupdf._wasm_buffer_get_len(buf)
	return libmupdf.HEAPU8.slice(data, data + size)
}

const Matrix = {
	identity: [ 1, 0, 0, 1, 0, 0 ],
	scale(sx, sy) {
		return [ sx, 0, 0, sy, 0, 0 ]
	},
	translate(tx, ty) {
		return [ 1, 0, 0, 1, tx, ty ]
	},
	rotate(d) {
		while (d < 0)
			d += 360
		while (d >= 360)
			d -= 360
		let s = Math.sin((d * Math.PI) / 180)
		let c = Math.cos((d * Math.PI) / 180)
		return [ c, s, -s, c, 0, 0 ]
	},
	invert(m) {
		checkMatrix(m)
		let det = m[0] * m[3] - m[1] * m[2]
		if (det > -1e-23 && det < 1e-23)
			return m
		let rdet = 1 / det
		let inva = m[3] * rdet
		let invb = -m[1] * rdet
		let invc = -m[2] * rdet
		let invd = m[0] * rdet
		let inve = -m[4] * inva - m[5] * invc
		let invf = -m[4] * invb - m[5] * invd
		return [ inva, invb, invc, invd, inve, invf ]
	},
	concat(one, two) {
		checkMatrix(one)
		checkMatrix(two)
		return [
			one[0] * two[0] + one[1] * two[2],
			one[0] * two[1] + one[1] * two[3],
			one[2] * two[0] + one[3] * two[2],
			one[2] * two[1] + one[3] * two[3],
			one[4] * two[0] + one[5] * two[2] + two[4],
			one[4] * two[1] + one[5] * two[3] + two[5],
		]
	},
}

const Rect = {
	MIN_INF_RECT: 0x80000000,
	MAX_INF_RECT: 0x7fffff80,
	isEmpty: function (rect) {
		checkRect(rect)
		return rect[0] >= rect[2] || rect[1] >= rect[3]
	},
	isValid: function (rect) {
		checkRect(rect)
		return rect[0] <= rect[2] && rect[1] <= rect[3]
	},
	isInfinite: function (rect) {
		checkRect(rect)
		return (
			rect[0] === Rect.MIN_INF_RECT &&
			rect[1] === Rect.MIN_INF_RECT &&
			rect[2] === Rect.MAX_INF_RECT &&
			rect[3] === Rect.MAX_INF_RECT
		)
	},
	transform: function (rect, matrix) {
		checkRect(rect)
		checkMatrix(matrix)
		var t

		if (Rect.isInfinite(rect))
			return rect
		if (!Rect.isValid(rect))
			return rect

		var ax0 = rect[0] * matrix[0]
		var ax1 = rect[2] * matrix[0]
		if (ax0 > ax1)
			t = ax0, ax0 = ax1, ax1 = t

		var cy0 = rect[1] * matrix[2]
		var cy1 = rect[3] * matrix[2]
		if (cy0 > cy1)
			t = cy0, cy0 = cy1, cy1 = t

		ax0 += cy0 + matrix[4]
		ax1 += cy1 + matrix[4]

		var bx0 = rect[0] * matrix[1]
		var bx1 = rect[2] * matrix[1]
		if (bx0 > bx1)
			t = bx0, bx0 = bx1, bx1 = t

		var dy0 = rect[1] * matrix[3]
		var dy1 = rect[3] * matrix[3]
		if (dy0 > dy1)
			t = dy0, dy0 = dy1, dy1 = t

		bx0 += dy0 + matrix[5]
		bx1 += dy1 + matrix[5]

		return [ ax0, bx0, ax1, bx1 ]
	},
}

class Userdata {
	constructor(pointer) {
		if (typeof pointer !== "number")
			throw new Error("invalid pointer: " + typeof pointer)

		if (!this.constructor._finalizer) {
			this.constructor._drop = libmupdf[this.constructor._drop]
			this.constructor._finalizer = new FinalizationRegistry(this.constructor._drop)
		}

		this.constructor._finalizer.register(this, pointer, this)
		this.pointer = pointer
	}
	destroy() {
		this.constructor._finalizer.unregister(this)
		this.constructor._drop(this.pointer)
		this.pointer = 0
	}

	// Custom "console.log" formatting for Node
	[Symbol.for("nodejs.util.inspect.custom")]() {
		return this.toString()
	}

	toString() {
		return `[${this.constructor.name} ${this.pointer}]`
	}
	valueOf() {
		return this.pointer
	}
}

class Buffer extends Userdata {
	static _drop = "_wasm_drop_buffer"

	constructor(arg) {
		let pointer = 0
		if (typeof arg === "undefined") {
			pointer = libmupdf._wasm_new_buffer(1024)
		} else if (typeof arg === "number") {
			pointer = arg
		} else if (typeof arg === "string") {
			let data_len = libmupdf.lengthBytesUTF8(arg)
			let data_ptr = libmupdf._wasm_malloc(data_len) + 1
			libmupdf.stringToUTF8(arg, data_len, data_ptr + 1)
			pointer = libmupdf._wasm_new_buffer_from_data(data_ptr, data_len)
		} else if (arg instanceof ArrayBuffer || arg instanceof Uint8Array) {
			let data_len = arg.byteLength
			let data_ptr = libmupdf._wasm_malloc(data_len)
			libmupdf.HEAPU8.set(new Uint8Array(arg), data_ptr)
			pointer = libmupdf._wasm_new_buffer_from_data(data_ptr, data_len)
		}
		super(pointer)
	}

	getLength() {
		return libmupdf._wasm_buffer_get_len(this)
	}

	readByte(at) {
		let data = libmupdf._wasm_buffer_get_data(this)
		libmupdf.HEAPU8[data + at]
	}

	write(s) {
		libmupdf._wasm_append_string(this, STRING(s))
	}

	writeByte(b) {
		libmupdf._wasm_append_byte(this, b)
	}

	writeLine(s) {
		this.write(s)
		this.writeByte(10)
	}

	writeBuffer(other) {
		if (!(other instanceof Buffer))
			other = new Buffer(other)
		libmupdf._wasm_append_buffer(this, other)
	}

	asUint8Array() {
		let data = libmupdf._wasm_buffer_get_data(this)
		let size = libmupdf._wasm_buffer_get_len(this)
		return libmupdf.HEAPU8.subarray(data, data + size)
	}

	asString() {
		return fromString(libmupdf._wasm_buffer_get_data(this))
	}
}

class ColorSpace extends Userdata {
	static _drop = "_wasm_drop_colorspace"
	static TYPES = [
		"None",
		"Gray",
		"RGB",
		"BGR",
		"CMYK",
		"Lab",
		"Indexed",
		"Separation"
	]
	constructor(from, name) {
		let pointer = from
		if (from instanceof ArrayBuffer || from instanceof Uint8Array)
			from = new Buffer(from)
		if (from instanceof Buffer)
			pointer = libmupdf._wasm_new_icc_colorspace(name, from)
		super(pointer)
	}
	getName() {
		return fromString(libmupdf._wasm_colorspace_get_name(this))
	}
	getType() {
		return ColorSpace.TYPES[libmupdf._wasm_colorspace_get_type(this)]
	}
	getNumberOfComponents() {
		return libmupdf._wasm_colorspace_get_n(this)
	}
	toString() {
		return "[ColorSpace " + this.getName() + "]"
	}
}

class Font extends Userdata {
	static _drop = "_wasm_drop_font"

	static ADOBE_CNS = 0
	static ADOBE_GB = 1
	static ADOBE_JAPAN = 2
	static ADOBE_KOREA = 3

	static CJK_ORDERING_BY_LANG = {
		"Adobe-CNS1": 0,
		"Adobe-GB1": 1,
		"Adobe-Japan1": 2,
		"Adobe-Korea1": 3,
		"zh-Hant": 0,
		"zh-TW": 0,
		"zh-HK": 0,
		"zh-Hans": 1,
		"zh-CN": 1,
		"ja": 2,
		"ko": 3,
	}

	constructor(arg1, arg2) {
		let pointer = 0
		if (typeof arg1 === "number") {
			pointer = libmupdf._wasm_keep_font(arg1)
		} else if (typeof arg1 === "string") {
			pointer = libmupdf._wasm_new_base14_font(STRING(name))
		}
		else if (arg1 instanceof Buffer) {
			pointer = libmupdf._wasm_new_font_from_buffer(arg1, arg2 | 0)
		}
		super(pointer)
	}

	getName() {
		return fromString(libmupdf._wasm_font_get_name(this))
	}

	encodeCharacter(uni) {
		if (typeof uni === "string")
			uni = uni.charCodeAt(0)
		return libmupdf._wasm_encode_character(this, uni)
	}

	advanceGlyph(gid, wmode = 0) {
		return libmupdf._wasm_advance_glyph(this, gid, wmode)
	}
}

class Image extends Userdata {
	static _drop = "_wasm_drop_image"

	constructor(arg1) {
		let pointer = 0
		if (typeof arg1 === "number")
			pointer = libmupdf._wasm_keep_image(arg1)
		else if (arg1 instanceof Pixmap)
			pointer = libmupdf._wasm_new_from_pixmap(arg1)
		else if (arg1 instanceof Buffer)
			pointer = libmupdf._wasm_new_image_from_buffer(arg1)
		super(pointer)
	}

	getWidth() {
		return libmupdf._wasm_image_get_w(this)
	}
	getHeight() {
		return libmupdf._wasm_image_get_h(this)
	}
	getNumberOfComponents() {
		return libmupdf._wasm_image_get_n(this)
	}
	getBitsPerComponent() {
		return libmupdf._wasm_image_get_bpc(this)
	}
	getXResolution() {
		return libmupdf._wasm_image_get_xres(this)
	}
	getYResolution() {
		return libmupdf._wasm_image_get_yres(this)
	}
	getImageMask() {
		return libmupdf._wasm_image_get_imagemask(this)
	}

	getColorSpace() {
		let cs = libmupdf._wasm_image_get_colorspace(this)
		if (cs)
			return new ColorSpace(libmupdf._wasm_keep_colorspace(cs))
		return null
	}

	getMask() {
		let mask = libmupdf._wasm_image_get_mask(this)
		if (mask)
			return new Image(mask)
		return null
	}

	toPixmap() {
		return new Pixmap(libmupdf._wasm_pdf_get_pixmap_from_image(this))
	}
}

class StrokeState extends Userdata {
	static _drop = "_wasm_drop_stroke_state"
	constructor(pointer) {
		if (pointer === undefined)
			pointer = libmupdf._wasm_new_stroke_state()
		super(pointer)
	}
	getLineCap() {
		return libmupdf._wasm_stroke_state_get_start_cap(this)
	}
	setLineCap(j) {
		libmupdf._wasm_stroke_state_set_start_cap(this, j)
		libmupdf._wasm_stroke_state_set_dash_cap(this, j)
		libmupdf._wasm_stroke_state_set_end_cap(this, j)
	}
	setLineJoin(j) {
		libmupdf._wasm_stroke_state_set_linejoin(this, j)
	}
	getLineJoin() {
		return libmupdf._wasm_stroke_state_get_linejoin(this)
	}
	setLineWidth(w) {
		libmupdf._wasm_stroke_state_set_linewidth(this, w)
	}
	getMiterLimit() {
		return libmupdf._wasm_stroke_state_get_miterlimit(this)
	}
	setMiterLimit(m) {
		libmupdf._wasm_stroke_state_set_miterlimit(this, m)
	}
}

class Path extends Userdata {
	static _drop = "_wasm_drop_path"
	constructor() {
		super(libmupdf._wasm_new_path())
	}
	getBounds() {
		return fromRect(libmupdf._wasm_bound_path(this))
	}
	moveTo(x, y) {
		libmupdf._wasm_moveto(this, x, y)
	}
	lineTo(x, y) {
		libmupdf._wasm_lineto(this, x, y)
	}
	curveTo(x1, y1, x2, y2, x3, y3) {
		libmupdf._wasm_curveto(this, x1, y1, x2, y2, x3, y3)
	}
	curveToV(cx, cy, ex, ey) {
		libmupdf._wasm_curvetov(this, cx, cy, ex, ey)
	}
	curveToY(cx, cy, ex, ey) {
		libmupdf._wasm_curvetoy(this, cx, cy, ex, ey)
	}
	closePath() {
		libmupdf._wasm_closepath(this)
	}
	rect(x1, y1, x2, y2) {
		libmupdf._wasm_rectto(this, x1, y1, x2, y2)
	}
	transform(matrix) {
		checkMatrix(matrix)
		libmupdf._wasm_transform_path(this, MATRIX(matrix))
	}
	walk(walker) {
		throw "TODO"
	}
}

class Text extends Userdata {
	static _drop = "_wasm_drop_text"

	constructor() {
		super(libmupdf._wasm_new_text())
	}

	getBounds() {
		return fromRect(libmupdf._wasm_bound_text(this))
	}

	showGlyph(font, trm, gid, uni, wmode = 0) {
		checkType(font, Font)
		checkMatrix(trm)
		checkType(gid, "number")
		checkType(uni, "number")
		libmupdf._wasm_show_glyph(
			this,
			font,
			MATRIX(trm),
			gid,
			uni,
			wmode
		)
	}

	showString(font, trm, str, wmode = 0) {
		checkType(font, Font)
		checkMatrix(trm)
		checkType(str, "string")
		let out_trm = fromMatrix(
			libmupdf._wasm_show_string(
				this,
				font,
				MATRIX(trm),
				STRING(str),
				wmode
			)
		)
		trm[4] = out_trm[4]
		trm[5] = out_trm[5]
	}

	walk(walker) {
		throw "TODO"
	}
}

class DisplayList extends Userdata {
	static _drop = "_wasm_drop_display_list"

	constructor(arg1) {
		let pointer = 0
		if (typeof arg1 === "number") {
			pointer = arg1
		} else {
			checkRect(arg1)
			pointer = libmupdf._wasm_new_display_list(RECT(arg1))
		}
		super(pointer)
	}

	getBounds() {
		return fromRect(libmupdf._wasm_bound_display_list(this))
	}

	toPixmap(matrix, colorspace, alpha = false) {
		checkMatrix(matrix)
		checkType(colorspace, ColorSpace)
		return new Pixmap(
			libmupdf._wasm_new_pixmap_from_display_list(
				this,
				MATRIX(matrix),
				colorspace,
				alpha
			)
		)
	}

	toStructuredText() {
		return new StructuredText(libmupdf._wasm_new_stext_page_from_display_list(this))
	}

	run(device, matrix) {
		checkType(device, Device)
		checkMatrix(matrix)
		libmupdf._wasm_run_display_list(this, device, MATRIX(matrix))
	}

	// TODO: search
}

class Pixmap extends Userdata {
	static _drop = "_wasm_drop_pixmap"

	constructor(arg1, bbox = null, alpha = false) {
		let pointer = arg1
		if (arg1 instanceof ColorSpace) {
			checkRect(bbox)
			pointer = libmupdf._wasm_new_pixmap_with_bbox(arg1, RECT(bbox), alpha)
		}
		super(pointer)
	}

	getBounds() {
		let x = libmupdf._wasm_pixmap_get_x(this)
		let y = libmupdf._wasm_pixmap_get_y(this)
		let w = libmupdf._wasm_pixmap_get_w(this)
		let h = libmupdf._wasm_pixmap_get_h(this)
		return [ x, y, x + w, y + h ]
	}

	clear(value) {
		if (typeof value === "undefined")
			libmupdf._wasm_clear_pixmap(this)
		else
			libmupdf._wasm_clear_pixmap_with_value(this, value)
	}

	getWidth() {
		return libmupdf._wasm_pixmap_get_w(this)
	}
	getHeight() {
		return libmupdf._wasm_pixmap_get_h(this)
	}
	getX() {
		return libmupdf._wasm_pixmap_get_x(this)
	}
	getY() {
		return libmupdf._wasm_pixmap_get_y(this)
	}
	getStride() {
		return libmupdf._wasm_pixmap_get_stride(this)
	}
	getNumberOfComponents() {
		return libmupdf._wasm_pixmap_get_n(this)
	}
	getXResolution() {
		return libmupdf._wasm_pixmap_get_xres(this)
	}
	getYResolution() {
		return libmupdf._wasm_pixmap_get_yres(this)
	}

	setResolution(x, y) {
		libmupdf._wasm_pixmap_set_xres(this, x)
		libmupdf._wasm_pixmap_set_yres(this, y)
	}

	getColorSpace() {
		let cs = libmupdf._wasm_pixmap_get_colorspace(this)
		if (cs)
			return new ColorSpace(libmupdf._wasm_keep_colorspace(cs))
		return null
	}

	getPixels() {
		let s = libmupdf._wasm_pixmap_get_stride(this)
		let h = libmupdf._wasm_pixmap_get_h(this)
		let p = libmupdf._wasm_pixmap_get_samples(this)
		return new Uint8ClampedArray(libmupdf.HEAPU8.buffer, p, s * h)
	}

	asPNG() {
		let buf = libmupdf._wasm_new_buffer_from_pixmap_as_png(this)
		try {
			return fromBuffer(buf)
		} finally {
			libmupdf._wasm_drop_buffer(buf)
		}
	}

	asPSD() {
		let buf = libmupdf._wasm_new_buffer_from_pixmap_as_psd(this)
		try {
			return fromBuffer(buf)
		} finally {
			libmupdf._wasm_drop_buffer(buf)
		}
	}

	asPAM() {
		let buf = libmupdf._wasm_new_buffer_from_pixmap_as_pam(this)
		try {
			return fromBuffer(buf)
		} finally {
			libmupdf._wasm_drop_buffer(buf)
		}
	}

	asJPEG(quality) {
		let buf = libmupdf._wasm_new_buffer_from_pixmap_as_jpeg(this, quality)
		try {
			return fromBuffer(buf)
		} finally {
			libmupdf._wasm_drop_buffer(buf)
		}
	}

	invert() {
		libmupdf._wasm_invert_pixmap(this)
	}

	invertLuminance() {
		libmupdf._wasm_invert_pixmap_luminance(this)
	}

	gamma(p) {
		libmupdf._wasm_gamma_pixmap(this, p)
	}

	tint(black, white) {
		if (black instanceof Array)
			black = ( ( (black[0] * 255) << 16 ) | ( (black[1] * 255) << 8 ) | ( (black[2] * 255) ) )
		if (white instanceof Array)
			white = ( ( (white[0] * 255) << 16 ) | ( (white[1] * 255) << 8 ) | ( (white[2] * 255) ) )
		libmupdf._wasm_tint_pixmap(this, black, white)
	}
}

class Shade extends Userdata {
	static _drop = "_wasm_drop_shade"
	constructor(pointer) {
		super(pointer)
	}
	getBounds() {
		return fromRect(libmupdf._wasm_bound_shade(this))
	}
}

class StructuredText extends Userdata {
	static _drop = "_wasm_drop_stext_page"

	static SELECT_CHARS = 0
	static SELECT_WORDS = 1
	static SELECT_LINES = 2

	walk(walker) {
		let block = libmupdf._wasm_stext_page_get_first_block(this)
		while (block) {
			let block_type = libmupdf._wasm_stext_block_get_type(block)
			let block_bbox = fromRect(libmupdf._wasm_stext_block_get_bbox(block))

			if (block_type === 1) {
				if (walker.onImageBlock) {
					let matrix = fromMatrix(libmupdf._wasm_stext_block_get_transform(block))
					let image = new Image(libmupdf._wasm_stext_block_get_image(block))
					walker.onImageBlock(block_bbox, matrix, image)
				}
			} else {
				if (walker.beginTextBlock)
					walker.beginTextBlock(block_bbox)

				let line = libmupdf._wasm_stext_block_get_first_line(block)
				while (line) {
					let line_bbox = fromRect(libmupdf._wasm_stext_line_get_bbox(line))
					let line_wmode = libmupdf._wasm_stext_line_get_wmode(line)

					if (walker.beginLine)
						walker.beginLine(line_bbox, line_wmode)

					if (walker.onChar) {
						let ch = libmupdf._wasm_stext_line_get_first_char(line)
						while (ch) {
							let ch_rune = String.fromCharCode(libmupdf._wasm_stext_char_get_c(ch))
							let ch_origin = fromPoint(libmupdf._wasm_stext_char_get_origin(ch))
							let ch_font = new Font(libmupdf._wasm_stext_char_get_font(ch))
							let ch_size = libmupdf._wasm_stext_char_get_size(ch)
							let ch_quad = fromQuad(libmupdf._wasm_stext_char_get_quad(ch))

							walker.onChar(ch_rune, ch_origin, ch_font, ch_size, ch_quad)

							ch = libmupdf._wasm_stext_char_get_next(ch)
						}
					}

					if (walker.endLine)
						walker.endLine()

					line = libmupdf._wasm_stext_line_get_next(line)
				}

				if (walker.endTextBlock)
					walker.endTextBlock()
			}

			block = libmupdf._wasm_stext_block_get_next(block)
		}
	}

	asJSON(scale = 1) {
		return fromStringFree(libmupdf._wasm_print_stext_page_as_json(this, scale))
	}

	// TODO: highlight(a, b) -> quad[]
	// TODO: copy(a, b) -> string
	// TODO: search(needle) -> quad[][]
}

class Device extends Userdata {
	static _drop = "_wasm_drop_device"

	static BLEND_MODES = [
		"Normal",
		"Multiply",
		"Screen",
		"Overlay",
		"Darken",
		"Lighten",
		"ColorDodge",
		"ColorBurn",
		"HardLight",
		"SoftLight",
		"Difference",
		"Exclusion",
		"Hue",
		"Saturation",
		"Color",
		"Luminosity",
	]

	fillPath(path, evenOdd, ctm, colorspace, color, alpha) {
		checkType(path, Path)
		checkMatrix(ctm)
		checkType(colorspace, ColorSpace)
		checkColor(color)
		libmupdf._wasm_fill_path(this, path, evenOdd, MATRIX(ctm), colorspace, COLOR(color), alpha)
	}

	strokePath(path, stroke, ctm, colorspace, color, alpha) {
		checkType(path, Path)
		checkType(stroke, StrokeState)
		checkMatrix(ctm)
		checkType(colorspace, ColorSpace)
		checkColor(color)
		libmupdf._wasm_stroke_path(
			this,
			path,
			stroke,
			MATRIX(ctm),
			colorspace,
			COLOR(color),
			alpha
		)
	}

	clipPath(path, evenOdd, ctm) {
		checkType(path, Path)
		checkMatrix(ctm)
		libmupdf._wasm_clip_path(this, path, evenOdd, MATRIX(ctm))
	}

	clipStrokePath(path, stroke, ctm) {
		checkType(path, Path)
		checkType(stroke, StrokeState)
		checkMatrix(ctm)
		libmupdf._wasm_clip_stroke_path(this, path, stroke, MATRIX(ctm))
	}

	fillText(text, ctm, colorspace, color, alpha) {
		checkType(text, Text)
		checkMatrix(ctm)
		checkType(colorspace, ColorSpace)
		checkColor(color)
		libmupdf._wasm_fill_text(this, text, MATRIX(ctm), colorspace, COLOR(color), alpha)
	}

	strokeText(text, stroke, ctm, colorspace, color, alpha) {
		checkType(text, Text)
		checkType(stroke, StrokeState)
		checkMatrix(ctm)
		checkType(colorspace, ColorSpace)
		checkColor(color)
		libmupdf._wasm_stroke_text(
			this,
			text,
			stroke,
			MATRIX(ctm),
			colorspace,
			COLOR(color),
			alpha
		)
	}

	clipText(text, ctm) {
		checkType(text, Text)
		checkMatrix(ctm)
		libmupdf._wasm_clip_text(this, text, MATRIX(ctm))
	}

	clipStrokeText(text, stroke, ctm) {
		checkType(text, Text)
		checkType(stroke, StrokeState)
		checkMatrix(ctm)
		libmupdf._wasm_clip_stroke_text(this, text, stroke, MATRIX(ctm))
	}

	ignoreText(text, ctm) {
		checkType(text, Text)
		checkMatrix(ctm)
		libmupdf._wasm_ignore_text(this, text, MATRIX(ctm))
	}

	fillShade(shade, ctm, alpha) {
		checkType(shade, Shade)
		checkMatrix(ctm)
		libmupdf._wasm_fill_shade(this, shade, MATRIX(ctm), alpha)
	}

	fillImage(image, ctm, alpha) {
		checkType(image, Image)
		checkMatrix(ctm)
		libmupdf._wasm_fill_image(this, image, MATRIX(ctm), alpha)
	}

	fillImageMask(image, ctm, colorspace, color, alpha) {
		checkType(image, Image)
		checkMatrix(ctm)
		checkType(colorspace, ColorSpace)
		checkColor(color)
		libmupdf._wasm_fill_image_mask(this, image, MATRIX(ctm), colorspace, COLOR(color), alpha)
	}

	clipImageMask(image, ctm) {
		checkType(image, Image)
		checkMatrix(ctm)
		libmupdf._wasm_clip_image_mask(this, image, MATRIX(ctm))
	}

	popClip() {
		libmupdf._wasm_pop_clip(this)
	}

	beginMask(area, luminosity, colorspace, color) {
		checkRect(area)
		checkType(colorspace, ColorSpace)
		checkColor(color)
		libmupdf._wasm_begin_mask(this, RECT(area), luminosity, colorspace, COLOR(color))
	}

	endMask() {
		libmupdf._wasm_end_mask(this)
	}

	beginGroup(area, colorspace, isolated, knockout, blendmode, alpha) {
		checkRect(area)
		checkType(colorspace, ColorSpace)
		blendmode = Device.BLEND_MODES.indexOf(blendmode)
		libmupdf._wasm_begin_group(this, RECT(area), colorspace, isolated, knockout, blendmode, alpha)
	}

	endGroup() {
		libmupdf._wasm_end_group(this)
	}

	beginTile(area, view, xstep, ystep, ctm, id) {
		checkRect(area)
		checkRect(view)
		checkMatrix(ctm)
		return libmupdf._wasm_begin_tile(this, RECT(area), RECT2(view), xstep, ystep, MATRIX(ctm), id)
	}

	endTile() {
		libmupdf._wasm_end_tile(this)
	}

	beginLayer(name) {
		libmupdf._wasm_begin_layer(this, STRING(name))
	}

	endLayer() {
		libmupdf._wasm_end_layer(this)
	}

	close() {
		libmupdf._wasm_close_device(this)
	}
}

class DrawDevice extends Device {
	constructor(matrix, pixmap) {
		checkMatrix(matrix)
		checkType(pixmap, Pixmap)
		super(libmupdf._wasm_new_draw_device(MATRIX(matrix), pixmap))
	}
}

class DisplayListDevice extends Device {
	constructor(displayList) {
		checkType(displayList, DisplayList)
		super(
			libmupdf._wasm_new_list_device(displayList)
		)
	}
}

// === DocumentWriter ===

class DocumentWriter extends Userdata {
	static _drop = "_wasm_drop_document_writer"

	constructor(buffer, format, options) {
		checkType(buffer, Buffer)
		super(
			libmupdf._wasm_new_document_writer_with_buffer(
				buffer,
				STRING(format),
				STRING(options)
			)
		)
	}

	beginPage(mediabox) {
		checkRect(mediabox)
		return new Device(libmupdf._wasm_begin_page(this, RECT(mediabox)))
	}

	endPage() {
		libmupdf._wasm_end_page(this)
	}

	close() {
		libmupdf._wasm_close_document_writer(this)
	}
}

// === Document ===

class Document extends Userdata {
	static _drop = "_wasm_drop_document"

	static META_FORMAT = "format"
	static META_ENCRYPTION = "encryption";
	static META_INFO_AUTHOR = "info:Author";
	static META_INFO_TITLE = "info:Title";
	static META_INFO_SUBJECT = "info:Subject";
	static META_INFO_KEYWORDS = "info:Keywords";
	static META_INFO_CREATOR = "info:Creator";
	static META_INFO_PRODUCER = "info:Producer";
	static META_INFO_CREATIONDATE = "info:CreationDate";
	static META_INFO_MODIFICATIONDATE = "info:ModDate";

	static PERMISSION_PRINT = "p".charCodeAt(0)
	static PERMISSION_COPY = "c".charCodeAt(0)
	static PERMISSION_EDIT = "e".charCodeAt(0)
	static PERMISSION_ANNOTATE = "n".charCodeAt(0)

	static openDocument(from, magic) {
		let pointer = 0

		if (from instanceof ArrayBuffer || from instanceof Uint8Array)
			from = new Buffer(from)
		if (from instanceof Buffer)
			pointer = libmupdf._wasm_open_document_with_buffer(STRING(magic), from)
		else if (from instanceof Stream)
			pointer = libmupdf._wasm_open_document_with_stream(STRING(magic), from)
		else
			throw new Error("not a Buffer or Stream")

		let pdf_ptr = libmupdf._wasm_pdf_document_from_fz_document(pointer)
		if (pdf_ptr)
			return new PDFDocument(pointer)
		return new Document(pointer)
	}

	isPDF() {
		return false
	}

	needsPassword() {
		return libmupdf._wasm_needs_password(this)
	}

	authenticatePassword(password) {
		return libmupdf._wasm_authenticate_password(this, STRING(password))
	}

	hasPermission(flag) {
		if (typeof flag === "string") {
			switch (flag) {
				case "print":
					flag = Document.PERMISSION_PRINT
					break
				case "annotatate":
					flag = Document.PERMISSION_ANNOTATE
					break
				case "edit":
					flag = Document.PERMISSION_EDIT
					break
				case "copy":
					flag = Document.PERMISSION_COPY
					break
				default:
					throw new Error("invalid permission name")
			}
		}
		return libmupdf._wasm_has_permission(this, flag)
	}

	getMetaData(key) {
		let value = libmupdf._wasm_lookup_metadata(this, STRING(key))
		if (value)
			return fromString(value)
		return undefined
	}

	setMetaData(key, value) {
		key = allocateUTF8(key)
		value = allocateUTF8(value)
		try {
			libmupdf._wasm_set_metadata(this, key, value)
		} finally {
			libmupdf._wasm_free(value)
			libmupdf._wasm_free(key)
		}
	}

	countPages() {
		return libmupdf._wasm_count_pages(this)
	}

	isReflowable() {
		// TODO: No HTML/EPUB support in WASM.
		return false
	}

	layout(w, h, em) {
		libmupdf._wasm_layout_document(this, w, h, em)
	}

	loadPage(index) {
		let fz_ptr = libmupdf._wasm_load_page(this, index)
		let pdf_ptr = libmupdf._wasm_pdf_page_from_fz_page(fz_ptr)
		if (pdf_ptr)
			return new PDFPage(pdf_ptr)
		return new Page(fz_ptr)
	}

	loadOutline() {
		let doc = this
		function to_outline(outline) {
			let result = []
			while (outline) {
				let item = {}

				let title = libmupdf._wasm_outline_get_title(outline)
				if (title)
					item.title = fromString(title)

				let uri = libmupdf._wasm_outline_get_uri(outline)
				if (uri)
					item.uri = fromString(uri)

				let page = libmupdf._wasm_outline_get_page(doc, outline)
				if (page >= 0)
					item.page = page

				let down = libmupdf._wasm_outline_get_down(outline)
				if (down)
					item.down = to_outline(down)

				result.push(item)

				outline = libmupdf._wasm_outline_get_next(outline)
			}
			return result
		}
		let root = libmupdf._wasm_load_outline(this)
		if (root)
			return to_outline(root)
		return null
	}

	resolveLink(link) {
		if (link instanceof Link) {
			return libmupdf._wasm_resolve_link(this, libmupdf._wasm_link_get_uri(link))
		}
		return libmupdf._wasm_resolve_link(this, STRING(link))
	}
}

class Link extends Userdata {
	static _drop = "_wasm_drop_link"

	getBounds() {
		return fromRect(libmupdf._wasm_link_get_rect(this))
	}

	getURI() {
		return fromString(libmupdf._wasm_link_get_uri(this))
	}

	isExternal() {
		return /^\w[\w+-.]*:/.test(this.getURI())
	}
}

class Page extends Userdata {
	static _drop = "_wasm_drop_page"

	isPDF() {
		return false
	}

	getBounds() {
		return fromRect(libmupdf._wasm_bound_page(this))
	}

	getLabel() {
		return fromString(libmupdf._wasm_page_label(this))
	}

	run(device, matrix) {
		checkType(device, Device)
		checkMatrix(matrix)
		libmupdf._wasm_run_page(this, device, MATRIX(matrix))
	}

	runPageContents(device, matrix) {
		checkType(device, Device)
		checkMatrix(matrix)
		libmupdf._wasm_run_page_contents(this, device, MATRIX(matrix))
	}

	runPageAnnots(device, matrix) {
		checkType(device, Device)
		checkMatrix(matrix)
		libmupdf._wasm_run_page_annots(this, device, MATRIX(matrix))
	}

	runPageWidgets(device, matrix) {
		checkType(device, Device)
		checkMatrix(matrix)
		libmupdf._wasm_run_page_widgets(this, device, MATRIX(matrix))
	}

	toPixmap(matrix, colorspace, alpha = false, showExtras = true) {
		checkType(colorspace, ColorSpace)
		checkMatrix(matrix)
		let result
		if (showExtras)
			result = libmupdf._wasm_new_pixmap_from_page(this,
				MATRIX(matrix),
				colorspace,
				alpha)
		else
			result = libmupdf._wasm_new_pixmap_from_page_contents(this,
				MATRIX(matrix),
				colorspace,
				alpha)
		return new Pixmap(result)
	}

	toDisplayList(showExtras = true) {
		let result
		if (showExtras)
			result = libmupdf._wasm_new_display_list_from_page(this)
		else
			result = libmupdf._wasm_new_display_list_from_page_contents(this)
		return new DisplayList(result)
	}

	toStructuredText(options) {
		// TODO: parse options
		return new StructuredText(libmupdf._wasm_new_stext_page_from_page(this))
	}

	getLinks() {
		let links = []
		let link = libmupdf._wasm_load_links(this)
		while (link) {
			links.push(new Link(libmupdf._wasm_keep_link(link)))
			link = libmupdf._wasm_link_get_next(link)
		}
		return links
	}

	search(needle, max_hits = 500) {
		checkType(needle, "string")
		let hits = 0
		let marks = 0
		try {
			hits = libmupdf._wasm_malloc(32 * max_hits)
			marks = libmupdf._wasm_malloc(4 * max_hits)
			let n = libmupdf._wasm_search_page(this, STRING(needle), marks, hits, max_hits)
			let outer = []
			if (n > 0) {
				let inner = []
				for (let i = 0; i < n; ++i) {
					let mark = libmupdf.HEAP32[(marks>>2) + i]
					let quad = fromQuad(hits + i * 32)
					if (i > 0 && mark) {
						outer.push(inner)
						inner = []
					}
					inner.push(quad)
				}
				outer.push(inner)
			}
			return outer
		} finally {
			libmupdf._wasm_free(marks)
			libmupdf._wasm_free(hits)
		}
	}
}

// === PDFDocument ===

class PDFDocument extends Document {
	constructor(pointer) {
		if (!pointer)
			pointer = libmupdf._wasm_pdf_create_document()
		super(pointer)
	}

	isPDF() {
		return true
	}

	getVersion() {
		return libmupdf._wasm_pdf_version(this)
	}

	getLanguage() {
		return fromString(libmupdf._wasm_pdf_document_language(this))
	}

	setLanguage(lang) {
		libmupdf._wasm_pdf_set_document_language(this, STRING(lang))
	}

	countObjects() {
		return libmupdf._wasm_pdf_xref_len(this)
	}

	getTrailer() {
		return new PDFObject(libmupdf._wasm_pdf_trailer(this))
	}

	createObject() {
		let num = libmupdf._wasm_pdf_create_object(this)
		return fromPDFObject(libmupdf._wasm_pdf_new_indirect(this, num))
	}

	newNull() { return PDFObject.Null }
	newBool(v) { return fromPDFObject(libmupdf._wasm_pdf_new_bool(v)) }
	newInteger(v) { return fromPDFObject(libmupdf._wasm_pdf_new_int(v)) }
	newReal(v) { return fromPDFObject(libmupdf._wasm_pdf_new_real(v)) }
	newName(v) { return fromPDFObject(libmupdf._wasm_pdf_new_name(v)) }
	newString(v) { return fromPDFObject(libmupdf._wasm_pdf_new_text_string(v)) }

	newIndirect(v) { return fromPDFObject(libmupdf._wasm_pdf_new_indirect(this, v)) }
	newArray(cap=8) { return fromPDFObject(libmupdf._wasm_pdf_new_array(this, cap)) }
	newDictionary(cap=8) { return fromPDFObject(libmupdf._wasm_pdf_new_dict(this, cap)) }

	deleteObject(num) {
		if (num instanceof PDFObject)
			num = num.asIndirect()
		else
			checkType(num, "number")
		libmupdf._wasm_pdf_delete_object(this, num)
	}

	addObject(obj) {
		obj = PDFOBJ(obj)
		return fromPDFObject(libmupdf._wasm_pdf_add_object(this, obj))
	}

	addStream(buf, obj) {
		obj = PDFOBJ(obj)
		checkType(buf, Buffer)
		libmupdf._wasm_pdf_add_stream(this, buf, obj, 0)
	}

	addRawStream(buf, obj) {
		obj = PDFOBJ(obj)
		checkType(buf, Buffer)
		libmupdf._wasm_pdf_add_stream(this, buf, obj, 1)
	}

	addSimpleFont(font, encoding) {
		checkType(font, Font)
		checkType(encoding, "string")
		if (encoding === "Latin" || encoding === "Latn") encoding = 0
		else if (encoding === "Greek" || encoding === "Grek") encoding = 1
		else if (encoding === "Cyrillic" || encoding === "Cyrl") encoding = 2
		else encoding = 0
		return fromPDFObject(libmupdf._wasm_pdf_add_simple_font(this, font, encoding))
	}

	addCJKFont(font, lang, wmode, serif) {
		checkType(font, Font)
		if (typeof lang === "string")
			lang = Font.CJK_ORDERING_BY_LANG[lang]
		return fromPDFObject(libmupdf._wasm_pdf_add_cjk_font(this, font, lang, wmode, serif))
	}

	addFont(font) {
		checkType(font, Font)
		return fromPDFObject(libmupdf._wasm_pdf_add_font(this, font))
	}

	addImage(image) {
		checkType(image, Image)
		return fromPDFObject(libmupdf._wasm_pdf_add_image(this, image))
	}

	loadImage(ref) {
		checkType(ref, PDFObject)
		return new Image(libmupdf._wasm_pdf_load_image(this, ref))
	}

	findPage(index) {
		checkType(index, "number")
		return fromPDFObject(libmupdf._wasm_pdf_lookup_page_obj(this, index))
	}

	addPage(mediabox, rotate, resources, contents) {
		resources = PDFOBJ(resources)
		checkRect(mediabox)
		checkType(rotate, "number")
		checkType(contents, Buffer)
		return fromPDFObject(
			libmupdf._wasm_pdf_add_page(
				this,
				RECT(mediabox),
				resources,
				contents
			)
		)
	}

	insertPage(at, obj) {
		obj = PDFOBJ(obj)
		checkType(at, "number")
		libmupdf._wasm_pdf_insert_page(this, at, obj)
	}

	deletePage(at) {
		checkType(at, "number")
		libmupdf._wasm_pdf_delete_page(this, at)
	}

	isEmbeddedFile(ref) {
		checkType(ref, PDFObject)
		return libmupdf._wasm_pdf_is_embedded_file(ref)
	}

	addEmbeddedFile(filename, mimetype, contents, created, modified, checksum = false) {
		checkType(filename, "string")
		checkType(mimetype, "string")
		checkType(contents, Buffer)
		checkType(created, Date)
		checkType(modified, Date)
		checkType(checksum, "boolean")
		return fromPDFObject(
			libmupdf._wasm_pdf_add_embedded_file(
				this,
				STRING(filename),
				STRING2(mimetype),
				created.getTime() / 1000 | 0,
				modified.getTime() / 1000 | 0,
				checksum
			)
		)
	}

	getEmbeddedFileParams(ref) {
		checkType(ref, PDFObject)
		let ptr = libmupdf._wasm_pdf_get_embedded_file_params(ref)
		return {
			filename:
				fromString(libmupdf._wasm_pdf_get_embedded_file_params_filename(ptr)),
			mimetype:
				fromString(libmupdf._wasm_pdf_get_embedded_file_params_mimetype(ptr)),
			size:
				libmupdf._wasm_pdf_get_embedded_file_params_filename(ptr),
			creationDate:
				new Date(libmupdf._wasm_pdf_get_embedded_file_params_created(ptr) * 1000),
			modificationDate:
				new Date(libmupdf._wasm_pdf_get_embedded_file_params_modified(ptr) * 1000),
		}
	}

	getEmbeddedFileContents(ref) {
		checkType(ref, PDFObject)
		let contents = libmupdf._wasm_pdf_load_embedded_file_contents(ref)
		if (contents)
			return new Buffer(contents)
		return null
	}

	saveToBuffer(options) {
		// TODO: object options to string options?
		return new Buffer(libmupdf._wasm_pdf_write_document_buffer(this, STRING(options)))
	}

	static PAGE_LABEL_NONE = "\0"
	static PAGE_LABEL_DECIMAL = "D"
	static PAGE_LABEL_ROMAN_UC = "R"
	static PAGE_LABEL_ROMAN_LC = "r"
	static PAGE_LABEL_ALPHA_UC = "A"
	static PAGE_LABEL_ALPHA_LC = "a"

	setPageLabels(index, style = "D", prefix = "", start = 1) {
		libmupdf._wasm_pdf_set_page_labels(this, index, style.charCodeAt(0), STRING(prefix), start)
	}

	deletePageLabels(index) {
		libmupdf._wasm_pdf_delete_page_labels(this, index)
	}

	wasRepaired() {
		return libmupdf._wasm_pdf_was_repaired(this)
	}

	hasUnsavedChanges() {
		return libmupdf._wasm_pdf_has_unsaved_changes(this)
	}

	countVersions() {
		return libmupdf._wasm_pdf_count_versions(this)
	}

	countUnsavedVersions() {
		return libmupdf._wasm_pdf_count_unsaved_versions(this)
	}

	validateChangeHistory() {
		return libmupdf._wasm_pdf_validate_change_history(this)
	}

	canBeSavedIncrementally() {
		return libmupdf._wasm_pdf_can_be_saved_incrementally(this)
	}

	enableJournal() {
		libmupdf._wasm_pdf_enable_journal(this)
	}

	getJournal() {
		let position = libmupdf._wasm_pdf_undoredo_state_position(this)
		let n = libmupdf._wasm_pdf_undoredo_state_count(this)
		let steps = []
		for (let i = 0; i < n; ++i)
			steps.push(
				fromString(
					libmupdf._wasm_pdf_undoredo_step(this, i),
				)
			)
		return { position, steps }
	}

	beginOperation(op) {
		libmupdf._wasm_pdf_begin_operation(this, STRING(op))
	}

	beginImplicitOperation() {
		libmupdf._wasm_pdf_begin_implicit_operation(this)
	}

	endOperation() {
		libmupdf._wasm_pdf_end_operation(this)
	}

	canUndo() {
		return libmupdf._wasm_pdf_can_undo(this)
	}

	canRedo() {
		return libmupdf._wasm_pdf_can_redo(this)
	}

	undo() {
		libmupdf._wasm_pdf_undo(this)
	}

	redo() {
		libmupdf._wasm_pdf_redo(this)
	}
}

class PDFPage extends Page {
	constructor(pointer) {
		super(pointer)
		this._annots = null
	}

	isPDF() {
		return true
	}

	getWidgets() {
		let list = []
		let widget = libmupdf._wasm_pdf_first_widget(this)
		while (widget) {
			list.push(new PDFWidget(libmupdf._wasm_pdf_keep_annot(widget)))
			widget = libmupdf._wasm_pdf_next_widget(widget)
		}
		return list
	}

	getAnnotations() {
		if (!this._annots) {
			this._annots = []
			let annot = libmupdf._wasm_pdf_first_annot(this)
			while (annot) {
				this._annots.push(new PDFAnnotation(libmupdf._wasm_pdf_keep_annot(annot)))
				annot = libmupdf._wasm_pdf_next_annot(annot)
			}
		}
		return this._annots
	}

	createAnnotation(type) {
		if (typeof type === "string")
			type = PDFAnnotation.TYPES.indexOf(type)
		let annot = new PDFAnnotation(libmupdf._wasm_pdf_create_annot(this, type))
		if (this._annots)
			this._annots.push(annot)
		return annot
	}

	deleteAnnotation(annot) {
		checkType(annot, PDFAnnotation)
		libmupdf._wasm_pdf_delete_annot(this, annot)
		if (this._annots) {
			let ix = this._annots.indexOf(annot)
			if (ix >= 0)
				this._annots.splice(ix, 1)
		}
	}

	static REDACT_IMAGE_NONE = 0
	static REDACT_IMAGE_REMOVE = 1
	static REDACT_IMAGE_PIXELS = 2

	applyRedactions(black_boxes = 1, image_method = 2) {
		libmupdf._wasm_pdf_redact_page(this, black_boxes, image_method)
	}

	update() {
		return !!libmupdf._wasm_pdf_update_page(this)
	}

	createLink(bbox, uri) {
		checkRect(bbox)
		return new Link(libmupdf._wasm_pdf_create_link(this, RECT(bbox), STRING(uri)))
	}
}

function fromPDFObject(ptr) {
	if (ptr === 0)
		return PDFObject.Null
	return new PDFObject(ptr)
}

function keepPDFObject(ptr) {
	return new PDFObject(libmupdf._wasm_pdf_keep_obj(ptr))
}

function PDFOBJ(doc, obj) {
	if (obj instanceof PDFObject)
		return obj
	if (obj === null || obj === undefined)
		return doc.newNull()
	if (typeof obj === "string")
		return doc.newString(obj)
	if (typeof obj === "number")
		return obj | (0 === obj) ? doc.newInteger(obj) : doc.newReal(obj)
	if (typeof obj === "boolean")
		return doc.newBool(obj)
	if (obj instanceof Array) {
		let result = doc.newArray(obj.length)
		for (let item of obj)
			result.push(PDFOBJ(item))
		return result
	}
	if (obj instanceof Object) {
		let result = doc.newDictionary()
		for (let key in obj)
			result.put(key, PDFOBJ(obj[key]))
		return result
	}
	throw new TypeError("cannot convert value to PDFObject")
}

class PDFObject extends Userdata {
	static _drop = "_wasm_pdf_drop_obj"

	constructor(pointer) {
		super(libmupdf._wasm_pdf_keep_obj(pointer))
	}

	isNull() { return this === PDFObject.Null }
	isIndirect() { return libmupdf._wasm_pdf_is_indirect(this) }
	isBoolean() { return libmupdf._wasm_pdf_is_bool(this) }
	isInteger() { return libmupdf._wasm_pdf_is_int(this) }
	isNumber() { return libmupdf._wasm_pdf_is_number(this) }
	isName() { return libmupdf._wasm_pdf_is_name(this) }
	isString() { return libmupdf._wasm_pdf_is_string(this) }
	isArray() { return libmupdf._wasm_pdf_is_array(this) }
	isDictionary() { return libmupdf._wasm_pdf_is_dict(this) }
	isStream() { return libmupdf._wasm_pdf_is_stream(this) }

	asIndirect() { return libmupdf._wasm_pdf_to_num(this) }
	asBoolean() { return libmupdf._wasm_pdf_to_bool(this) }
	asNumber() { return libmupdf._wasm_pdf_to_number(this) }
	asName() { return fromString(libmupdf._wasm_pdf_to_name(this)) }
	asString() { return fromString(libmupdf._wasm_pdf_to_text_string(this)) }

	readStream() { return new Buffer(libmupdf._wasm_pdf_load_stream(this)) }
	readRawStream() { return new Buffer(libmupdf._wasm_pdf_load_raw_stream(this)) }

	resolve() {
		return fromPDFObject(libmupdf._wasm_pdf_resolve_indirect(this))
	}

	get length() {
		return libmupdf._wasm_pdf_array_len(this)
	}

	_get(path) {
		let obj = this.pointer
		for (let key of path) {
			if (typeof key === "number")
				obj = libmupdf._wasm_pdf_array_get(obj, key)
			else if (typeof key === PDFObject)
				obj = libmupdf._wasm_pdf_dict_get(obj, key.pointer)
			else
				obj = libmupdf._wasm_pdf_dict_gets(obj, STRING(key))
			if (obj === 0)
				break
		}
		return obj
	}

	get(...path) { return fromPDFObject(this._get(path)) }
	getIndirect(...path) { return libmupdf._wasm_pdf_to_num(this._get(path)) }
	getBoolean(...path) { return libmupdf._wasm_pdf_to_bool(this._get(path)) }
	getNumber(...path) { return libmupdf._wasm_pdf_to_number(this._get(path)) }
	getName(...path) { return fromString(libmupdf._wasm_pdf_to_name(this._get(path))) }
	getString(...path) { return fromString(libmupdf._wasm_pdf_to_text_string(this._get(path))) }

	put(key, value) {
		value = PDFOBJ(value)
		if (typeof key === "number")
			libmupdf._wasm_pdf_array_put(this, key, value)
		else if (typeof key === PDFObject)
			libmupdf._wasm_pdf_dict_put(this, key, value)
		else
			libmupdf._wasm_pdf_dict_puts(this, STRING(key), value)
	}

	push(value) {
		value = PDFOBJ(value)
		libmupdf._wasm_pdf_array_push(this, value)
	}

	delete(key) {
		if (typeof key === "number")
			libmupdf._wasm_pdf_array_delete(this, key)
		else if (typeof key === PDFObject)
			libmupdf._wasm_pdf_dict_del(this, key)
		else
			libmupdf._wasm_pdf_dict_dels(this, STRING(key))
	}

	asPrimitive() {
		if (this.isNull()) return null
		if (this.isBoolean()) return this.asBoolean()
		if (this.isNumber()) return this.asNumber()
		if (this.isName()) return this.asName()
		if (this.isString()) return this.asString()
		if (this.isIndirect()) return "R"
		return this
	}

	toString(tight = true, ascii = true) {
		return fromStringFree(libmupdf._wasm_pdf_sprint_obj(this, tight, ascii))
	}
}

class PDFAnnotation extends Userdata {
	static _drop = "_wasm_pdf_drop_annot"

	/* IMPORTANT: Keep in sync with mupdf/pdf/annot.h and PDFAnnotation.java */
	static TYPES = [
		"Text",
		"Link",
		"FreeText",
		"Line",
		"Square",
		"Circle",
		"Polygon",
		"PolyLine",
		"Highlight",
		"Underline",
		"Squiggly",
		"StrikeOut",
		"Redact",
		"Stamp",
		"Caret",
		"Ink",
		"Popup",
		"FileAttachment",
		"Sound",
		"Movie",
		"RichMedia",
		"Widget",
		"Screen",
		"PrinterMark",
		"TrapNet",
		"Watermark",
		"3D",
		"Projection",
	]

        static LINE_ENDING_NONE = 0
        static LINE_ENDING_SQUARE = 1
        static LINE_ENDING_CIRCLE = 2
        static LINE_ENDING_DIAMOND = 3
        static LINE_ENDING_OPEN_ARROW = 4
        static LINE_ENDING_CLOSED_ARROW = 5
        static LINE_ENDING_BUTT = 6
        static LINE_ENDING_R_OPEN_ARROW = 7
        static LINE_ENDING_R_CLOSED_ARROW = 8
        static LINE_ENDING_SLASH = 9

        static BORDER_STYLE_SOLID = 0
        static BORDER_STYLE_DASHED = 1
        static BORDER_STYLE_BEVELED = 2
        static BORDER_STYLE_INSET = 3
        static BORDER_STYLE_UNDERLINE = 4

        static BORDER_EFFECT_NONE = 0
        static BORDER_EFFECT_CLOUDY = 1

        static IS_INVISIBLE = 1 << (1-1)
        static IS_HIDDEN = 1 << (2-1)
        static IS_PRINT = 1 << (3-1)
        static IS_NO_ZOOM = 1 << (4-1)
        static IS_NO_ROTATE = 1 << (5-1)
        static IS_NO_VIEW = 1 << (6-1)
        static IS_READ_ONLY = 1 << (7-1)
        static IS_LOCKED = 1 << (8-1)
        static IS_TOGGLE_NO_VIEW = 1 << (9-1)
        static IS_LOCKED_CONTENTS = 1 << (10-1)

	getObject() {
		return keepPDFObject(libmupdf._wasm_pdf_annot_obj(this))
	}

	getBounds() {
		return fromRect(libmupdf._wasm_pdf_bound_annot(this))
	}

	run(device, matrix) {
		checkType(device, Device)
		checkMatrix(matrix)
		libmupdf._wasm_pdf_run_annot(this, device, MATRIX(matrix))
	}

	toPixmap(matrix, colorspace, alpha = false) {
		checkMatrix(matrix)
		checkType(colorspace, ColorSpace)
		return new Pixmap(
			libmupdf._wasm_pdf_new_pixmap_from_annot(
				this,
				MATRIX(matrix),
				colorspace,
				alpha)
		)
	}

	toDisplayList() {
		return new DisplayList(libmupdf._wasm_pdf_new_display_list_from_annot(this))
	}

	update() {
		return !!libmupdf._wasm_pdf_update_annot(this)
	}

	getType() {
		let type = libmupdf._wasm_pdf_annot_type(this)
		return PDFAnnotation.TYPES[type]
	}

	getLanguage() {
		return fromString(libmupdf._wasm_pdf_annot_language(this))
	}

	setLanguage(lang) {
		libmupdf._wasm_pdf_set_annot_language(this, STRING(lang))
	}

	getFlags() {
		return libmupdf._wasm_pdf_annot_flags(this)
	}

	setFlags(flags) {
		return libmupdf._wasm_pdf_set_annot_flags(this, flags)
	}

	getContents() {
		return fromString(libmupdf._wasm_pdf_annot_contents(this))
	}

	setContents(text) {
		libmupdf._wasm_pdf_set_annot_contents(this, STRING(text))
	}

	getAuthor() {
		return fromString(libmupdf._wasm_pdf_annot_author(this))
	}

	setAuthor(text) {
		libmupdf._wasm_pdf_set_annot_author(this, STRING(text))
	}

	getCreationDate() {
		return new Date(libmupdf._wasm_pdf_annot_creation_date(this) * 1000)
	}

	setCreationDate(date) {
		checkType(date, Date)
		return new Date(libmupdf._wasm_pdf_annot_creation_date(this, date.getTime() / 1000))
	}

	getModificationDate() {
		return new Date(libmupdf._wasm_pdf_annot_modification_date(this) * 1000)
	}

	setModificationDate(date) {
		checkType(date, Date)
		return new Date(libmupdf._wasm_pdf_annot_modification_date(this, date.getTime() / 1000))
	}

	getRect() {
		return fromRect(libmupdf._wasm_pdf_annot_rect(this))
	}

	setRect(rect) {
		checkRect(rect)
		return fromRect(libmupdf._wasm_pdf_set_annot_rect(this, RECT(rect)))
	}

	getPopup() {
		return fromRect(libmupdf._wasm_pdf_annot_popup(this))
	}

	setPopup(rect) {
		checkType(rect)
		libmupdf._wasm_pdf_set_annot_popup(this, RECT(rect))
	}

	// TODO: rename to getIsOpen ?
	isOpen() {
		return libmupdf._wasm_pdf_annot_is_open(this)
	}

	setIsOpen(isOpen) {
		return libmupdf._wasm_pdf_annot_set_is_open(this, isOpen)
	}

	getIcon() {
		return fromString(libmupdf._wasm_pdf_annot_icon_name(this))
	}

	setIcon(text) {
		libmupdf._wasm_pdf_set_annot_icon_name(this, STRING(text))
	}

	getOpacity() {
		return libmupdf._wasm_pdf_annot_opacity(this)
	}

	setOpacity(opacity) {
		libmupdf._wasm_pdf_set_annot_opacity(this, opacity)
	}

	getQuadding() {
		return libmupdf._wasm_pdf_annot_quadding(this)
	}

	setQuadding(quadding) {
		return libmupdf._wasm_pdf_set_annot_quadding(this, quadding)
	}

	getFileSpec() {
		return keepPDFObject(libmupdf._wasm_pdf_annot_filespec(this))
	}

	setFileSpec(fs) {
		fs = PDFOBJ(fs)
		return libmupdf._wasm_pdf_set_annot_filespec(this, fs)
	}

	getQuadPoints() {
		let n = libmupdf._wasm_pdf_annot_quad_point_count(this)
		let result = []
		for (let i = 0; i < n; ++i)
			result.push(fromQuad(libmupdf._wasm_pdf_annot_quad_point(this, i)))
		return result
	}

	clearQuadPoints() {
		libmupdf._wasm_pdf_annot_clear_quad_points(this)
	}

	addQuadPoint(quad) {
		checkQuad(quad)
		libmupdf._wasm_pdf_annot_add_quad_point(this, QUAD(quad))
	}

	setQuadPoints(quadlist) {
		this.clearQuadPoints()
		for (let quad of quadlist)
			this.addQuadPoint(quad)
	}

	getVertices() {
		let n = libmupdf._wasm_pdf_annot_vertex_count(this)
		let result = new Array(n)
		for (let i = 0; i < n; ++i)
			result[i] = fromPoint(libmupdf._wasm_pdf_annot_vertex(this, i))
		return result
	}

	clearVertices() {
		libmupdf._wasm_pdf_annot_clear_vertices(this)
	}

	addVertex(vertex) {
		checkPoint(vertex)
		libmupdf._wasm_pdf_annot_add_vertex(this, POINT(vertex))
	}

	setVertices(vertexlist) {
		this.clearVertices()
		for (let vertex of vertexlist)
			this.addVertex(vertex)
	}

	getInkList() {
		let n = libmupdf._wasm_pdf_annot_ink_list_count(this)
		let result = new Array(n)
		for (let i = 0; i < n; ++i) {
			let m = libmupdf._wasm_pdf_annot_ink_list_stroke_count(this, i)
			result[i] = new Array(m)
			for (let k = 0; k < m; ++k)
				result[i][k] = fromPoint(libmupdf._wasm_pdf_annot_ink_list_stroke_vertex(this, i, k))
		}
		return result
	}

	clearInkList() {
		libmupdf._wasm_pdf_annot_clear_ink_list(this)
	}

	addInkListStroke() {
		libmupdf._wasm_pdf_annot_add_ink_list_stroke(this)
	}

	addInkListStrokeVertex(v) {
		checkPoint(v)
		libmupdf._wasm_pdf_annot_add_ink_list_stroke_vertex(this, POINT(v))
	}

	setInkList(inklist) {
		this.clearInkList()
		for (let stroke of inklist) {
			this.addInkListStroke()
			for (let vertex of stroke)
				this.addInkListStrokeVertex(vertex)
		}
	}

	// TODO: line ending styles
	// TODO: color
	// TODO: interior_color
	// TODO: border dash
	// TODO: get default appearance

	setDefaultAppearance(fontName, size, color) {
		checkType(fontName, "string")
		checkType(size, "number")
		checkColor(color)
		libmupdf._wasm_pdf_set_annot_default_appearance(STRING(fontName), size, color.length, COLOR(color))
	}
}

class PDFWidget extends PDFAnnotation {
	/* IMPORTANT: Keep in sync with mupdf/pdf/widget.h and PDFWidget.java */
	static TYPES = [
		"button",
		"button",
		"checkbox",
		"combobox",
		"listbox",
		"radiobutton",
		"signature",
		"text",
	]

	/* Field flags */
	static FIELD_IS_READ_ONLY = 1;
	static FIELD_IS_REQUIRED = 1 << 1;
	static FIELD_IS_NO_EXPORT = 1 << 2;

	/* Text fields */
	static TX_FIELD_IS_MULTILINE = 1 << 12;
	static TX_FIELD_IS_PASSWORD = 1 << 13;
	static TX_FIELD_IS_COMB = 1 << 24;

	/* Button fields */
	static BTN_FIELD_IS_NO_TOGGLE_TO_OFF = 1 << 14;
	static BTN_FIELD_IS_RADIO = 1 << 15;
	static BTN_FIELD_IS_PUSHBUTTON = 1 << 16;

	/* Choice fields */
	static CH_FIELD_IS_COMBO = 1 << 17;
	static CH_FIELD_IS_EDIT = 1 << 18;
	static CH_FIELD_IS_SORT = 1 << 19;
	static CH_FIELD_IS_MULTI_SELECT = 1 << 21;

	getFieldType() {
		return PDFWidget.TYPES(libmupdf._wasm_pdf_annot_field_type(this))
	}

	isButton() {
		let type = this.getFieldType()
		return type === "button" || type === "checkbox" || type === "radiobutton"
	}

	isPushButton() {
		return this.getFieldType() === "button"
	}

	isCheckbox() {
		return this.getFieldType() === "checkbox"
	}

	isRadioButton() {
		return this.getFieldType() === "radiobutton"
	}

	isText() {
		return this.getFieldType() === "text"
	}

	isChoice() {
		let type = this.getFieldType()
		return type === "combobox" || type === "listbox"
	}

	isListBox() {
		return this.getFieldType() === "listbox"
	}

	isComboBox() {
		return this.getFieldType() === "combobox"
	}

	getFieldFlags() {
		return libmupdf._wasm_pdf_annot_field_flags(this)
	}

	isMultiline() {
		return (this.getFieldFlags() & PDFWidget.TX_FIELD_IS_MULTILINE) !== 0
	}

	isPassword() {
		return (this.getFieldFlags() & PDFWidget.TX_FIELD_IS_PASSWORD) !== 0
	}

	isComb() {
		return (this.getFieldFlags() & PDFWidget.TX_FIELD_IS_COMB) !== 0
	}

	isReadOnly() {
		return (this.getFieldFlags() & PDFWidget.FIELD_IS_READ_ONLY) !== 0
	}

	getLabel() {
		return fromString(libmupdf._wasm_pdf_annot_field_label(this))
	}

	getName() {
		let ptr = libmupdf._wasm_pdf_load_field_name(this)
		let str = fromString(ptr)
		libmupdf._wasm_free(ptr)
		return str
	}

	getValue() {
		return fromString(libmupdf._wasm_pdf_annot_field_value(this))
	}

	setTextValue(value) {
		return libmupdf._wasm_pdf_set_annot_text_field_value(this, STRING(value))
	}

	getMaxLen() {
		return libmupdf._wasm_pdf_annot_text_widget_max_len(this)
	}

	setChoiceValue(value) {
		return libmupdf._wasm_pdf_set_annot_choice_field_value(this, STRING(value))
	}

	getOptions(isExport=false) {
		let result = []
		let n = libmupdf._wasm_pdf_annot_choice_field_option_count(this)
		for (let i = 0; i < n; ++i) {
			result.push(
				fromString(
					libmupdf._wasm_pdf_annot_choice_field_option(this, isExport, i)
				)
			)
		}
	}

	toggle() {
		libmupdf._wasm_pdf_toggle_widget(this)
	}

	// Interactive Text Widget editing in a GUI.
	// TODO: getEditingState()
	// TODO: setEditingState()
	// TODO: clearEditingState()
	// TODO: layoutTextWidget()

	// Interactive form validation Javascript triggers.
	// NOTE: No embedded PDF Javascript engine in WASM build.
	// TODO: eventEnter()
	// TODO: eventExit()
	// TODO: eventDown()
	// TODO: eventUp()
	// TODO: eventFocus()
	// TODO: eventBlur()

	// NOTE: No OpenSSL support in WASM build.
	// TODO: isSigned()
	// TODO: validateSignature()
	// TODO: checkCertificate()
	// TODO: checkDigest()
	// TODO: getSignature()
	// TODO: previewSignature()
	// TODO: clearSignature()
	// TODO: sign()
}

// Background progressive fetch

class TryLaterError extends Error {
	constructor(message) {
		super(message)
		this.name = "TryLaterError"
	}
}

class Stream extends Userdata {
	static _drop = "_wasm_drop_stream"
	constructor(url, contentLength, block_size, prefetch) {
		super(libmupdf._wasm_open_stream_from_url(STRING(url), contentLength, block_size, prefetch))
	}
}

// TODO - move in Stream
function onFetchData(id, block, data) {
	let n = data.byteLength
	let p = libmupdf._wasm_malloc(n)
	libmupdf.HEAPU8.set(new Uint8Array(data), p)
	libmupdf._wasm_on_data_fetched(id, block, p, n)
	libmupdf._wasm_free(p)
}

// TODO - replace with map
let fetchStates = {}

function fetchOpen(id, url, contentLength, blockShift, prefetch) {
	console.log("OPEN", url, "PROGRESSIVELY")
	fetchStates[id] = {
		url: url,
		blockShift: blockShift,
		blockSize: 1 << blockShift,
		prefetch: prefetch,
		contentLength: contentLength,
		map: new Array((contentLength >>> blockShift) + 1).fill(0),
		closed: false,
	}
}

async function fetchRead(id, block) {
	let state = fetchStates[id]

	if (state.map[block] > 0)
		return

	state.map[block] = 1
	let contentLength = state.contentLength
	let url = state.url
	let start = block << state.blockShift
	let end = start + state.blockSize
	if (end > contentLength)
		end = contentLength

	try {
		let response = await fetch(url, { headers: { Range: `bytes=${start}-${end - 1}` } })
		if (state.closed)
			return

		// TODO - use ReadableStream instead?
		let buffer = await response.arrayBuffer()
		if (state.closed)
			return

		console.log("READ", url, block + 1, "/", state.map.length)
		state.map[block] = 2

		onFetchData(id, block, buffer)

		onFetchCompleted(id)

		// TODO - Does this create a risk of stack overflow?
		if (state.prefetch)
			fetchReadNext(id, block + 1)
	} catch (error) {
		state.map[block] = 0
		console.log("FETCH ERROR", url, block, error.toString)
	}
}

function fetchReadNext(id, next) {
	let state = fetchStates[id]
	if (!state)
		return

	// Don't prefetch if we're already waiting for any blocks.
	for (let block = 0; block < state.map.length; ++block)
		if (state.map[block] === 1)
			return

	// Find next block to prefetch (starting with the last fetched block)
	for (let block = next; block < state.map.length; ++block)
		if (state.map[block] === 0)
			return fetchRead(id, block)

	// Find next block to prefetch (starting from the beginning)
	for (let block = 0; block < state.map.length; ++block)
		if (state.map[block] === 0)
			return fetchRead(id, block)

	console.log("ALL BLOCKS READ")
}

function fetchClose(id) {
	fetchStates[id].closed = true
	delete fetchStates[id]
}

// --- EXPORTS ---

const mupdf = {
	Matrix,
	Rect,
	Buffer,
	ColorSpace,
	Font,
	StrokeState,
	Image,
	Path,
	Text,
	Pixmap,
	DisplayList,
	DrawDevice,
	DisplayListDevice,
	Document,
	DocumentWriter,
	PDFDocument,
	PDFAnnotation,
	PDFPage,
	PDFObject,
	TryLaterError,
	Stream,
	onFetchCompleted: () => {},
}

// TODO - Figure out better naming scheme for fetch methods
function onFetchCompleted(id) {
	mupdf.onFetchCompleted(id)
}

const libmupdf_injections = {
	fetchOpen,
	fetchRead,
	fetchClose,
	TryLaterError,
}

mupdf.ready = libmupdf(libmupdf_injections).then((m) => {
	libmupdf = m
	libmupdf._wasm_init_context()

	// To pass Rect and Matrix as pointer arguments
	_wasm_point = libmupdf._wasm_malloc(4 * 2) >> 2
	_wasm_rect = libmupdf._wasm_malloc(4 * 8) >> 2
	_wasm_matrix = libmupdf._wasm_malloc(4 * 6) >> 2
	_wasm_color = libmupdf._wasm_malloc(4 * 4) >> 2
	_wasm_quad = libmupdf._wasm_malloc(4 * 8) >> 2

	ColorSpace.DeviceGray = new ColorSpace(libmupdf._wasm_device_gray())
	ColorSpace.DeviceRGB = new ColorSpace(libmupdf._wasm_device_rgb())
	ColorSpace.DeviceBGR = new ColorSpace(libmupdf._wasm_device_bgr())
	ColorSpace.DeviceCMYK = new ColorSpace(libmupdf._wasm_device_cmyk())
	ColorSpace.Lab = new ColorSpace(libmupdf._wasm_device_lab())

	PDFObject.Null = new PDFObject(0)
})

// If running in Node.js environment
if (typeof require === "function")
	module.exports = mupdf
