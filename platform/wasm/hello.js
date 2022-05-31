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

const fs = require("fs");
const mupdf = require("./lib/mupdf.js");

let input;
if (process.argv[2] != null) {
	input = fs.readFileSync(process.argv[2]);
} else {
	input = fs.readFileSync("samples/annotations_galore_II.pdf");
}

mupdf.onInitialized = function () {
	var doc = new mupdf.Document(input, "application/pdf");
	console.log("opened doc", doc, doc.toString());
	var n = doc.countPages();
	console.log("num pages", n);
	var p = doc.loadPage(1);
	console.log("page", p.toString());
	console.log("page bounds", p.bounds());
	var pix = p.toPixmap([1,0,0,1,0,0], mupdf.DeviceRGB, false);
	console.log("pixmap", pix.toString(), pix.width, pix.height, pix.samples.length);
	console.log("saving as png");
	var png = pix.toPNG();
	fs.mkdirSync("samples/", { recursive: true });
	fs.writeFileSync("samples/out.png", png);
	console.log("all done.");

	let dpi = 96;
	console.log("pageText:", mupdf.getPageText(doc, 1, dpi));
	console.log("pageLinks:", mupdf.getPageLinks(doc, 1, dpi));
	console.log("pageAnnotations:", mupdf.getPageAnnotations(doc, 1, dpi));
};
