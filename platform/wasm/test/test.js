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

const { assert } = require("chai");
const fs = require("fs/promises");
const mupdf = require("../lib/mupdf.js");

describe("mupdf", function () {
	let input;
	beforeAll(async function () {
		input = await fs.readFile("samples/annotations_galore_II.pdf");
	});

	beforeAll(async function () {
		await mupdf.ready;
	});

	describe.skip("geometry", function () {
		describe("Matrix", function () {
			it("should transform Rect", function () {
				const matrix = mupdf.Matrix.scale(3, 2);
				const rect = new mupdf.Rect(10, 10, 20, 20);

				assert.deepEqual(matrix.transformRect(rect), new mupdf.Rect(30, 20, 31, 40));
			});
		});
	});

	describe("Document", function () {
		describe("openFromData()", function () {
			it("should return a valid Document", function () {
				let doc = mupdf.Document.openFromData(input, "application/pdf");
				assert.isNotNull(doc);
				assert.equal(doc.countPages(), 3);
				assert.equal(doc.title(), "");
			});
		});

		describe("openFromStream()", function () {
			it("should return a valid Document", function () {
				let stream = mupdf.Stream.fromJsBuffer(input);
				let doc = mupdf.Document.openFromStream(stream, "application/pdf");

				assert.isNotNull(doc);
				assert.equal(doc.countPages(), 3);
				assert.equal(doc.title(), "");
			});
		});

		describe("loadPage()", function () {
			it("should return a valid Page", function () {
				let doc = mupdf.Document.openFromData(input, "application/pdf");
				let page = doc.loadPage(0);

				assert.isNotNull(page);
				assert.instanceOf(page, mupdf.PdfPage);
				assert.deepEqual(page.bounds(), new mupdf.Rect(0, 0, 612, 792));
				assert.equal(page.width(), 612);
				assert.equal(page.height(), 792);
			});

			it("should throw on OOB", function () {
				let doc = mupdf.Document.openFromData(input, "application/pdf");
				assert.throws(() => doc.loadPage(500), mupdf.MupdfError);
				assert.throws(() => doc.loadPage(-1), mupdf.MupdfError);
			});
		});

		describe("loadOutline()", function () {
			it("should return a null Outline if document doesn't have one", function () {
				let doc = mupdf.Document.openFromData(input, "application/pdf");
				let outline = doc.loadOutline();

				assert.isNull(outline);
			});

			// TODO - non-null outline
		});
	});

	describe("Page", function () {
		let doc;
		let page;
		beforeAll(function () {
			doc = mupdf.Document.openFromData(input, "application/pdf");
			page = doc.loadPage(0);
		});

		describe("toPixmap()", function () {
			it("should return a valid Pixmap", function () {
				let pixmap = page.toPixmap(new mupdf.Matrix(1,0,0,1,0,0), mupdf.DeviceRGB, false);

				assert.isNotNull(pixmap);
				assert.equal(pixmap.width(), 612);
				assert.equal(pixmap.height(), 792);
			});
		});

		describe("toSTextPage()", function () {
			it("should return a valid STextPage", function () {
				let stextPage = page.toSTextPage();

				assert.isNotNull(stextPage);

				let buffer = mupdf.Buffer.empty();
				let output = mupdf.Output.withBuffer(buffer);
				stextPage.printAsJson(output, 1);

				let stextObj = JSON.parse(buffer.toJsString());
				expect(stextObj).toMatchSnapshot();
			});
		});

		describe("loadLinks()", function () {
			it("should return list of Links on page", function () {
				let links = page.loadLinks();

				assert.isNotNull(links);
				assert.lengthOf(links.links, 2);
			});
		});

		describe("search()", function () {
			it("should return list of hitboxes of search results", function () {
				let hits = page.search("a");
				assert.isArray(hits);
				expect(hits).toMatchSnapshot();
			});
		});

		describe("PdfPage", function () {
			describe("annotations()", function () {
				it("should return list of annotations on page", function () {
					let annotations = page.annotations();

					assert.isNotNull(annotations);
					assert.lengthOf(annotations.annotations, 8);
				});
			});
		});
	});

	describe("Link", function () {
		let doc;
		let page;
		let links;
		beforeAll(function () {
			doc = mupdf.Document.openFromData(input, "application/pdf");
			page = doc.loadPage(0);
			links = page.loadLinks();
		});

		describe("rect()", function () {
			it("should return Link hitbox", function () {
				let link = links.links[0];
				let linkRect = link.rect();

				assert.instanceOf(linkRect, mupdf.Rect);
				expect(linkRect).toMatchSnapshot();
			});
		});

		describe("isExternalLink()", function () {
			it("should return true if link has external URL", function () {
				let link = links.links[0];

				assert.isTrue(link.isExternalLink());
			});
		});

		describe("uri()", function () {
			it("should return link URI", function () {
				let link = links.links[0];

				assert.equal(link.uri(), "http://www.adobe.com");
			});
		});

		// TODO - resolve
	});

	// TODO - Outline

	// TODO - Annotations

	// TODO - Pixmap

	describe("Buffer", function () {
		describe("empty()", function () {
			it("should return a buffer with size = 0", function () {
				let buffer = mupdf.Buffer.empty();

				assert.isNotNull(buffer);
				assert.equal(buffer.size(), 0);
			});

			it("should reserve at least given capacity", function () {
				let buffer = mupdf.Buffer.empty(64);

				assert.isNotNull(buffer);
				assert.equal(buffer.size(), 0);
				assert.isAtLeast(buffer.capacity(), 64);
			});
		});

		describe("fromJsBuffer()", function () {
			it("should return valid buffer", function () {
				let jsArray = Uint8Array.from([1, 2, 3, 4, 5]);
				let buffer = mupdf.Buffer.fromJsBuffer(jsArray);

				assert.isNotNull(buffer);
				assert.equal(buffer.size(), 5);
			});

			it("should preserve data through round-trip", function () {
				let jsArray = Uint8Array.from([1, 2, 3, 4, 5]);
				let buffer = mupdf.Buffer.fromJsBuffer(jsArray);

				assert.deepEqual(buffer.toUint8Array(), jsArray);
			});

			it("should be valid for empty array", function () {
				let jsArray = Uint8Array.from([]);
				let buffer = mupdf.Buffer.fromJsBuffer(jsArray);

				assert.isNotNull(buffer);
				assert.equal(buffer.size(), 0);
				assert.deepEqual(buffer.toUint8Array(), jsArray);
			});
		});

		describe("fromJsString()", function () {
			it("should preserve data through round-trip", function () {
				let buffer = mupdf.Buffer.fromJsString("Hello world");

				assert.isNotNull(buffer);
				assert.isAbove(buffer.size(), 0);
				assert.deepEqual(buffer.toJsString(), "Hello world");
			});

			it("should be valid for empty string", function () {
				let buffer = mupdf.Buffer.fromJsString("");

				assert.isNotNull(buffer);
				assert.equal(buffer.size(), 0);
				assert.deepEqual(buffer.toJsString(), "");
			});
		});

		describe("resize()", function () {
			it("should reserve at least given capacity", function () {
				let jsArray = Uint8Array.from([1, 2, 3, 4, 5]);
				let buffer = mupdf.Buffer.fromJsBuffer(jsArray);

				buffer.resize(128);

				assert.equal(buffer.size(), 5);
				assert.isAtLeast(buffer.capacity(), 128);
			});

			it("should shrink array if given smaller size", function () {
				let jsArray = Uint8Array.from([1, 2, 3, 4, 5]);
				let buffer = mupdf.Buffer.fromJsBuffer(jsArray);

				buffer.resize(3);

				assert.equal(buffer.size(), 3);
				assert.isAtLeast(buffer.capacity(), 3);
			});
		});

		describe("grow()", function () {
			it("should increase capacity", function () {
				let jsArray = Uint8Array.from([1, 2, 3, 4, 5]);
				let buffer = mupdf.Buffer.fromJsBuffer(jsArray);
				let oldCapacity = buffer.capacity();

				buffer.grow();

				assert.equal(buffer.size(), 5);
				assert.isAtLeast(buffer.capacity(), oldCapacity);
			});
		});

		describe("trim()", function () {
			it("should set capacity to length", function () {
				let jsArray = Uint8Array.from([1, 2, 3, 4, 5]);
				let buffer = mupdf.Buffer.fromJsBuffer(jsArray);
				buffer.resize(100);

				buffer.trim();

				assert.equal(buffer.size(), 5);
				assert.equal(buffer.capacity(), 5);
			});
		});

		describe("clear()", function () {
			it("should set buffer size to 0", function () {
				let jsArray = Uint8Array.from([1, 2, 3, 4, 5]);
				let buffer = mupdf.Buffer.fromJsBuffer(jsArray);

				buffer.clear();

				assert.equal(buffer.size(), 0);
			});
		});
	});

	describe("Stream", function () {
		describe("fromBuffer()", function () {
			it("should read bytes from buffer", function () {
				let jsArray = Uint8Array.from([1, 2, 3, 4, 5]);
				let buffer = mupdf.Buffer.fromJsBuffer(jsArray);

				let stream = mupdf.Stream.fromBuffer(buffer);

				assert.isTrue(stream.readAll().sameContentAs(buffer));
			});
		});

		describe("fromJsBuffer()", function () {
			it("should read bytes from JS buffer", function () {
				let jsArray = Uint8Array.from([1, 2, 3, 4, 5]);
				let stream = mupdf.Stream.fromJsBuffer(jsArray);

				assert.isTrue(stream.readAll().sameContentAs(mupdf.Buffer.fromJsBuffer(jsArray)));
			});

			it("should be valid for empty array", function () {
				let jsArray = Uint8Array.from([]);
				let stream = mupdf.Stream.fromJsBuffer(jsArray);

				assert.isTrue(stream.readAll().sameContentAs(mupdf.Buffer.empty()));
			});
		});

		describe("fromJsString()", function () {
			it("should read bytes from string", function () {
				let stream = mupdf.Stream.fromJsString("Hello world");

				assert.isTrue(stream.readAll().sameContentAs(mupdf.Buffer.fromJsString("Hello world")));
			});

			it("should be valid for empty string", function () {
				let stream = mupdf.Stream.fromJsString("");

				assert.isTrue(stream.readAll().sameContentAs(mupdf.Buffer.fromJsString("")));
			});
		});
	});

	// TODO - Output

	it.skip("should save a document to PNG", async function () {
		let doc = mupdf.Document.openFromData(input, "application/pdf");
		var page = doc.loadPage(0);
		var pix = page.toPixmap(new mupdf.Matrix(1,0,0,1,0,0), mupdf.DeviceRGB, false);
		var png = pix.toPNG();
		await fs.mkdir("samples/", { recursive: true });
		await fs.writeFile("samples/out.png", png);
	});
});

// TODO
// - DeviceGray/RGB/etc
// - Finalizer?
