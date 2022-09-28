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

/* eslint-disable no-unused-vars */

class MupdfPageViewer {
	constructor(worker, pageNumber, defaultSize, dpi) {
		this.worker = worker;
		this.pageNumber = pageNumber;

		const root = document.createElement("div");
		root.classList.add("page");
		root.style.width = (defaultSize.w * dpi / 72) + "px";
		root.style.height = (defaultSize.h * dpi / 72) + "px";

		const anchor = document.createElement("a");
		anchor.classList.add("anchor");
		anchor.id = "page" + pageNumber;
		root.appendChild(anchor);

		this.rootNode = root;
		this.size = defaultSize;

		this.imgNode = null;
		this.renderPromise = null;
		this.queuedRenderArgs = null;
		this.renderCookie = null;

		this.textNode = null;
		this.textPromise = null;
		this.textResultObject = null;

		this.linksNode = null;
		this.linksPromise = null;
		this.linksResultObject = null;

		this.searchHitsNode = null;
		this.searchPromise = null;
		this.searchResultObject = null;
		this.lastSearchNeedle = null;
		this.searchNeedle = null;
	}

	render(dpi, searchNeedle) {
		// TODO - error handling
		this._loadPageImg({ dpi });
		this._loadPageText(dpi);
		this._loadPageLinks(dpi);
		this._loadPageSearch(dpi, searchNeedle);
	}

	cancelRender() {
		// TODO - use promise cancelling
		if (this.renderCookie != null) {
			const int32pointer = this.renderCookie >> 2;
			const wasmMemoryView32 = new Int32Array(this.worker.wasmMemory);
			wasmMemoryView32[int32pointer] = 1;
		}
	}

	// TODO - render on zoom
	// TODO - update child nodes
	async setZoom(zoomLevel) {
		const dpi = (zoomLevel * 96 / 100) | 0;

		this.rootNode.style.width = (this.size.w * dpi / 72) + "px";
		this.rootNode.style.height = (this.size.h * dpi / 72) + "px";
	}

	setSearchNeedle(searchNeedle = null) {
		console.log("setSearchNeedle");
		this.searchNeedle = searchNeedle;
	}

	clear() {
		this.cancelRender();

		this.imgNode?.remove();
		this.textNode?.remove();
		this.linksNode?.remove();
		this.searchHitsNode?.remove();

		// TODO - use promise cancelling
		this.renderPromise = null;
		this.textPromise = null;
		this.linksPromise = null;
		this.searchPromise = null;


		this.imgNode = null;
		this.renderPromise = null;
		this.queuedRenderArgs = null;
		this.renderCookie = null;

		this.textNode = null;
		this.textPromise = null;
		this.textResultObject = null;

		this.linksNode = null;
		this.linksPromise = null;
		this.linksResultObject = null;

		this.searchHitsNode = null;
		this.searchPromise = null;
		this.searchResultObject = null;
		this.lastSearchNeedle = null;
		this.searchNeedle = null;
	}

	showError(functionName, error) {
		console.error(`mupdf.${functionName}: ${error.message}:\n${error.stack}`);

		let div = document.createElement("div");
		div.classList.add("error");
		div.textContent = error.name + ": " + error.message;
		this.clear();
		this.rootNode.replaceChildren(div);
	}

	// TODO - make private
	// --- INTERNAL METHODS ---

	async _loadPageImg(renderArgs) {
		if (this.renderPromise != null) {
			// If a render is ongoing, we mark the current arguments as queued
			// to be processed when the render ends.
			// This also erases any previous queued render arguments.
			this.queuedRenderArgs = renderArgs;
			return;
		}
		if (this.imgNode?.renderArgs != null) {
			// If the current image node was rendered with the same arguments
			// we skip the render.
			if (renderArgs.dpi === this.imgNode.renderArgs.dpi)
				return;
		}

		let { dpi } = renderArgs;
		let rootNode = this.rootNode;

		let imgNode = new Image();
		imgNode.draggable = false;
		// user-select:none disables image.draggable, and we want
		// to keep pointer-events for the link image-map
		imgNode.ondragstart = function () { return false; };
		imgNode.onload = function () {
			URL.revokeObjectURL(this.src);
			// TODO - size should not depend on returned image
			rootNode.style.width = (this.width / devicePixelRatio) + "px";
			rootNode.style.height = (this.height / devicePixelRatio) + "px";
			imgNode.style.width = rootNode.style.width;
			imgNode.style.height = rootNode.style.height;
			imgNode.renderArgs = renderArgs;
		};

		try {
			this.renderCookie = await this.worker.createCookie();
			this.renderPromise = this.worker.drawPageAsPNG(this.pageNumber, dpi * devicePixelRatio, this.renderCookie);
			let pngData = await this.renderPromise;

			// if render was aborted, return early
			if (pngData == null)
				return;

			imgNode.src = URL.createObjectURL(new Blob([pngData], {type:"image/png"}));

			this.imgNode?.remove();
			this.imgNode = imgNode;
			this.rootNode.insertBefore(imgNode, this.rootNode.firstChild);
		}
		catch (error) {
			this.showError("_loadPageImg", error);
		}
		finally {
			this.worker.deleteCookie(this.renderCookie);
			this.renderCookie = null;
			this.renderPromise = null;
		}

		if (this.queuedRenderArgs != null) {
			// TODO - Error handling
			this._loadPageImg(this.queuedRenderArgs);
			this.queuedRenderArgs = null;
		}
	}

	// TODO - replace "dpi" with "scale"?
	async _loadPageText(dpi) {
		// TODO - Disable text when editing (conditions to be figured out)
		if (this.textNode != null && dpi === this.textNode.dpi) {
			// Text was already rendered at the right scale, nothing to be done
			return;
		}
		if (this.textResultObject) {
			// Text was already returned, just needs to be rescaled
			this._applyPageText(this.textResultObject, dpi);
			return;
		}

		let textNode = document.createElement("div");
		textNode.classList.add("text");

		this.textNode?.remove();
		this.textNode = textNode;
		this.rootNode.appendChild(textNode);

		try {
			this.textPromise = this.worker.getPageText(this.pageNumber);

			this.textResultObject = await this.textPromise;
			this._applyPageText(this.textResultObject, dpi);
		}
		catch (error) {
			this.showError("_loadPageText", error);
		}
		finally {
			this.textPromise = null;
		}
	}

	_applyPageText(textResultObject, dpi) {
		console.log("PAGE TEXT:", textResultObject);
		this.textNode.dpi = dpi;
		let nodes = [];
		let pdf_w = [];
		let html_w = [];
		let text_len = [];
		let scale = dpi / 72;
		this.textNode.replaceChildren();
		for (let block of textResultObject.blocks) {
			if (block.type === "text") {
				for (let line of block.lines) {
					let text = document.createElement("span");
					text.style.left = (line.bbox.x * scale) + "px";
					text.style.top = ((line.y - line.font.size * 0.8) * scale) + "px";
					text.style.height = (line.bbox.h * scale) + "px";
					text.style.fontSize = (line.font.size * scale) + "px";
					text.style.fontFamily = line.font.family;
					text.style.fontWeight = line.font.weight;
					text.style.fontStyle = line.font.style;
					text.textContent = line.text;
					this.textNode.appendChild(text);
					nodes.push(text);
					pdf_w.push(line.bbox.w);
					text_len.push(line.text.length-1);
				}
			}
		}
		for (let i = 0; i < nodes.length; ++i) {
			if (text_len[i] > 0)
				html_w[i] = nodes[i].clientWidth;
		}
		for (let i = 0; i < nodes.length; ++i) {
			if (text_len[i] > 0)
				nodes[i].style.letterSpacing = ((pdf_w[i] - html_w[i]) / text_len[i]) + "px";
		}
	}

	async _loadPageLinks(dpi) {
		if (this.linksNode != null && dpi === this.linksNode.dpi) {
			// Links were already rendered at the right scale, nothing to be done
			return;
		}
		if (this.linksResultObject) {
			// Links were already returned, just need to be rescaled
			this._applyPageLinks(this.linksResultObject, dpi);
			return;
		}

		let linksNode = document.createElement("div");
		linksNode.classList.add("links");

		// TODO - Figure out node order
		this.linksNode?.remove();
		this.linksNode = linksNode;
		this.rootNode.appendChild(linksNode);

		try {
			this.linksPromise = this.worker.getPageLinks(this.pageNumber);

			this.linksResultObject = await this.linksPromise;
			this._applyPageLinks(this.linksResultObject, dpi);
		}
		catch (error) {
			this.showError("_loadPageLinks", error);
		}
		finally {
			this.linksPromise = null;
		}
	}

	_applyPageLinks(linksResultObject, dpi) {
		let scale = dpi / 72;
		this.linksNode.dpi = dpi;
		this.linksNode.replaceChildren();
		for (let link of linksResultObject) {
			let a = document.createElement("a");
			a.href = link.href;
			a.style.left = (link.x * scale) + "px";
			a.style.top = (link.y * scale) + "px";
			a.style.width = (link.w * scale) + "px";
			a.style.height = (link.h * scale) + "px";
			this.linksNode.appendChild(a);
		}
	}

	async _loadPageSearch(dpi, searchNeedle) {
		if (this.searchHitsNode != null && dpi === this.searchHitsNode.dpi && searchNeedle == this.searchHitsNode.searchNeedle) {
			// Search results were already rendered at the right scale, nothing to be done
			return;
		}
		if (this.searchResultObject && searchNeedle == this.searchHitsNode.searchNeedle) {
			// Search results were already returned, just need to be rescaled
			this._applyPageSearch(this.searchResultObject, dpi);
			return;
		}

		let searchHitsNode = document.createElement("div");
		searchHitsNode.classList.add("searchHitList");
		this.searchHitsNode?.remove();
		this.searchHitsNode = searchHitsNode;
		this.rootNode.appendChild(searchHitsNode);

		try {
			if (searchNeedle ?? "" !== "") {
				console.log("SEARCH", this.pageNumber, JSON.stringify(this.searchNeedle));
				this.searchPromise = this.worker.search(this.pageNumber, this.searchNeedle ?? "");
				this.searchResultObject = await this.searchPromise;
			}
			else {
				this.searchResultObject = [];
			}

			this._applyPageSearch(this.searchResultObject, searchNeedle, dpi);
		}
		catch (error) {
			this.showError("_loadPageSearch", error);
		}
		finally {
			this.searchPromise = null;
		}
	}

	_applyPageSearch(searchResultObject, searchNeedle, dpi) {
		let scale = dpi / 72;
		this.searchHitsNode.searchNeedle = searchNeedle;
		this.searchHitsNode.dpi = dpi;
		this.searchHitsNode.replaceChildren();
		for (let bbox of searchResultObject) {
			let div = document.createElement("div");
			div.classList.add("searchHit");
			div.style.left = (bbox.x * scale) + "px";
			div.style.top = (bbox.y * scale) + "px";
			div.style.width = (bbox.w * scale) + "px";
			div.style.height = (bbox.h * scale) + "px";
			this.searchHitsNode.appendChild(div);
		}
	}
}
