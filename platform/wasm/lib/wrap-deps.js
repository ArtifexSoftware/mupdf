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

// The content of this file is added at the beginning of libmupdf.js when the
// project is linked.
//
// JS functions and classes shoud be added to this file to be available from C code.

/* eslint-disable no-unused-vars */

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
