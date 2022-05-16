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

#ifndef XML_IMP_H

#define XML_IMP_H

#include "mupdf/fitz.h"

/* These types are required for basic XML operation. */

struct attribute
{
	char *value;
	struct attribute *next;
	char name[1];
};

struct fz_xml_doc
{
	fz_pool *pool;
	fz_xml *root;
};

/* Text nodes never use the down pointer. Therefore
 * if the down pointer is the MAGIC_TEXT value, we
 * know there is text. */
struct fz_xml
{
	fz_xml *up, *down, *prev, *next;
#ifdef FZ_XML_SEQ
	int seq;
#endif
	union
	{
		char text[1];
		struct
		{
			struct attribute *atts;
			char name[1];
		} d;
	} u;
};

#define MAGIC_TEXT ((fz_xml *)1)

#endif
