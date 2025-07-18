// Copyright (C) 2004-2025 Artifex Software, Inc.
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
// Artifex Software, Inc., 39 Mesa Street, Suite 108A, San Francisco,
// CA 94129, USA, for further information.

#include "mupdf/fitz.h"

#include <string.h>
#include <assert.h>

// Thoughts for further optimisations:
// All paths start with MoveTo. We could probably avoid most cases where
// we store that. The next thing after a close must be a move.
// Commands are MOVE, LINE, HORIZ, VERT, DEGEN, CURVE, CURVEV, CURVEY, QUAD, RECT.
// We'd need to drop 2 to get us down to 3 bits.
// Commands can be followed by CLOSE. Use 1 bit for close.
// PDF 'RECT' implies close according to the spec, but I suspect
// we can ignore this as filling closes implicitly.
// We use a single bit in the path header to tell us whether we have
// a trailing move. Trailing moves can always be stripped when path
// construction completes.

typedef enum
{
	FZ_MOVETO = 'M',
	FZ_LINETO = 'L',
	FZ_DEGENLINETO = 'D',
	FZ_CURVETO = 'C',
	FZ_CURVETOV = 'V',
	FZ_CURVETOY = 'Y',
	FZ_HORIZTO = 'H',
	FZ_VERTTO = 'I',
	FZ_QUADTO = 'Q',
	FZ_RECTTO = 'R',
	FZ_MOVETOCLOSE = 'm',
	FZ_LINETOCLOSE = 'l',
	FZ_DEGENLINETOCLOSE = 'd',
	FZ_CURVETOCLOSE = 'c',
	FZ_CURVETOVCLOSE = 'v',
	FZ_CURVETOYCLOSE = 'y',
	FZ_HORIZTOCLOSE = 'h',
	FZ_VERTTOCLOSE = 'i',
	FZ_QUADTOCLOSE = 'q',
} fz_path_item_kind;

struct fz_path
{
	int8_t refs;
	uint8_t packed;
	int cmd_len, cmd_cap;
	unsigned char *cmds;
	int coord_len, coord_cap;
	float *coords;
	fz_point current;
	fz_point begin;
};

typedef struct
{
	int8_t refs;
	uint8_t packed;
	uint8_t coord_len;
	uint8_t cmd_len;
} fz_packed_path;

/*
	Paths are created UNPACKED. That means we have a fz_path
	structure with coords and cmds pointing to malloced blocks.

	After they have been completely constructed, callers may choose
	to 'pack' them into some target block of memory. If if coord_len
	and cmd_len are both < 256, then they are PACKED_FLAT into an
	fz_packed_path with the coords and cmds in the bytes afterwards,
	all inside the target block. If they cannot be accommodated in
	that way, then they are PACKED_OPEN, where an fz_path is put
	into the target block, and cmds and coords remain pointers to
	allocated blocks.
*/
enum
{
	FZ_PATH_UNPACKED = 0,
	FZ_PATH_PACKED_FLAT = 1,
	FZ_PATH_PACKED_OPEN = 2
};

#define LAST_CMD(path) ((path)->cmd_len > 0 ? (path)->cmds[(path)->cmd_len-1] : 0)

fz_path *
fz_new_path(fz_context *ctx)
{
	fz_path *path;

	path = fz_malloc_struct(ctx, fz_path);
	path->refs = 1;
	path->packed = FZ_PATH_UNPACKED;
	path->current.x = 0;
	path->current.y = 0;
	path->begin.x = 0;
	path->begin.y = 0;

	return path;
}

/*
	Take an additional reference to
	a path.

	No modifications should be carried out on a path
	to which more than one reference is held, as
	this can cause race conditions.
*/
fz_path *
fz_keep_path(fz_context *ctx, const fz_path *pathc)
{
	fz_path *path = (fz_path *)pathc; /* Explicit cast away of const */
	int trimmable = 0;

	if (path == NULL)
		return NULL;
	fz_lock(ctx, FZ_LOCK_ALLOC);
	/* Technically, we should only access ->refs with the lock held,
	 * so do that here. We can't actually do the trimming here, because
	 * to do so would do memory accesses with the ALLOC lock held. */
	if (path->refs == 1 && path->packed == FZ_PATH_UNPACKED)
		trimmable = 1;
	fz_keep_imp8_locked(ctx, path, &path->refs);
	fz_unlock(ctx, FZ_LOCK_ALLOC);

	/* This is thread safe, because we know that the only person
	 * holding a reference to this thread is us. */
	if (trimmable)
		fz_trim_path(ctx, path);

	return path;
}

void
fz_drop_path(fz_context *ctx, const fz_path *pathc)
{
	fz_path *path = (fz_path *)pathc; /* Explicit cast away of const */

	if (fz_drop_imp8(ctx, path, &path->refs))
	{
		if (path->packed != FZ_PATH_PACKED_FLAT)
		{
			fz_free(ctx, path->cmds);
			fz_free(ctx, path->coords);
		}
		if (path->packed == FZ_PATH_UNPACKED)
			fz_free(ctx, path);
	}
}

int fz_packed_path_size(const fz_path *path)
{
	switch (path->packed)
	{
	case FZ_PATH_UNPACKED:
		if (path->cmd_len > 255 || path->coord_len > 255)
			return sizeof(fz_path);
		return sizeof(fz_packed_path) + sizeof(float) * path->coord_len + sizeof(uint8_t) * path->cmd_len;
	case FZ_PATH_PACKED_OPEN:
		return sizeof(fz_path);
	case FZ_PATH_PACKED_FLAT:
	{
		fz_packed_path *pack = (fz_packed_path *)path;
		return sizeof(fz_packed_path) + sizeof(float) * pack->coord_len + sizeof(uint8_t) * pack->cmd_len;
	}
	default:
		assert("This never happens" == NULL);
		return 0;
	}
}

size_t
fz_pack_path(fz_context *ctx, uint8_t *pack_, const fz_path *path)
{
	uint8_t *ptr;
	size_t size;

	if (path->packed == FZ_PATH_PACKED_FLAT)
	{
		fz_packed_path *pack = (fz_packed_path *)path;
		fz_packed_path *out = (fz_packed_path *)pack_;
		size = sizeof(fz_packed_path) + sizeof(float) * pack->coord_len + sizeof(uint8_t) * pack->cmd_len;

		if (out)
		{
			out->refs = 1;
			out->packed = FZ_PATH_PACKED_FLAT;
			out->coord_len = pack->coord_len;
			out->cmd_len = pack->cmd_len;
			memcpy(&out[1], &pack[1], size - sizeof(*out));
		}
		return size;
	}

	size = sizeof(fz_packed_path) + sizeof(float) * path->coord_len + sizeof(uint8_t) * path->cmd_len;

	/* If the path can't be packed flat, then pack it open */
	if (path->cmd_len > 255 || path->coord_len > 255)
	{
		fz_path *pack = (fz_path *)pack_;

		if (pack != NULL)
		{
			pack->refs = 1;
			pack->packed = FZ_PATH_PACKED_OPEN;
			pack->current.x = 0;
			pack->current.y = 0;
			pack->begin.x = 0;
			pack->begin.y = 0;
			pack->coord_cap = path->coord_len;
			pack->coord_len = path->coord_len;
			pack->cmd_cap = path->cmd_len;
			pack->cmd_len = path->cmd_len;
			pack->coords = Memento_label(fz_malloc_array(ctx, path->coord_len, float), "path_packed_coords");
			fz_try(ctx)
			{
				pack->cmds = Memento_label(fz_malloc_array(ctx, path->cmd_len, uint8_t), "path_packed_cmds");
			}
			fz_catch(ctx)
			{
				fz_free(ctx, pack->coords);
				fz_rethrow(ctx);
			}
			memcpy(pack->coords, path->coords, sizeof(float) * path->coord_len);
			memcpy(pack->cmds, path->cmds, sizeof(uint8_t) * path->cmd_len);
		}
		return sizeof(fz_path);
	}
	else
	{
		fz_packed_path *pack = (fz_packed_path *)pack_;

		if (pack != NULL)
		{
			pack->refs = 1;
			pack->packed = FZ_PATH_PACKED_FLAT;
			pack->cmd_len = path->cmd_len;
			pack->coord_len = path->coord_len;
			ptr = (uint8_t *)&pack[1];
			memcpy(ptr, path->coords, sizeof(float) * path->coord_len);
			ptr += sizeof(float) * path->coord_len;
			memcpy(ptr, path->cmds, sizeof(uint8_t) * path->cmd_len);
		}

		return size;
	}
}

static void
push_cmd(fz_context *ctx, fz_path *path, int cmd)
{
	if (path->refs != 1)
		fz_throw(ctx, FZ_ERROR_ARGUMENT, "cannot modify shared paths");

	if (path->cmd_len + 1 >= path->cmd_cap)
	{
		int new_cmd_cap = fz_maxi(16, path->cmd_cap * 2);
		path->cmds = fz_realloc_array(ctx, path->cmds, new_cmd_cap, unsigned char);
		path->cmd_cap = new_cmd_cap;
	}

	path->cmds[path->cmd_len++] = cmd;
}

static void
push_coord(fz_context *ctx, fz_path *path, float x, float y)
{
	if (path->coord_len + 2 >= path->coord_cap)
	{
		int new_coord_cap = fz_maxi(32, path->coord_cap * 2);
		path->coords = fz_realloc_array(ctx, path->coords, new_coord_cap, float);
		path->coord_cap = new_coord_cap;
	}

	path->coords[path->coord_len++] = x;
	path->coords[path->coord_len++] = y;

	path->current.x = x;
	path->current.y = y;
}

static void
push_ord(fz_context *ctx, fz_path *path, float xy, int isx)
{
	if (path->coord_len + 1 >= path->coord_cap)
	{
		int new_coord_cap = fz_maxi(32, path->coord_cap * 2);
		path->coords = fz_realloc_array(ctx, path->coords, new_coord_cap, float);
		path->coord_cap = new_coord_cap;
	}

	path->coords[path->coord_len++] = xy;

	if (isx)
		path->current.x = xy;
	else
		path->current.y = xy;
}

fz_point
fz_currentpoint(fz_context *ctx, fz_path *path)
{
	return path->current;
}

void
fz_moveto(fz_context *ctx, fz_path *path, float x, float y)
{
	if (path->packed)
		fz_throw(ctx, FZ_ERROR_ARGUMENT, "Cannot modify a packed path");

	if (path->cmd_len > 0 && LAST_CMD(path) == FZ_MOVETO)
	{
		/* Collapse moveto followed by moveto. */
		path->coords[path->coord_len-2] = x;
		path->coords[path->coord_len-1] = y;
		path->current.x = x;
		path->current.y = y;
		path->begin = path->current;
		return;
	}

	push_cmd(ctx, path, FZ_MOVETO);
	push_coord(ctx, path, x, y);

	path->begin = path->current;
}

void
fz_lineto(fz_context *ctx, fz_path *path, float x, float y)
{
	float x0, y0;

	if (path->packed)
		fz_throw(ctx, FZ_ERROR_ARGUMENT, "Cannot modify a packed path");

	x0 = path->current.x;
	y0 = path->current.y;

	if (path->cmd_len == 0)
	{
		fz_warn(ctx, "lineto with no current point");
		return;
	}

	/* (Anything other than MoveTo) followed by (LineTo the same place) is a nop */
	if (LAST_CMD(path) != FZ_MOVETO && x0 == x && y0 == y)
		return;

	if (x0 == x)
	{
		if (y0 == y)
		{
			if (LAST_CMD(path) != FZ_MOVETO)
				return;
			push_cmd(ctx, path, FZ_DEGENLINETO);
		}
		else
		{
			push_cmd(ctx, path, FZ_VERTTO);
			push_ord(ctx, path, y, 0);
		}
	}
	else if (y0 == y)
	{
		push_cmd(ctx, path, FZ_HORIZTO);
		push_ord(ctx, path, x, 1);
	}
	else
	{
		push_cmd(ctx, path, FZ_LINETO);
		push_coord(ctx, path, x, y);
	}
}

void
fz_curveto(fz_context *ctx, fz_path *path,
	float x1, float y1,
	float x2, float y2,
	float x3, float y3)
{
	float x0, y0;

	if (path->packed)
		fz_throw(ctx, FZ_ERROR_ARGUMENT, "Cannot modify a packed path");

	x0 = path->current.x;
	y0 = path->current.y;

	if (path->cmd_len == 0)
	{
		fz_warn(ctx, "curveto with no current point");
		return;
	}

	/* Check for degenerate cases: */
	if (x0 == x1 && y0 == y1)
	{
		if (x2 == x3 && y2 == y3)
		{
			/* If (x1,y1)==(x2,y2) and prev wasn't a moveto, then skip */
			if (x1 == x2 && y1 == y2 && LAST_CMD(path) != FZ_MOVETO)
				return;
			/* Otherwise a line will suffice */
			fz_lineto(ctx, path, x3, y3);
		}
		else if (x1 == x2 && y1 == y2)
		{
			/* A line will suffice */
			fz_lineto(ctx, path, x3, y3);
		}
		else
			fz_curvetov(ctx, path, x2, y2, x3, y3);
		return;
	}
	else if (x2 == x3 && y2 == y3)
	{
		if (x1 == x2 && y1 == y2)
		{
			/* A line will suffice */
			fz_lineto(ctx, path, x3, y3);
		}
		else
			fz_curvetoy(ctx, path, x1, y1, x3, y3);
		return;
	}

	push_cmd(ctx, path, FZ_CURVETO);
	push_coord(ctx, path, x1, y1);
	push_coord(ctx, path, x2, y2);
	push_coord(ctx, path, x3, y3);
}

void
fz_quadto(fz_context *ctx, fz_path *path,
	float x1, float y1,
	float x2, float y2)
{
	float x0, y0;

	if (path->packed)
		fz_throw(ctx, FZ_ERROR_ARGUMENT, "Cannot modify a packed path");

	x0 = path->current.x;
	y0 = path->current.y;

	if (path->cmd_len == 0)
	{
		fz_warn(ctx, "quadto with no current point");
		return;
	}

	/* Check for degenerate cases: */
	if ((x0 == x1 && y0 == y1) || (x1 == x2 && y1 == y2))
	{
		if (x0 == x2 && y0 == y2 && LAST_CMD(path) != FZ_MOVETO)
			return;
		/* A line will suffice */
		fz_lineto(ctx, path, x2, y2);
		return;
	}

	push_cmd(ctx, path, FZ_QUADTO);
	push_coord(ctx, path, x1, y1);
	push_coord(ctx, path, x2, y2);
}

void
fz_curvetov(fz_context *ctx, fz_path *path, float x2, float y2, float x3, float y3)
{
	float x0, y0;

	if (path->packed)
		fz_throw(ctx, FZ_ERROR_ARGUMENT, "Cannot modify a packed path");

	x0 = path->current.x;
	y0 = path->current.y;

	if (path->cmd_len == 0)
	{
		fz_warn(ctx, "curveto with no current point");
		return;
	}

	/* Check for degenerate cases: */
	if (x2 == x3 && y2 == y3)
	{
		/* If (x0,y0)==(x2,y2) and prev wasn't a moveto, then skip */
		if (x0 == x2 && y0 == y2 && LAST_CMD(path) != FZ_MOVETO)
			return;
		/* Otherwise a line will suffice */
		fz_lineto(ctx, path, x3, y3);
	}
	else if (x0 == x2 && y0 == y2)
	{
		/* A line will suffice */
		fz_lineto(ctx, path, x3, y3);
	}

	push_cmd(ctx, path, FZ_CURVETOV);
	push_coord(ctx, path, x2, y2);
	push_coord(ctx, path, x3, y3);
}

void
fz_curvetoy(fz_context *ctx, fz_path *path, float x1, float y1, float x3, float y3)
{
	float x0, y0;

	if (path->packed)
		fz_throw(ctx, FZ_ERROR_ARGUMENT, "Cannot modify a packed path");

	x0 = path->current.x;
	y0 = path->current.y;

	if (path->cmd_len == 0)
	{
		fz_warn(ctx, "curveto with no current point");
		return;
	}

	/* Check for degenerate cases: */
	if (x1 == x3 && y1 == y3)
	{
		/* If (x0,y0)==(x1,y1) and prev wasn't a moveto, then skip */
		if (x0 == x1 && y0 == y1 && LAST_CMD(path) != FZ_MOVETO)
			return;
		/* Otherwise a line will suffice */
		fz_lineto(ctx, path, x3, y3);
	}

	push_cmd(ctx, path, FZ_CURVETOY);
	push_coord(ctx, path, x1, y1);
	push_coord(ctx, path, x3, y3);
}

void
fz_closepath(fz_context *ctx, fz_path *path)
{
	uint8_t rep;

	if (path->packed)
		fz_throw(ctx, FZ_ERROR_ARGUMENT, "Cannot modify a packed path");

	if (path->cmd_len == 0)
	{
		fz_warn(ctx, "closepath with no current point");
		return;
	}

	switch(LAST_CMD(path))
	{
	case FZ_MOVETO:
		rep = FZ_MOVETOCLOSE;
		break;
	case FZ_LINETO:
		rep = FZ_LINETOCLOSE;
		break;
	case FZ_DEGENLINETO:
		rep = FZ_DEGENLINETOCLOSE;
		break;
	case FZ_CURVETO:
		rep = FZ_CURVETOCLOSE;
		break;
	case FZ_CURVETOV:
		rep = FZ_CURVETOVCLOSE;
		break;
	case FZ_CURVETOY:
		rep = FZ_CURVETOYCLOSE;
		break;
	case FZ_HORIZTO:
		rep = FZ_HORIZTOCLOSE;
		break;
	case FZ_VERTTO:
		rep = FZ_VERTTOCLOSE;
		break;
	case FZ_QUADTO:
		rep = FZ_QUADTOCLOSE;
		break;
	case FZ_RECTTO:
		/* RectTo implies close */
		return;
	case FZ_MOVETOCLOSE:
	case FZ_LINETOCLOSE:
	case FZ_DEGENLINETOCLOSE:
	case FZ_CURVETOCLOSE:
	case FZ_CURVETOVCLOSE:
	case FZ_CURVETOYCLOSE:
	case FZ_HORIZTOCLOSE:
	case FZ_VERTTOCLOSE:
	case FZ_QUADTOCLOSE:
		/* CLOSE following a CLOSE is a NOP */
		return;
	default: /* default never happens */
	case 0:
		/* Closing an empty path is a NOP */
		return;
	}

	path->cmds[path->cmd_len-1] = rep;

	path->current = path->begin;
}

void
fz_rectto(fz_context *ctx, fz_path *path, float x1, float y1, float x2, float y2)
{
	if (path->packed)
		fz_throw(ctx, FZ_ERROR_ARGUMENT, "Cannot modify a packed path");

	if (path->cmd_len > 0 && LAST_CMD(path) == FZ_MOVETO)
	{
		/* Collapse moveto followed by rectto. */
		path->coord_len -= 2;
		path->cmd_len--;
	}

	push_cmd(ctx, path, FZ_RECTTO);
	push_coord(ctx, path, x1, y1);
	push_coord(ctx, path, x2, y2);

	path->current = path->begin;
}

static inline void bound_expand(fz_rect *r, fz_point p)
{
	if (p.x < r->x0) r->x0 = p.x;
	if (p.y < r->y0) r->y0 = p.y;
	if (p.x > r->x1) r->x1 = p.x;
	if (p.y > r->y1) r->y1 = p.y;
}

void fz_walk_path(fz_context *ctx, const fz_path *path, const fz_path_walker *proc, void *arg)
{
	int i, k, cmd_len;
	float x=0, y=0, sx=0, sy=0;
	uint8_t *cmds;
	float *coords;

	switch (path->packed)
	{
	case FZ_PATH_UNPACKED:
	case FZ_PATH_PACKED_OPEN:
		cmd_len = path->cmd_len;
		coords = path->coords;
		cmds = path->cmds;
		break;
	case FZ_PATH_PACKED_FLAT:
		cmd_len = ((fz_packed_path *)path)->cmd_len;
		coords = (float *)&((fz_packed_path *)path)[1];
		cmds = (uint8_t *)&coords[((fz_packed_path *)path)->coord_len];
		break;
	default:
		assert("This never happens" == NULL);
		return;
	}

	if (cmd_len == 0)
		return;

	for (k=0, i = 0; i < cmd_len; i++)
	{
		uint8_t cmd = cmds[i];

		switch (cmd)
		{
		case FZ_CURVETO:
		case FZ_CURVETOCLOSE:
			proc->curveto(ctx, arg,
					coords[k],
					coords[k+1],
					coords[k+2],
					coords[k+3],
					x = coords[k+4],
					y = coords[k+5]);
			k += 6;
			if (cmd == FZ_CURVETOCLOSE)
			{
				if (proc->closepath)
					proc->closepath(ctx, arg);
				x = sx;
				y = sy;
			}
			break;
		case FZ_CURVETOV:
		case FZ_CURVETOVCLOSE:
			if (proc->curvetov)
				proc->curvetov(ctx, arg,
						coords[k],
						coords[k+1],
						x = coords[k+2],
						y = coords[k+3]);
			else
			{
				proc->curveto(ctx, arg,
						x,
						y,
						coords[k],
						coords[k+1],
						coords[k+2],
						coords[k+3]);
				x = coords[k+2];
				y = coords[k+3];
			}
			k += 4;
			if (cmd == FZ_CURVETOVCLOSE)
			{
				if (proc->closepath)
					proc->closepath(ctx, arg);
				x = sx;
				y = sy;
			}
			break;
		case FZ_CURVETOY:
		case FZ_CURVETOYCLOSE:
			if (proc->curvetoy)
				proc->curvetoy(ctx, arg,
						coords[k],
						coords[k+1],
						x = coords[k+2],
						y = coords[k+3]);
			else
				proc->curveto(ctx, arg,
						coords[k],
						coords[k+1],
						coords[k+2],
						coords[k+3],
						x = coords[k+2],
						y = coords[k+3]);
			k += 4;
			if (cmd == FZ_CURVETOYCLOSE)
			{
				if (proc->closepath)
					proc->closepath(ctx, arg);
				x = sx;
				y = sy;
			}
			break;
		case FZ_QUADTO:
		case FZ_QUADTOCLOSE:
			if (proc->quadto)
				proc->quadto(ctx, arg,
					coords[k],
					coords[k+1],
					x = coords[k+2],
					y = coords[k+3]);
			else
			{
				float c2x = coords[k] * 2;
				float c2y = coords[k+1] * 2;
				float c1x = (x + c2x) / 3;
				float c1y = (y + c2y) / 3;
				x = coords[k+2];
				y = coords[k+3];
				c2x = (c2x + x) / 3;
				c2y = (c2y + y) / 3;

				proc->curveto(ctx, arg,
					c1x,
					c1y,
					c2x,
					c2y,
					x,
					y);
			}
			k += 4;
			if (cmd == FZ_QUADTOCLOSE)
			{
				if (proc->closepath)
					proc->closepath(ctx, arg);
				x = sx;
				y = sy;
			}
			break;
		case FZ_MOVETO:
		case FZ_MOVETOCLOSE:
			proc->moveto(ctx, arg,
				x = coords[k],
				y = coords[k+1]);
			k += 2;
			sx = x;
			sy = y;
			if (cmd == FZ_MOVETOCLOSE)
			{
				if (proc->closepath)
					proc->closepath(ctx, arg);
				x = sx;
				y = sy;
			}
			break;
		case FZ_LINETO:
		case FZ_LINETOCLOSE:
			proc->lineto(ctx, arg,
				x = coords[k],
				y = coords[k+1]);
			k += 2;
			if (cmd == FZ_LINETOCLOSE)
			{
				if (proc->closepath)
					proc->closepath(ctx, arg);
				x = sx;
				y = sy;
			}
			break;
		case FZ_HORIZTO:
		case FZ_HORIZTOCLOSE:
			proc->lineto(ctx, arg,
				x = coords[k],
				y);
			k += 1;
			if (cmd == FZ_HORIZTOCLOSE)
			{
				if (proc->closepath)
					proc->closepath(ctx, arg);
				x = sx;
				y = sy;
			}
			break;
		case FZ_VERTTO:
		case FZ_VERTTOCLOSE:
			proc->lineto(ctx, arg,
				x,
				y = coords[k]);
			k += 1;
			if (cmd == FZ_VERTTOCLOSE)
			{
				if (proc->closepath)
					proc->closepath(ctx, arg);
				x = sx;
				y = sy;
			}
			break;
		case FZ_DEGENLINETO:
		case FZ_DEGENLINETOCLOSE:
			proc->lineto(ctx, arg,
				x,
				y);
			if (cmd == FZ_DEGENLINETOCLOSE)
			{
				if (proc->closepath)
					proc->closepath(ctx, arg);
				x = sx;
				y = sy;
			}
			break;
		case FZ_RECTTO:
			if (proc->rectto)
			{
				proc->rectto(ctx, arg,
						x = coords[k],
						y = coords[k+1],
						coords[k+2],
						coords[k+3]);
			}
			else
			{
				proc->moveto(ctx, arg,
					x = coords[k],
					y = coords[k+1]);
				proc->lineto(ctx, arg,
					coords[k+2],
					coords[k+1]);
				proc->lineto(ctx, arg,
					coords[k+2],
					coords[k+3]);
				proc->lineto(ctx, arg,
					coords[k],
					coords[k+3]);
				if (proc->closepath)
					proc->closepath(ctx, arg);
			}
			sx = x;
			sy = y;
			k += 4;
			break;
		}
	}
}

/*
	A couple of notes about the path bounding algorithm.

	Firstly, we don't expand the bounds immediately on a move, because
	a sequence of moves together will only actually use the last one,
	and trailing moves are ignored. This is achieved using 'trailing_move'.

	Secondly, we watch for paths that are entirely rectilinear (all segments
	move left/right/up/down only, with no curves). Such "only_right_angles"
	paths can be bounded with us ignoring any mitre limit. This is a really
	common case that can otherwise bloats simple boxes far more than is
	useful. This is particular annoying during table recognition!
*/
typedef struct
{
	fz_matrix ctm;
	fz_rect rect;
	fz_point move;
	int trailing_move;
	int first;
	int only_right_angles;
	fz_point prev;
} bound_path_arg;

static void
bound_moveto(fz_context *ctx, void *arg_, float x, float y)
{
	bound_path_arg *arg = (bound_path_arg *)arg_;
	arg->move = arg->prev = fz_transform_point_xy(x, y, arg->ctm);
	arg->trailing_move = 1;
}

static inline int
eq0(float x)
{
	return x >= -0.001 && x <= 0.001;
}

static void
bound_lineto(fz_context *ctx, void *arg_, float x, float y)
{
	bound_path_arg *arg = (bound_path_arg *)arg_;
	fz_point p = fz_transform_point_xy(x, y, arg->ctm);
	if (arg->first)
	{
		arg->rect.x0 = arg->rect.x1 = p.x;
		arg->rect.y0 = arg->rect.y1 = p.y;
		arg->first = 0;
	}
	else
		bound_expand(&arg->rect, p);
	if (arg->trailing_move)
	{
		arg->trailing_move = 0;
		bound_expand(&arg->rect, arg->move);
	}
	if (arg->only_right_angles && !eq0(arg->prev.x - p.x) && !eq0(arg->prev.y - p.y))
		arg->only_right_angles = 0;
	arg->prev = p;
}

static void
bound_curveto(fz_context *ctx, void *arg_, float x1, float y1, float x2, float y2, float x3, float y3)
{
	bound_path_arg *arg = (bound_path_arg *)arg_;
	fz_point p = fz_transform_point_xy(x1, y1, arg->ctm);
	if (arg->first)
	{
		arg->rect.x0 = arg->rect.x1 = p.x;
		arg->rect.y0 = arg->rect.y1 = p.y;
		arg->first = 0;
	}
	else
		bound_expand(&arg->rect, p);
	bound_expand(&arg->rect, fz_transform_point_xy(x2, y2, arg->ctm));
	bound_expand(&arg->rect, fz_transform_point_xy(x3, y3, arg->ctm));
	if (arg->trailing_move)
	{
		arg->trailing_move = 0;
		bound_expand(&arg->rect, arg->move);
	}
	arg->only_right_angles = 0;
	arg->prev = p;
}

static const fz_path_walker bound_path_walker =
{
	bound_moveto,
	bound_lineto,
	bound_curveto,
	NULL
};

static fz_rect
adjust_rect_for_stroke(fz_context *ctx, fz_rect r, const fz_stroke_state *stroke, fz_matrix ctm, int no_mitre)
{
	float expand;

	if (!stroke)
		return r;

	expand = stroke->linewidth/2;
	if (expand == 0)
		expand = 0.5f;
	if (r.x1 == r.x0 || r.y1 == r.y0)
	{
		/* Mitring can't apply in this case. */
	}
	else if (!no_mitre && stroke->linejoin == FZ_LINEJOIN_MITER && stroke->miterlimit > 0.5f)
	{
		/* miter limit is expressed in terms of the linewidth, not half the line width. */
		expand *= stroke->miterlimit * 2;
	}
	else if (!no_mitre && stroke->linejoin == FZ_LINEJOIN_MITER_XPS && stroke->miterlimit > 1.0f)
	{
		/* for xps, miter limit is expressed in terms of half the linewidth. */
		expand *= stroke->miterlimit;
	}

	expand *= fz_matrix_max_expansion(ctm);

	r.x0 -= expand;
	r.y0 -= expand;
	r.x1 += expand;
	r.y1 += expand;
	return r;
}

fz_rect
fz_bound_path(fz_context *ctx, const fz_path *path, const fz_stroke_state *stroke, fz_matrix ctm)
{
	bound_path_arg arg;

	arg.ctm = ctm;
	arg.rect = fz_empty_rect;
	arg.trailing_move = 0;
	arg.first = 1;
	arg.only_right_angles = 1;

	fz_walk_path(ctx, path, &bound_path_walker, &arg);

	if (!arg.first && stroke)
	{
		arg.rect = adjust_rect_for_stroke(ctx, arg.rect, stroke, ctm, arg.only_right_angles);
	}

	return arg.rect;
}

fz_rect
fz_adjust_rect_for_stroke(fz_context *ctx, fz_rect r, const fz_stroke_state *stroke, fz_matrix ctm)
{
	return adjust_rect_for_stroke(ctx, r, stroke, ctm, 0);
}

void
fz_transform_path(fz_context *ctx, fz_path *path, fz_matrix ctm)
{
	int i, k, n;
	fz_point p, p1, p2, p3, q, s;

	if (path->packed)
		fz_throw(ctx, FZ_ERROR_ARGUMENT, "Cannot transform a packed path");

	if (ctm.b == 0 && ctm.c == 0)
	{
		/* Simple, in place transform */
		i = 0;
		k = 0;
		while (i < path->cmd_len)
		{
			uint8_t cmd = path->cmds[i];

			switch (cmd)
			{
			case FZ_MOVETO:
			case FZ_LINETO:
			case FZ_MOVETOCLOSE:
			case FZ_LINETOCLOSE:
				n = 1;
				break;
			case FZ_DEGENLINETO:
			case FZ_DEGENLINETOCLOSE:
				n = 0;
				break;
			case FZ_CURVETO:
			case FZ_CURVETOCLOSE:
				n = 3;
				break;
			case FZ_RECTTO:
				s.x = path->coords[k];
				s.y = path->coords[k+1];
				n = 2;
				break;
			case FZ_CURVETOV:
			case FZ_CURVETOY:
			case FZ_QUADTO:
			case FZ_CURVETOVCLOSE:
			case FZ_CURVETOYCLOSE:
			case FZ_QUADTOCLOSE:
				n = 2;
				break;
			case FZ_HORIZTO:
			case FZ_HORIZTOCLOSE:
				q.x = path->coords[k];
				p = fz_transform_point(q, ctm);
				path->coords[k++] = p.x;
				n = 0;
				break;
			case FZ_VERTTO:
			case FZ_VERTTOCLOSE:
				q.y = path->coords[k];
				p = fz_transform_point(q, ctm);
				path->coords[k++] = p.y;
				n = 0;
				break;
			default:
				assert("Unknown path cmd" == NULL);
			}
			while (n > 0)
			{
				q.x = path->coords[k];
				q.y = path->coords[k+1];
				p = fz_transform_point(q, ctm);
				path->coords[k++] = p.x;
				path->coords[k++] = p.y;
				n--;
			}
			switch (cmd)
			{
			case FZ_MOVETO:
			case FZ_MOVETOCLOSE:
				s = q;
				break;
			case FZ_LINETOCLOSE:
			case FZ_DEGENLINETOCLOSE:
			case FZ_CURVETOCLOSE:
			case FZ_CURVETOVCLOSE:
			case FZ_CURVETOYCLOSE:
			case FZ_QUADTOCLOSE:
			case FZ_HORIZTOCLOSE:
			case FZ_VERTTOCLOSE:
			case FZ_RECTTO:
				q = s;
				break;
			}
			i++;
		}
	}
	else if (ctm.a == 0 && ctm.d == 0)
	{
		/* In place transform with command rewriting */
		i = 0;
		k = 0;
		while (i < path->cmd_len)
		{
			uint8_t cmd = path->cmds[i];

			switch (cmd)
			{
			case FZ_MOVETO:
			case FZ_LINETO:
			case FZ_MOVETOCLOSE:
			case FZ_LINETOCLOSE:
				n = 1;
				break;
			case FZ_DEGENLINETO:
			case FZ_DEGENLINETOCLOSE:
				n = 0;
				break;
			case FZ_CURVETO:
			case FZ_CURVETOCLOSE:
				n = 3;
				break;
			case FZ_RECTTO:
				s.x = path->coords[k];
				s.y = path->coords[k+1];
				n = 2;
				break;
			case FZ_CURVETOV:
			case FZ_CURVETOY:
			case FZ_QUADTO:
			case FZ_CURVETOVCLOSE:
			case FZ_CURVETOYCLOSE:
			case FZ_QUADTOCLOSE:
				n = 2;
				break;
			case FZ_HORIZTO:
				q.x = path->coords[k];
				p = fz_transform_point(q, ctm);
				path->coords[k++] = p.y;
				path->cmds[i] = FZ_VERTTO;
				n = 0;
				break;
			case FZ_HORIZTOCLOSE:
				q.x = path->coords[k];
				p = fz_transform_point(q, ctm);
				path->coords[k++] = p.y;
				path->cmds[i] = FZ_VERTTOCLOSE;
				n = 0;
				break;
			case FZ_VERTTO:
				q.y = path->coords[k];
				p = fz_transform_point(q, ctm);
				path->coords[k++] = p.x;
				path->cmds[i] = FZ_HORIZTO;
				n = 0;
				break;
			case FZ_VERTTOCLOSE:
				q.y = path->coords[k];
				p = fz_transform_point(q, ctm);
				path->coords[k++] = p.x;
				path->cmds[i] = FZ_HORIZTOCLOSE;
				n = 0;
				break;
			default:
				assert("Unknown path cmd" == NULL);
			}
			while (n > 0)
			{
				q.x = path->coords[k];
				q.y = path->coords[k+1];
				p = fz_transform_point(q, ctm);
				path->coords[k++] = p.x;
				path->coords[k++] = p.y;
				n--;
			}
			switch (cmd)
			{
			case FZ_MOVETO:
			case FZ_MOVETOCLOSE:
				s = q;
				break;
			case FZ_LINETOCLOSE:
			case FZ_DEGENLINETOCLOSE:
			case FZ_CURVETOCLOSE:
			case FZ_CURVETOVCLOSE:
			case FZ_CURVETOYCLOSE:
			case FZ_QUADTOCLOSE:
			case FZ_HORIZTOCLOSE:
			case FZ_VERTTOCLOSE:
			case FZ_RECTTO:
				q = s;
				break;
			}
			i++;
		}
	}
	else
	{
		int extra_coord = 0;
		int extra_cmd = 0;
		int coord_read, coord_write, cmd_read, cmd_write;

		/* General case. Have to allow for rects/horiz/verts
		 * becoming non-rects/horiz/verts. */
		for (i = 0; i < path->cmd_len; i++)
		{
			uint8_t cmd = path->cmds[i];
			switch (cmd)
			{
			case FZ_HORIZTO:
			case FZ_VERTTO:
			case FZ_HORIZTOCLOSE:
			case FZ_VERTTOCLOSE:
				extra_coord += 1;
				break;
			case FZ_RECTTO:
				extra_coord += 2;
				extra_cmd += 3;
				break;
			default:
				/* Do nothing */
				break;
			}
		}
		if (path->cmd_len + extra_cmd < path->cmd_cap)
		{
			path->cmds = fz_realloc_array(ctx, path->cmds, path->cmd_len + extra_cmd, unsigned char);
			path->cmd_cap = path->cmd_len + extra_cmd;
		}
		if (path->coord_len + extra_coord < path->coord_cap)
		{
			path->coords = fz_realloc_array(ctx, path->coords, path->coord_len + extra_coord, float);
			path->coord_cap = path->coord_len + extra_coord;
		}
		memmove(path->cmds + extra_cmd, path->cmds, path->cmd_len * sizeof(unsigned char));
		path->cmd_len += extra_cmd;
		memmove(path->coords + extra_coord, path->coords, path->coord_len * sizeof(float));
		path->coord_len += extra_coord;

		for (cmd_write = 0, cmd_read = extra_cmd, coord_write = 0, coord_read = extra_coord; cmd_read < path->cmd_len; i += 2)
		{
			uint8_t cmd = path->cmds[cmd_write++] = path->cmds[cmd_read++];

			switch (cmd)
			{
			case FZ_MOVETO:
			case FZ_LINETO:
			case FZ_MOVETOCLOSE:
			case FZ_LINETOCLOSE:
				n = 1;
				break;
			case FZ_DEGENLINETO:
			case FZ_DEGENLINETOCLOSE:
				n = 0;
				break;
			case FZ_CURVETO:
			case FZ_CURVETOCLOSE:
				n = 3;
				break;
			case FZ_CURVETOV:
			case FZ_CURVETOY:
			case FZ_QUADTO:
			case FZ_CURVETOVCLOSE:
			case FZ_CURVETOYCLOSE:
			case FZ_QUADTOCLOSE:
				n = 2;
				break;
			case FZ_RECTTO:
				p.x = path->coords[coord_read++];
				p.y = path->coords[coord_read++];
				p2.x = path->coords[coord_read++];
				p2.y = path->coords[coord_read++];
				p1.x = p2.x;
				p1.y = p.y;
				p3.x = p.x;
				p3.y = p2.y;
				s = p;
				p = fz_transform_point(p, ctm);
				p1 = fz_transform_point(p1, ctm);
				p2 = fz_transform_point(p2, ctm);
				p3 = fz_transform_point(p3, ctm);
				path->coords[coord_write++] = p.x;
				path->coords[coord_write++] = p.y;
				path->coords[coord_write++] = p1.x;
				path->coords[coord_write++] = p1.y;
				path->coords[coord_write++] = p2.x;
				path->coords[coord_write++] = p2.y;
				path->coords[coord_write++] = p3.x;
				path->coords[coord_write++] = p3.y;
				path->cmds[cmd_write-1] = FZ_MOVETO;
				path->cmds[cmd_write++] = FZ_LINETO;
				path->cmds[cmd_write++] = FZ_LINETO;
				path->cmds[cmd_write++] = FZ_LINETOCLOSE;
				n = 0;
				break;
			case FZ_HORIZTO:
				q.x = path->coords[coord_read++];
				p = fz_transform_point(q, ctm);
				path->coords[coord_write++] = p.x;
				path->coords[coord_write++] = p.y;
				path->cmds[cmd_write-1] = FZ_LINETO;
				n = 0;
				break;
			case FZ_HORIZTOCLOSE:
				p.x = path->coords[coord_read++];
				p.y = q.y;
				p = fz_transform_point(p, ctm);
				path->coords[coord_write++] = p.x;
				path->coords[coord_write++] = p.y;
				path->cmds[cmd_write-1] = FZ_LINETOCLOSE;
				q = s;
				n = 0;
				break;
			case FZ_VERTTO:
				q.y = path->coords[coord_read++];
				p = fz_transform_point(q, ctm);
				path->coords[coord_write++] = p.x;
				path->coords[coord_write++] = p.y;
				path->cmds[cmd_write-1] = FZ_LINETO;
				n = 0;
				break;
			case FZ_VERTTOCLOSE:
				p.x = q.x;
				p.y = path->coords[coord_read++];
				p = fz_transform_point(p, ctm);
				path->coords[coord_write++] = p.x;
				path->coords[coord_write++] = p.y;
				path->cmds[cmd_write-1] = FZ_LINETOCLOSE;
				q = s;
				n = 0;
				break;
			default:
				assert("Unknown path cmd" == NULL);
			}
			while (n > 0)
			{
				q.x = path->coords[coord_read++];
				q.y = path->coords[coord_read++];
				p = fz_transform_point(q, ctm);
				path->coords[coord_write++] = p.x;
				path->coords[coord_write++] = p.y;
				n--;
			}
			switch (cmd)
			{
			case FZ_MOVETO:
			case FZ_MOVETOCLOSE:
				s = q;
				break;
			case FZ_LINETOCLOSE:
			case FZ_DEGENLINETOCLOSE:
			case FZ_CURVETOCLOSE:
			case FZ_CURVETOYCLOSE:
			case FZ_CURVETOVCLOSE:
			case FZ_QUADTOCLOSE:
			case FZ_HORIZTOCLOSE:
			case FZ_VERTTOCLOSE:
			case FZ_RECTTO:
				q = s;
				break;
			}
		}
	}
}

void fz_trim_path(fz_context *ctx, fz_path *path)
{
	if (path->packed)
		fz_throw(ctx, FZ_ERROR_ARGUMENT, "Can't trim a packed path");
	if (path->cmd_cap > path->cmd_len)
	{
		path->cmds = fz_realloc_array(ctx, path->cmds, path->cmd_len, unsigned char);
		path->cmd_cap = path->cmd_len;
	}
	if (path->coord_cap > path->coord_len)
	{
		path->coords = fz_realloc_array(ctx, path->coords, path->coord_len, float);
		path->coord_cap = path->coord_len;
	}
}

const fz_stroke_state fz_default_stroke_state = {
	-2, /* -2 is the magic number we use when we have stroke states stored on the stack */
	FZ_LINECAP_BUTT, FZ_LINECAP_BUTT, FZ_LINECAP_BUTT,
	FZ_LINEJOIN_MITER,
	1, 10,
	0, 0, { 0 }
};

fz_stroke_state *
fz_keep_stroke_state(fz_context *ctx, const fz_stroke_state *strokec)
{
	fz_stroke_state *stroke = (fz_stroke_state *)strokec; /* Explicit cast away of const */

	if (!stroke)
		return NULL;

	/* -2 is the magic number we use when we have stroke states stored on the stack */
	if (stroke->refs == -2)
		return fz_clone_stroke_state(ctx, stroke);

	return fz_keep_imp(ctx, stroke, &stroke->refs);
}

int
fz_stroke_state_eq(fz_context *ctx, const fz_stroke_state *a, const fz_stroke_state *b)
{
	int i;

	if (a == NULL && b == NULL) return 1;

	if (a == NULL && b != NULL) return 0;
	if (a != NULL && b == NULL) return 0;

	if (a->start_cap != b->start_cap) return 0;
	if (a->dash_cap != b->dash_cap) return 0;
	if (a->end_cap != b->end_cap) return 0;
	if (a->linejoin != b->linejoin) return 0;
	if (a->linewidth != b->linewidth) return 0;
	if (a->miterlimit != b->miterlimit) return 0;
	if (a->dash_phase != b->dash_phase) return 0;
	if (a->dash_len != b->dash_len) return 0;

	for (i = 0; i < a->dash_len; i++)
		if (a->dash_list[i] != b->dash_list[i]) return 0;

	return 1;
}

void
fz_drop_stroke_state(fz_context *ctx, const fz_stroke_state *strokec)
{
	fz_stroke_state *stroke = (fz_stroke_state *)strokec; /* Explicit cast away of const */

	if (fz_drop_imp(ctx, stroke, &stroke->refs))
		fz_free(ctx, stroke);
}

fz_stroke_state *
fz_new_stroke_state_with_dash_len(fz_context *ctx, int len)
{
	fz_stroke_state *state;

	if (len < 0)
		len = 0;

	state = fz_malloc_flexible(ctx, fz_stroke_state, dash_list, len);
	state->refs = 1;
	state->start_cap = FZ_LINECAP_BUTT;
	state->dash_cap = FZ_LINECAP_BUTT;
	state->end_cap = FZ_LINECAP_BUTT;
	state->linejoin = FZ_LINEJOIN_MITER;
	state->linewidth = 1;
	state->miterlimit = 10;
	state->dash_phase = 0;
	state->dash_len = 0;

	return state;
}

fz_stroke_state *
fz_new_stroke_state(fz_context *ctx)
{
	return fz_new_stroke_state_with_dash_len(ctx, 0);
}

fz_linecap
fz_linecap_from_string(const char *str)
{
	if (!strcmp(str, "Round"))
		return FZ_LINECAP_ROUND;
	if (!strcmp(str, "Square"))
		return FZ_LINECAP_SQUARE;
	if (!strcmp(str, "Triangle"))
		return FZ_LINECAP_TRIANGLE;
	return FZ_LINECAP_BUTT;
}

const char *
fz_string_from_linecap(fz_linecap cap)
{
	switch (cap) {
	default:
	case FZ_LINECAP_BUTT: return "Butt";
	case FZ_LINECAP_ROUND: return "Round";
	case FZ_LINECAP_SQUARE: return "Square";
	case FZ_LINECAP_TRIANGLE: return "Triangle";
	}
}

fz_linejoin
fz_linejoin_from_string(const char *str)
{
	if (!strcmp(str, "Round"))
		return FZ_LINEJOIN_ROUND;
	if (!strcmp(str, "Bevel"))
		return FZ_LINEJOIN_BEVEL;
	if (!strcmp(str, "MiterXPS"))
		return FZ_LINEJOIN_MITER_XPS;
	return FZ_LINEJOIN_MITER;
}

const char *
fz_string_from_linejoin(fz_linejoin join)
{
	switch (join) {
	default:
	case FZ_LINEJOIN_MITER: return "Miter";
	case FZ_LINEJOIN_ROUND: return "Round";
	case FZ_LINEJOIN_BEVEL: return "Bevel";
	case FZ_LINEJOIN_MITER_XPS: return "MiterXPS";
	}
}

fz_stroke_state *
fz_clone_stroke_state(fz_context *ctx, const fz_stroke_state *stroke)
{
	fz_stroke_state *clone = fz_new_stroke_state_with_dash_len(ctx, stroke->dash_len);
	size_t size = offsetof(fz_stroke_state, dash_list) + sizeof(float) * stroke->dash_len;
	memcpy(clone, stroke, size);
	clone->refs = 1;
	return clone;
}

fz_stroke_state *
fz_unshare_stroke_state_with_dash_len(fz_context *ctx, fz_stroke_state *shared, int len)
{
	int single;
	fz_stroke_state *unshared;

	fz_lock(ctx, FZ_LOCK_ALLOC);
	single = (shared->refs == 1);
	fz_unlock(ctx, FZ_LOCK_ALLOC);

	if (single && len == shared->dash_len)
		return shared;

	unshared = fz_new_stroke_state_with_dash_len(ctx, len);
	if (shared->dash_len >= len)
		memcpy(unshared, shared, offsetof(fz_stroke_state, dash_list) + sizeof(float) * len);
	else
		memcpy(unshared, shared, offsetof(fz_stroke_state, dash_list));
	unshared->refs = 1;
	unshared->dash_len = len;

	if (fz_drop_imp(ctx, shared, &shared->refs))
		fz_free(ctx, shared);
	return unshared;
}

fz_stroke_state *
fz_unshare_stroke_state(fz_context *ctx, fz_stroke_state *shared)
{
	return fz_unshare_stroke_state_with_dash_len(ctx, shared, shared->dash_len);
}

static void *
clone_block(fz_context *ctx, void *block, size_t len)
{
	void *target;

	if (len == 0 || block == NULL)
		return NULL;

	target = fz_malloc(ctx, len);
	memcpy(target, block, len);
	return target;
}

fz_path *
fz_clone_path(fz_context *ctx, fz_path *path)
{
	fz_path *new_path;

	assert(ctx != NULL);

	if (path == NULL)
		return NULL;

	new_path = fz_malloc_struct(ctx, fz_path);
	new_path->refs = 1;
	new_path->packed = FZ_PATH_UNPACKED;
	fz_try(ctx)
	{
		switch(path->packed)
		{
		case FZ_PATH_UNPACKED:
		case FZ_PATH_PACKED_OPEN:
			new_path->cmd_len = path->cmd_len;
			new_path->cmd_cap = path->cmd_cap;
			new_path->cmds = Memento_label(clone_block(ctx, path->cmds, path->cmd_cap), "path_cmds");
			new_path->coord_len = path->coord_len;
			new_path->coord_cap = path->coord_cap;
			new_path->coords = Memento_label(clone_block(ctx, path->coords, sizeof(float)*path->coord_cap), "path_coords");
			new_path->current = path->current;
			new_path->begin = path->begin;
			break;
		case FZ_PATH_PACKED_FLAT:
			{
				uint8_t *data;
				float *xy;
				int i;
				fz_packed_path *ppath = (fz_packed_path *)path;

				new_path->cmd_len = ppath->cmd_len;
				new_path->cmd_cap = ppath->cmd_len;
				new_path->coord_len = ppath->coord_len;
				new_path->coord_cap = ppath->coord_len;
				data = (uint8_t *)&ppath[1];
				new_path->coords = Memento_label(clone_block(ctx, data, sizeof(float)*path->coord_cap), "path_coords");
				data += sizeof(float) * path->coord_cap;
				new_path->cmds = Memento_label(clone_block(ctx, data, path->cmd_cap), "path_cmds");
				xy = new_path->coords;
				for (i = 0; i < new_path->cmd_len; i++)
				{
					switch (new_path->cmds[i])
					{
					case FZ_MOVETOCLOSE:
					case FZ_MOVETO:
						new_path->current.x = *xy++;
						new_path->current.y = *xy++;
						new_path->begin.x = new_path->current.x;
						new_path->begin.y = new_path->current.y;
						break;
					case FZ_CURVETO:
						xy += 2;
						/* fallthrough */
					case FZ_CURVETOV:
					case FZ_CURVETOY:
					case FZ_QUADTO:
						/* fallthrough */
						xy += 2;
					case FZ_LINETO:
						new_path->current.x = *xy++;
						new_path->current.y = *xy++;
						break;
					case FZ_DEGENLINETO:
						break;
					case FZ_HORIZTO:
						new_path->current.x = *xy++;
						break;
					case FZ_VERTTO:
						new_path->current.y = *xy++;
						break;
					case FZ_RECTTO:
						xy += 2;
						break;
					case FZ_CURVETOCLOSE:
						xy += 2;
						/* fallthrough */
					case FZ_CURVETOVCLOSE:
					case FZ_CURVETOYCLOSE:
					case FZ_QUADTOCLOSE:
					case FZ_LINETOCLOSE:
						xy++;
						/* fallthrough */
					case FZ_HORIZTOCLOSE:
					case FZ_VERTTOCLOSE:
						xy++;
						/* fallthrough */
					case FZ_DEGENLINETOCLOSE:
						new_path->current.x = new_path->begin.x;
						new_path->current.y = new_path->begin.y;
						break;
					}
				}
			}
		default:
			assert(!"Unknown packing method found in path");
		}
	}
	fz_catch(ctx)
	{
		fz_free(ctx, new_path->coords);
		fz_free(ctx, new_path->cmds);
		fz_free(ctx, new_path);
		fz_rethrow(ctx);
	}
	return new_path;
}

typedef struct
{
	fz_matrix ctm;
	fz_point p[4];
	int count;
	int trailing_move;
} rect_path_arg;

static void
rect_moveto(fz_context *ctx, void *arg_, float x, float y)
{
	rect_path_arg *arg = (rect_path_arg *)arg_;
	fz_point p = fz_transform_point_xy(x, y, arg->ctm);

	/* If we've already decided that it's not a rectangle. Just exit. */
	if (arg->count < 0)
		return;

	/* We should never get multiple successive moves, by construction. */

	/* If we're starting out... */
	if (arg->count == 0)
	{
		arg->p[0] = p;
		arg->count = 1;
		return;
	}

	/* Otherwise, any move is fine, as long as it's not followed by another line... */
	arg->trailing_move = 1;
}

static void
rect_lineto(fz_context *ctx, void *arg_, float x, float y)
{
	rect_path_arg *arg = (rect_path_arg *)arg_;
	fz_point p = fz_transform_point_xy(x, y, arg->ctm);

	/* If we've already decided that it's not a rectangle. Just exit. */
	if (arg->count < 0)
		return;

	if (arg->trailing_move)
	{
		arg->count = -1;
		return;
	}

	/* Watch for pesky lines back to the same place. */
	if (arg->p[arg->count-1].x == p.x && arg->p[arg->count-1].y == p.y)
		return;

	if (arg->count < 4)
	{
		arg->p[arg->count++] = p;
		return;
	}

	/* Allow for lines back to the start. */
	if (arg->count == 4)
	{
		if (arg->p[0].x == p.x && arg->p[0].y == p.y)
		{
			arg->count++;
			return;
		}
	}

	arg->count = -1;
}

static void
rect_curveto(fz_context *ctx, void *arg_, float x1, float y1, float x2, float y2, float x3, float y3)
{
	rect_path_arg *arg = (rect_path_arg *)arg_;

	arg->count = -1;
}

static const fz_path_walker rect_path_walker =
{
	rect_moveto,
	rect_lineto,
	rect_curveto,
	NULL
};

int
fz_path_is_rect(fz_context *ctx, const fz_path *path, fz_matrix ctm)
{
	return fz_path_is_rect_with_bounds(ctx, path, ctm, NULL);
}

int
fz_path_is_rect_with_bounds(fz_context *ctx, const fz_path *path, fz_matrix ctm, fz_rect *bounds)
{
	rect_path_arg arg;

	arg.ctm = ctm;
	arg.trailing_move = 0;
	arg.count = 0;

	fz_walk_path(ctx, path, &rect_path_walker, &arg);

	if (arg.count < 0)
		return 0;

	/* 3 entries are bad, unless the last one returns the first. */
	if (arg.count == 3 && (arg.p[0].x != arg.p[2].x || arg.p[0].y != arg.p[2].y))
	{
		return 0;
	}
	if (arg.count == 2 || arg.count == 3)
	{
		if (arg.p[0].x == arg.p[1].x || arg.p[0].y == arg.p[1].y)
		{
			if (bounds)
			{
				bounds->x0 = fz_min(arg.p[0].x, arg.p[1].x);
				bounds->x1 = fz_max(arg.p[0].x, arg.p[1].x);
				bounds->y0 = fz_min(arg.p[0].y, arg.p[1].y);
				bounds->y1 = fz_max(arg.p[0].y, arg.p[1].y);
			}
			return 1;
		}
	}
	/* All that's left are 4 entry ones */
	if (arg.count != 4)
		return 0;

	if (arg.p[0].x == arg.p[1].x)
	{
		/* p[0]  p[3]
		 * p[1]  p[2]
		 */
		if (arg.p[1].y == arg.p[2].y && arg.p[0].y == arg.p[3].y && arg.p[2].x == arg.p[3].x)
		{
			if (bounds)
			{
				bounds->x0 = fz_min(arg.p[0].x, arg.p[3].x);
				bounds->x1 = fz_max(arg.p[0].x, arg.p[3].x);
				bounds->y0 = fz_min(arg.p[0].y, arg.p[1].y);
				bounds->y1 = fz_max(arg.p[0].y, arg.p[1].y);
			}
			return 1;
		}
	}
	if (arg.p[0].y == arg.p[1].y)
	{
		/* p[0]  p[1]
		 * p[3]  p[2]
		 */
		if (arg.p[1].x == arg.p[2].x && arg.p[0].x == arg.p[3].x && arg.p[2].y == arg.p[3].y)
		{
			if (bounds)
			{
				bounds->x0 = fz_min(arg.p[0].x, arg.p[1].x);
				bounds->x1 = fz_max(arg.p[0].x, arg.p[1].x);
				bounds->y0 = fz_min(arg.p[0].y, arg.p[3].y);
				bounds->y1 = fz_max(arg.p[0].y, arg.p[3].y);
			}
			return 1;
		}
	}
	return 0;
}

typedef struct
{
	int unclosed;
	int active;
	float move_x;
	float move_y;
	float last_x;
	float last_y;
} closed_arg;

static void
closed_moveto(fz_context *ctx, void *arg_, float x, float y)
{
	closed_arg *arg = (closed_arg *)arg_;

	if (arg->active)
	{
		if (arg->move_x != arg->last_x || arg->move_y != arg->last_y)
			arg->unclosed = 1;
	}
	arg->active = 0;
	arg->move_x = x;
	arg->move_y = y;
	arg->last_x = x;
	arg->last_y = y;
}

static void
closed_lineto(fz_context *ctx, void *arg_, float x, float y)
{
	closed_arg *arg = (closed_arg *)arg_;

	arg->active = 1;
	arg->last_x = x;
	arg->last_y = y;
}

static void
closed_curveto(fz_context *ctx, void *arg_, float x0, float y0, float x1, float y1, float x2, float y2)
{
	closed_arg *arg = (closed_arg *)arg_;

	arg->active = 1;
	arg->last_x = x2;
	arg->last_y = y2;
}

static void
closed_close(fz_context *ctx, void *arg_)
{
	closed_arg *arg = (closed_arg *)arg_;

	arg->active = 0;
}

static const fz_path_walker closed_path_walker =
{
	closed_moveto,
	closed_lineto,
	closed_curveto,
	closed_close
};

int
fz_path_is_closed(fz_context *ctx, const fz_path *path)
{
	closed_arg arg = { 0 };

	fz_walk_path(ctx, path, &closed_path_walker, &arg);

	if (arg.active)
	{
		if (arg.move_x != arg.last_x || arg.move_y != arg.last_y)
			arg.unclosed = 1;
	}

	return !arg.unclosed;
}
