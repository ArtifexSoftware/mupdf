/*
 * Rasterizer
 */

#ifdef _FITZ_DRAW_H_
#error "fitz-draw.h must only be included once"
#endif
#define _FITZ_DRAW_H_

#ifndef _FITZ_BASE_H_
#error "fitz-base.h must be included before fitz-draw.h"
#endif

#ifndef _FITZ_WORLD_H_
#error "fitz-world.h must be included before fitz-draw.h"
#endif

#include "fitz/pathscan.h"
#include "fitz/render.h"

