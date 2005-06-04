/*
 * Streams and dynamic objects
 */

#ifdef _FITZ_STREAM_H_
#error "fitz-stream.h must only be included once"
#endif
#define _FITZ_STREAM_H_

#ifndef _FITZ_BASE_H_
#error "fitz-base.h must be included before fitz-stream.h"
#endif

#include "fitz/crypt.h"
#include "fitz/object.h"
#include "fitz/buffer.h"
#include "fitz/filter.h"
#include "fitz/stream.h"

