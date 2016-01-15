// File: Bidi.h
//
/*    For use with Bidi Reference Implementation
    For more information see the associated file bidi.cpp

    Credits:
    -------
    Written by: Asmus Freytag
    Command line interface by: Rick McGowan
    Verification (v24): Doug Felt

    Disclaimer and legal rights:
    ---------------------------
    Copyright (C) 1999-2009, ASMUS, Inc. All Rights Reserved.
    Distributed under the Terms of Use in http://www.unicode.org/copyright.html.

    THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
    IN NO EVENT SHALL THE COPYRIGHT HOLDER OR HOLDERS INCLUDED IN THIS NOTICE
    BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES,
    OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
    WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
    ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THE SOFTWARE.

     The files bidi.rc, and resource.h are distributed together with this file and are included 
     in the above definition of software.
*/
// Copyright (C) 1999-2009, ASMUS, Inc.     All Rights Reserved

#include "mupdf/fitz.h"

void Bidi_resolveNeutrals(int baselevel, int *pcls, const int *plevel, int cch);
void Bidi_resolveImplicit(const int * pcls, int * plevel, int cch);
void Bidi_resolveWeak(fz_context *ctx, int baselevel, int *pcls, int *plevel, int cch);
void Bidi_resolveWhitespace(int baselevel, const int *pcls, int *plevel, int cch);
int Bidi_resolveExplicit(int level, int dir, int * pcls, int * plevel, int cch, int nNest);
