.. default-domain:: js

.. highlight:: javascript

PDFProcessor
======================

A PDF processor object provides callbacks that will be called for each PDF operator
when it is passed to `PDFAnnotation.prototype.process` and `PDFPage.prototype.process`.
The callbacks correspond to the equivalent PDF operator.
Refer to the PDF specification for what these do and what the callback arguments are.

Special resource tracking
-------------------------

These are not operators per se, but are called when the
current resource dictionary used changes such as when
executing XObject forms.

- push_resources(resources)
- pop_resources()

General graphics state callbacks
-------------------------------------------

- op_w(lineWidth)
- op_j(lineJoin)
- op_J(lineCap)
- op_M(miterLimit)
- op_d(dashPattern, phase)
- op_ri(intent)
- op_i(flatness)
- op_gs(name, extGState)

Special graphics state
-------------------------------------------

- op_q()
- op_Q()
- op_cm(a, b, c, d, e, f)

Path construction
-------------------------------------------

- op_m(x, y)
- op_l(x, y)
- op_c(x1, y1, x2, y2, x3, y3)
- op_v(x2, y2, x3, y3)
- op_y(x1, y1, x3, y3)
- op_h()
- op_re(x, y, w, h)

Path painting
-------------------------------------------

- op_S()
- op_s()
- op_F()
- op_f()
- op_fstar()
- op_B()
- op_Bstar()
- op_b()
- op_bstar()
- op_n()

Clipping paths
-------------------------------------------

- op_W()
- op_Wstar()

Text objects
-------------------------------------------

- op_BT()
- op_ET()

Text state
-------------------------------------------

- op_Tc(charSpace)
- op_Tw(wordSpace)
- op_Tz(scale)
- op_TL(leading)
- op_Tf(name, size)
- op_Tr(render)
- op_Ts(rise)

Text positioning
-------------------------------------------

- op_Td(tx, ty)
- op_TD(tx, ty)
- op_Tm(a, b, c, d, e, f)
- op_Tstar()

Text showing
-------------------------------------------

- op_TJ(textArray)
- op_Tj(stringOrByteArray)
- op_squote(stringOrByteArray)
- op_dquote(wordSpace, charSpace, stringOrByteArray)

Type 3 fonts
-------------------------------------------

- op_d0(wx, wy)
- op_d1(wx, wy, llx, lly, urx, ury)

Color
-------------------------------------------

- op_CS(name, colorspace)
- op_cs(name, colorspace)
- op_SC_color(color)
- op_sc_color(color)

- op_SC_pattern(name, patternID, color)
- op_sc_pattern(name, patternID, color)
- op_SC_shade(name, shade)
- op_sc_shade(name, shade)

- op_G(gray)
- op_g(gray)
- op_RG(r, g, b)
- op_rg(r, g, b)
- op_K(c, m, y, k)
- op_k(c, m, y, k)

Shadings
-------------------------------------------

- op_sh(name, shade)

Inline images
-------------------------------------------

- op_BI(image, colorspace)

XObjects (Images and Forms)
-------------------------------------------

- op_Do_image(name, image)
- op_Do_form(xobject, resources)

Marked content
-------------------------------------------

- op_MP(tag)
- op_DP(tag, raw)
- op_BMC(tag)
- op_BDC(tag, raw)
- op_EMC()

Compatibility
-------------------------------------------

- op_BX()
- op_EX()
