#include <fitz.h>

fz_error *fz_fillpath(fz_gel *gel, fz_path *path, fz_matrix ctm, float flatness);
fz_error *fz_strokepath(fz_gel *gel, fz_path *path, fz_matrix ctm, float flatness);
fz_error *fz_dashpath(fz_gel *gel, fz_path *path, fz_matrix ctm, float flatness);

int main(int argc, char **argv)
{
	fz_path *path;
	fz_gel *gel;
	fz_ael *ael;
	fz_matrix ctm;
	fz_dash *dash;
	fz_stroke stroke = { 1, 1, 4.0, 15.0 };
	float dashes[] = { 20, 20, 5, 10 };
	int i;

	fz_newdash(&dash, 0.0, 2, dashes);

	fz_newpath(&path);

	/* AGaramond-Regular: 'X' */
	if (getenv("X")) {
		fz_moveto(path, 631, 25);
		fz_lineto(path, 666, 22);
		fz_curveto(path, 673, 16, 672, 2, 665, -3);
		fz_curveto(path, 619, -1, 580, 0, 539, 0);
		fz_curveto(path, 494, 0, 446, -1, 410, -3);
		fz_curveto(path, 404, 3, 403, 16, 408, 22);
		fz_lineto(path, 437, 25);
		fz_curveto(path, 460, 27, 471, 31, 471, 38);
		fz_curveto(path, 471, 44, 468, 54, 449, 82);
		fz_curveto(path, 405, 143, 350, 226, 306, 283);
		fz_curveto(path, 279, 249, 205, 140, 165, 70);
		fz_curveto(path, 157, 56, 152, 45, 152, 38);
		fz_curveto(path, 152, 32, 161, 27, 181, 25);
		fz_lineto(path, 208, 22);
		fz_curveto(path, 215, 16, 213, 2, 207, -3);
		fz_curveto(path, 171, -1, 133, 0, 99, 0);
		fz_curveto(path, 65, 0, 28, -1, -4, -3);
		fz_curveto(path, -13, 1, -14, 16, -7, 22);
		fz_lineto(path, 18, 25);
		fz_curveto(path, 72, 31, 107, 74, 137, 114);
		fz_curveto(path, 149, 130, 218, 218, 273, 298);
		fz_curveto(path, 280, 308, 282, 315, 282, 318);
		fz_curveto(path, 282, 321, 278, 330, 270, 341);
		fz_lineto(path, 120, 556);
		fz_curveto(path, 87, 603, 68, 625, 33, 631);
		fz_lineto(path, 1, 638);
		fz_curveto(path, -4, 644, -3, 660, 3, 663);
		fz_curveto(path, 50, 661, 83, 660, 119, 660);
		fz_curveto(path, 158, 660, 203, 661, 232, 663);
		fz_curveto(path, 239, 660, 240, 645, 234, 638);
		fz_lineto(path, 206, 636);
		fz_curveto(path, 188, 635, 176, 629, 176, 623);
		fz_curveto(path, 176, 614, 187, 597, 206, 568);
		fz_curveto(path, 240, 520, 298, 430, 334, 385);
		fz_curveto(path, 360, 417, 450, 559, 468, 589);
		fz_curveto(path, 476, 602, 482, 615, 482, 622);
		fz_curveto(path, 482, 627, 467, 633, 449, 635);
		fz_lineto(path, 423, 638);
		fz_curveto(path, 417, 645, 417, 659, 425, 663);
		fz_curveto(path, 460, 661, 492, 660, 531, 660);
		fz_curveto(path, 568, 660, 596, 661, 627, 663);
		fz_curveto(path, 634, 658, 635, 644, 629, 638);
		fz_lineto(path, 605, 636);
		fz_curveto(path, 575, 633, 539, 603, 498, 551);
		fz_curveto(path, 459, 501, 416, 441, 368, 374);
		fz_curveto(path, 362, 365, 358, 358, 358, 355);
		fz_curveto(path, 358, 352, 359, 345, 371, 329);
		fz_lineto(path, 540, 91);
		fz_curveto(path, 574, 44, 600, 28, 631, 25);
		fz_closepath(path);
	}

	/* AGaramond-Regular: 'g' */
	if (getenv("g")) {
		fz_moveto(path, 365, 372);
		fz_lineto(path, 446, 372);
		fz_curveto(path, 457, 367, 455, 333, 440, 331);
		fz_lineto(path, 368, 331);
		fz_curveto(path, 370, 314, 370, 297, 370, 280);
		fz_curveto(path, 370, 211, 329, 121, 202, 121);
		fz_curveto(path, 184, 121, 170, 123, 158, 124);
		fz_curveto(path, 146, 117, 114, 98, 114, 69);
		fz_curveto(path, 114, 46, 137, 27, 184, 27);
		fz_curveto(path, 218, 27, 259, 30, 303, 30);
		fz_curveto(path, 359, 30, 443, 20, 443, -80);
		fz_curveto(path, 443, -189, 324, -269, 194, -269);
		fz_curveto(path, 71, -269, 28, -203, 28, -153);
		fz_curveto(path, 28, -137, 32, -124, 39, -116);
		fz_curveto(path, 56, -98, 84, -72, 107, -49);
		fz_curveto(path, 116, -40, 124, -31, 115, -25);
		fz_curveto(path, 76, -15, 42, 19, 42, 54);
		fz_curveto(path, 42, 59, 46, 63, 57, 71);
		fz_curveto(path, 74, 82, 93, 99, 110, 117);
		fz_curveto(path, 115, 123, 120, 131, 120, 136);
		fz_curveto(path, 86, 154, 45, 193, 45, 257);
		fz_curveto(path, 45, 343, 119, 408, 208, 408);
		fz_curveto(path, 246, 408, 281, 398, 304, 388);
		fz_curveto(path, 336, 374, 343, 372, 365, 372);
		fz_closepath(path);
		fz_moveto(path, 271, -32);
		fz_lineto(path, 237, -32);
		fz_curveto(path, 205, -32, 165, -34, 151, -43);
		fz_curveto(path, 127, -58, 103, -89, 103, -127);
		fz_curveto(path, 103, -181, 146, -226, 237, -226);
		fz_curveto(path, 326, -226, 385, -176, 385, -119);
		fz_curveto(path, 385, -58, 343, -32, 271, -32);
		fz_closepath(path);
		fz_moveto(path, 217, 150);
		fz_curveto(path, 271, 150, 299, 193, 299, 254);
		fz_curveto(path, 299, 322, 271, 379, 210, 379);
		fz_curveto(path, 162, 379, 126, 335, 126, 267);
		fz_curveto(path, 126, 196, 169, 150, 217, 150);
		fz_closepath(path);
	}

	/* AGaramond-Regular: 'i' */
	if (getenv("i"))
	{
		fz_moveto(path, 98, 112);
		fz_lineto(path, 98, 287);
		fz_curveto(path, 98, 326, 98, 331, 71, 349);
		fz_lineto(path, 62, 355);
		fz_curveto(path, 58, 359, 58, 370, 63, 373);
		fz_curveto(path, 86, 381, 143, 407, 166, 422);
		fz_curveto(path, 171, 422, 175, 420, 176, 416);
		fz_curveto(path, 174, 381, 172, 333, 172, 292);
		fz_lineto(path, 172, 112);
		fz_curveto(path, 172, 40, 174, 30, 210, 25);
		fz_lineto(path, 231, 22);
		fz_curveto(path, 238, 17, 236, 0, 229, -3);
		fz_curveto(path, 199, -1, 170, 0, 135, 0);
		fz_curveto(path, 99, 0, 69, -1, 41, -3);
		fz_curveto(path, 34, 0, 32, 17, 39, 22);
		fz_lineto(path, 60, 25);
		fz_curveto(path, 97, 30, 98, 40, 98, 112);
		fz_closepath(path);
		fz_moveto(path, 131, 662);
		fz_curveto(path, 161, 662, 180, 639, 180, 611);
		fz_curveto(path, 180, 576, 155, 560, 128, 560);
		fz_curveto(path, 97, 560, 77, 582, 77, 609);
		fz_curveto(path, 77, 642, 102, 662, 131, 662);
		fz_closepath(path);
	}

	if (getenv("rect"))
	{
		//fz_moveto(path, 103, 100);
		//fz_lineto(path, 432, 400);
		//fz_lineto(path, 400, 100);
		//fz_closepath(path);

//		fz_moveto(path, 103, 100);
//		fz_lineto(path, 432, 400);
//		fz_lineto(path, 100, 400);
//		fz_closepath(path);

		fz_moveto(path, 199, 100);
		fz_lineto(path, 100, 200);
		fz_lineto(path, 300, 200);
		fz_lineto(path, 201, 100);

		fz_moveto(path, 150, 100);
		fz_lineto(path, 150, 100);
		fz_closepath(path);
	}

	fz_moveto(path, 100, 100);
	for (i = 0; i < 30; i++)
		fz_lineto(path, 100 + i * 10, 100 + i * 5);

	fz_endpath(path, FZ_STROKE, &stroke, dash);

	ctm = fz_identity();
	ctm = fz_concat(ctm, fz_rotate(0));
	ctm = fz_concat(ctm, fz_translate(100, -700));
	ctm = fz_concat(ctm, fz_scale(1.0, -1.0));

	fz_newgel(&gel);
	fz_newael(&ael);

	fz_resetgel(gel, 17, 15);
	// fz_fillpath(gel, path, ctm, 0.25);
	// fz_strokepath(gel, path, ctm, 0.25);
	fz_dashpath(gel, path, ctm, 0.25);
	fz_sortgel(gel);

/*
	for (i = 0; i < gel->len; i++)
	{
		printf("edge %d,%d to ?,%d\n",
			gel->edges[i].x,
			gel->edges[i].y,
			gel->edges[i].y + gel->edges[i].h);
	}
*/

	fz_scanconvert(gel, ael, 0);

	return 0;
}

