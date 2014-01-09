#include "common.h"

fz_context *ctx;
dispatch_queue_t queue;
float screenScale = 1;

CGSize fitPageToScreen(CGSize page, CGSize screen)
{
	float hscale = screen.width / page.width;
	float vscale = screen.height / page.height;
	float scale = fz_min(hscale, vscale);
	hscale = floorf(page.width * scale) / page.width;
	vscale = floorf(page.height * scale) / page.height;
	return CGSizeMake(hscale, vscale);
}

static int hit_count = 0;
static fz_rect hit_bbox[500];

int search_page(fz_document *doc, int number, char *needle, fz_cookie *cookie)
{
	fz_page *page = fz_load_page(doc, number);

	fz_text_sheet *sheet = fz_new_text_sheet(ctx);
	fz_text_page *text = fz_new_text_page(ctx);
	fz_device *dev = fz_new_text_device(ctx, sheet, text);
	fz_run_page(doc, page, dev, &fz_identity, cookie);
	fz_free_device(dev);

	hit_count = fz_search_text_page(ctx, text, needle, hit_bbox, nelem(hit_bbox));

	fz_free_text_page(ctx, text);
	fz_free_text_sheet(ctx, sheet);
	fz_free_page(doc, page);

	return hit_count;
}

fz_rect search_result_bbox(fz_document *doc, int i)
{
	return hit_bbox[i];
}

