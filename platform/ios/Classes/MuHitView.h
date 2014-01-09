#import <UIKit/UIKit.h>
#import "MuTapResult.h"

#undef ABS
#undef MIN
#undef MAX

#include "mupdf/fitz.h"

@interface MuHitView : UIView
{
	CGSize pageSize;
	int hitCount;
	CGRect hitRects[500];
	int linkPage[500];
	char *linkUrl[500];
	UIColor *color;
}
- (id) initWithSearchResults: (int)n forDocument: (fz_document *)doc;
- (id) initWithLinks: (fz_link*)links forDocument: (fz_document *)doc;
- (void) setPageSize: (CGSize)s;
- (MuTapResult *) handleTap:(CGPoint)pt;
@end
