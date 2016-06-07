#import <UIKit/UIKit.h>
#import "MuTapResult.h"

#undef ABS
#undef MIN
#undef MAX

#include "mupdf/fitz.h"

@interface MuHitView : UIView
- (instancetype) initWithSearchResults: (int)n forDocument: (fz_document *)doc;
- (instancetype) initWithLinks: (fz_link*)links forDocument: (fz_document *)doc;
- (void) setPageSize: (CGSize)s;
- (MuTapResult *) handleTap:(CGPoint)pt;
@end
