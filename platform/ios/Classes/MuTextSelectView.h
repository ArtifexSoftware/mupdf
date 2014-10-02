#include "common.h"

@interface MuTextSelectView : UIView
- (id) initWithWords:(NSArray *)_words pageSize:(CGSize)_pageSize;
- (NSArray *) selectionRects;
- (NSString *) selectedText;
@end
