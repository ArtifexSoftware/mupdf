#import <UIKit/UIKit.h>

@class MuDocumentController;

@interface MuOutlineController : UITableViewController
- (instancetype) initWithTarget: (id)aTarget titles: (NSMutableArray*)aTitles pages: (NSMutableArray*)aPages;
@end
