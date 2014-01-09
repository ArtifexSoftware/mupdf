#import <UIKit/UIKit.h>

@class MuDocumentController;

@interface MuOutlineController : UITableViewController
{
	MuDocumentController *target;
	NSMutableArray *titles;
	NSMutableArray *pages;
}
- (id) initWithTarget: (id)aTarget titles: (NSMutableArray*)aTitles pages: (NSMutableArray*)aPages;
@end
