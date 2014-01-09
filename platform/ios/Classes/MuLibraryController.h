#import <UIKit/UIKit.h>

#undef ABS
#undef MIN
#undef MAX

#include "mupdf/fitz.h"

#import "MuDocRef.h"

@interface MuLibraryController : UITableViewController <UIActionSheetDelegate>
{
	NSArray *files;
	NSTimer *timer;
	MuDocRef *doc;
	NSString *_filename;
	char *_filePath;
}
- (void) openDocument: (NSString*)filename;
- (void) askForPassword: (NSString*)prompt;
- (void) onPasswordOkay;
- (void) onPasswordCancel;
- (void) reload;
@end

