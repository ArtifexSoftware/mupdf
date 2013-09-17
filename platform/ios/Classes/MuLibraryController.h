//
//  MuLibraryController.h
//  MuPDF
//
//  Copyright (c) 2013 Artifex Software, Inc. All rights reserved.
//

#import <UIKit/UIKit.h>

#undef ABS
#undef MIN
#undef MAX

#include "mupdf/fitz.h"

@interface MuLibraryController : UITableViewController <UIActionSheetDelegate>
{
	NSArray *files;
	NSTimer *timer;
	fz_document *_doc; // temporaries for juggling password dialog
	NSString *_filename;
}
- (void) openDocument: (NSString*)filename;
- (void) askForPassword: (NSString*)prompt;
- (void) onPasswordOkay;
- (void) onPasswordCancel;
- (void) reload;
@end

