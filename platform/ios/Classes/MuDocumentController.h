//
//  MuDocumentController.h
//  MuPDF
//
//  Copyright (c) 2013 Artifex Software, Inc. All rights reserved.
//

#import <UIKit/UIKit.h>

#undef ABS
#undef MIN
#undef MAX

#include "mupdf/fitz.h"

#import "MuOutlineController.h"
#import "MuDocRef.h"
#import "MuDialogCreator.h"

enum
{
	BARMODE_MAIN,
	BARMODE_SEARCH,
	BARMODE_ANNOTATION,
	BARMODE_HIGHLIGHT,
	BARMODE_UNDERLINE,
	BARMODE_STRIKE
};

@interface MuDocumentController : UIViewController <UIScrollViewDelegate, UIGestureRecognizerDelegate, UISearchBarDelegate, MuDialogCreator>
{
	fz_document *doc;
	MuDocRef *docRef;
	NSString *key;
	BOOL reflowMode;
	MuOutlineController *outline;
	UIScrollView *canvas;
	UILabel *indicator;
	UISlider *slider;
	UISearchBar *searchBar;
	UIBarButtonItem *nextButton, *prevButton, *cancelButton, *searchButton, *outlineButton, *linkButton;
	UIBarButtonItem *moreButton;
	UIBarButtonItem *highlightButton, *underlineButton, *strikeoutButton;
	UIBarButtonItem *tickButton;
	UIBarButtonItem *reflowButton;
	UIBarButtonItem *sliderWrapper;
	int barmode;
	int searchPage;
	int cancelSearch;
	int showLinks;
	int width; // current screen size
	int height;
	int current; // currently visible page
	int scroll_animating; // stop view updates during scrolling animations
	float scale; // scale applied to views (only used in reflow mode)
}
- (id) initWithFilename: (NSString*)nsfilename document: (MuDocRef *)aDoc;
- (void) createPageView: (int)number;
- (void) gotoPage: (int)number animated: (BOOL)animated;
- (void) onShowOutline: (id)sender;
- (void) onShowSearch: (id)sender;
- (void) onCancel: (id)sender;
- (void) resetSearch;
- (void) showSearchResults: (int)count forPage: (int)number;
- (void) onSlide: (id)sender;
- (void) onTap: (UITapGestureRecognizer*)sender;
- (void) showNavigationBar;
- (void) hideNavigationBar;
@end
