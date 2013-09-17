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

@interface MuDocumentController : UIViewController <UIScrollViewDelegate, UISearchBarDelegate>
{
	fz_document *doc;
	NSString *key;
	MuOutlineController *outline;
	UIScrollView *canvas;
	UILabel *indicator;
	UISlider *slider;
	UISearchBar *searchBar;
	UIBarButtonItem *nextButton, *prevButton, *cancelButton, *searchButton, *outlineButton, *linkButton;
	UIBarButtonItem *sliderWrapper;
	int searchPage;
	int cancelSearch;
	int showLinks;
	int width; // current screen size
	int height;
	int current; // currently visible page
	int scroll_animating; // stop view updates during scrolling animations
}
- (id) initWithFilename: (NSString*)nsfilename document: (fz_document *)aDoc;
- (void) createPageView: (int)number;
- (void) gotoPage: (int)number animated: (BOOL)animated;
- (void) onShowOutline: (id)sender;
- (void) onShowSearch: (id)sender;
- (void) onCancelSearch: (id)sender;
- (void) resetSearch;
- (void) showSearchResults: (int)count forPage: (int)number;
- (void) onSlide: (id)sender;
- (void) onTap: (UITapGestureRecognizer*)sender;
- (void) showNavigationBar;
- (void) hideNavigationBar;
@end
