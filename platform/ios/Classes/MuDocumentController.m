#include "common.h"

#import "MuPageViewNormal.h"
#import "MuPageViewReflow.h"
#import "MuDocumentController.h"
#import "MuTextFieldController.h"
#import "MuChoiceFieldController.h"
#import "MuPrintPageRenderer.h"

#define GAP 20
#define INDICATOR_Y -44-24
#define SLIDER_W (width - GAP - 24)
#define SEARCH_W (width - GAP - 170)
#define MIN_SCALE (1.0)
#define MAX_SCALE (5.0)

static NSString *const AlertTitle = @"Save Document?";
// Correct functioning of the app relies on CloseAlertMessage and ShareAlertMessage differing
static NSString *const CloseAlertMessage = @"Changes have been made to the document that will be lost if not saved";
static NSString *const ShareAlertMessage = @"Your changes will not be shared unless the document is first saved";

static void flattenOutline(NSMutableArray *titles, NSMutableArray *pages, fz_outline *outline, int level)
{
	char indent[8*4+1];
	if (level > 8)
		level = 8;
	memset(indent, ' ', level * 4);
	indent[level * 4] = 0;
	while (outline)
	{
		if (outline->dest.kind == FZ_LINK_GOTO)
		{
			int page = outline->dest.ld.gotor.page;
			if (page >= 0 && outline->title)
			{
				NSString *title = [NSString stringWithUTF8String: outline->title];
				[titles addObject: [NSString stringWithFormat: @"%s%@", indent, title]];
				[pages addObject: [NSNumber numberWithInt: page]];
			}
		}
		flattenOutline(titles, pages, outline->down, level + 1);
		outline = outline->next;
	}
}

static char *tmp_path(char *path)
{
	int f;
	char *buf = malloc(strlen(path) + 6 + 1);
	if (!buf)
		return NULL;

	strcpy(buf, path);
	strcat(buf, "XXXXXX");

	f = mkstemp(buf);

	if (f >= 0)
	{
		close(f);
		return buf;
	}
	else
	{
		free(buf);
		return NULL;
	}
}

static void saveDoc(char *current_path, fz_document *doc)
{
	char *tmp;
	fz_write_options opts;
	opts.do_incremental = 1;
	opts.do_ascii = 0;
	opts.do_expand = 0;
	opts.do_garbage = 0;
	opts.do_linear = 0;

	tmp = tmp_path(current_path);
	if (tmp)
	{
		int written = 0;

		fz_var(written);
		fz_try(ctx)
		{
			FILE *fin = fopen(current_path, "rb");
			FILE *fout = fopen(tmp, "wb");
			char buf[256];
			size_t n;
			int err = 1;

			if (fin && fout)
			{
				while ((n = fread(buf, 1, sizeof(buf), fin)) > 0)
					fwrite(buf, 1, n, fout);
				err = (ferror(fin) || ferror(fout));
			}

			if (fin)
				fclose(fin);
			if (fout)
				fclose(fout);

			if (!err)
			{
				fz_write_document(ctx, doc, tmp, &opts);
				written = 1;
			}
		}
		fz_catch(ctx)
		{
			written = 0;
		}

		if (written)
		{
			rename(tmp, current_path);
		}

		free(tmp);
	}
}

@implementation MuDocumentController
{
	fz_document *doc;
	MuDocRef *docRef;
	NSString *key;
	char *filePath;
	BOOL reflowMode;
	MuOutlineController *outline;
	UIScrollView *canvas;
	UILabel *indicator;
	UISlider *slider;
	UISearchBar *searchBar;
	UIBarButtonItem *nextButton, *prevButton, *cancelButton, *searchButton, *outlineButton, *linkButton;
	UIBarButtonItem *moreButton;
	UIBarButtonItem *shareButton, *printButton, *annotButton;
	UIBarButtonItem *highlightButton, *underlineButton, *strikeoutButton;
	UIBarButtonItem *inkButton;
	UIBarButtonItem *tickButton;
	UIBarButtonItem *deleteButton;
	UIBarButtonItem *reflowButton;
	UIBarButtonItem *backButton;
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
	BOOL _isRotating;
}

- (id) initWithFilename: (NSString*)filename path:(char *)cstr document: (MuDocRef *)aDoc
{
	self = [super init];
	if (!self)
		return nil;

#if __IPHONE_OS_VERSION_MAX_ALLOWED >= 70000
	if ([self respondsToSelector:@selector(automaticallyAdjustsScrollViewInsets)])
		self.automaticallyAdjustsScrollViewInsets = NO;
#endif
	key = [filename retain];
	docRef = [aDoc retain];
	doc = docRef->doc;
	filePath = strdup(cstr);

	dispatch_sync(queue, ^{});

	fz_outline *root = fz_load_outline(ctx, doc);
	if (root) {
		NSMutableArray *titles = [[NSMutableArray alloc] init];
		NSMutableArray *pages = [[NSMutableArray alloc] init];
		flattenOutline(titles, pages, root, 0);
		if ([titles count])
			outline = [[MuOutlineController alloc] initWithTarget: self titles: titles pages: pages];
		[titles release];
		[pages release];
		fz_drop_outline(ctx, root);
	}

	return self;
}

- (UIBarButtonItem *) newResourceBasedButton:(NSString *)resource withAction:(SEL)selector
{
	if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad)
	{
		return [[UIBarButtonItem alloc] initWithImage:[UIImage imageWithContentsOfFile:[[NSBundle mainBundle] pathForResource:resource ofType:@"png"]] style:UIBarButtonItemStylePlain target:self action:selector];
	}
	else
	{
		UIView *buttonView;
		BOOL iOS7Style = ([[UIDevice currentDevice].systemVersion floatValue] >= 7.0f);
		UIButton *button = [UIButton buttonWithType:iOS7Style ? UIButtonTypeSystem : UIButtonTypeCustom];
		[button setImage:[UIImage imageNamed:resource] forState:UIControlStateNormal];
		[button addTarget:self action:selector forControlEvents:UIControlEventTouchUpInside];
		[button sizeToFit];
		buttonView = button;

		return [[UIBarButtonItem alloc] initWithCustomView:buttonView];
	}
}

- (void) addMainMenuButtons
{
	NSMutableArray *array = [NSMutableArray arrayWithCapacity:3];
	[array addObject:moreButton];
	[array addObject:searchButton];
	if (outlineButton)
		[array addObject:outlineButton];
	[array addObject:reflowButton];
	[array addObject:linkButton];
	[[self navigationItem] setRightBarButtonItems: array ];
	[[self navigationItem] setLeftBarButtonItem:backButton];
}

- (void) loadView
{
	[[NSUserDefaults standardUserDefaults] setObject: key forKey: @"OpenDocumentKey"];

	current = (int)[[NSUserDefaults standardUserDefaults] integerForKey: key];
	if (current < 0 || current >= fz_count_pages(ctx, doc))
		current = 0;

	UIView *view = [[UIView alloc] initWithFrame: CGRectZero];
	[view setAutoresizingMask: UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight];
	[view setAutoresizesSubviews: YES];
	view.backgroundColor = [UIColor grayColor];

	canvas = [[UIScrollView alloc] initWithFrame: CGRectMake(0,0,GAP,0)];
	[canvas setAutoresizingMask: UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight];
	[canvas setPagingEnabled: YES];
	[canvas setShowsHorizontalScrollIndicator: NO];
	[canvas setShowsVerticalScrollIndicator: NO];
	[canvas setDelegate: self];

	UITapGestureRecognizer *tapRecog = [[UITapGestureRecognizer alloc] initWithTarget: self action: @selector(onTap:)];
	tapRecog.delegate = self;
	[canvas addGestureRecognizer: tapRecog];
	[tapRecog release];
	// In reflow mode, we need to track pinch gestures on the canvas and pass
	// the scale changes to the subviews.
	UIPinchGestureRecognizer *pinchRecog = [[UIPinchGestureRecognizer alloc] initWithTarget:self action:@selector(onPinch:)];
	pinchRecog.delegate = self;
	[canvas addGestureRecognizer:pinchRecog];
	[pinchRecog release];

	scale = 1.0;

	scroll_animating = NO;

	indicator = [[UILabel alloc] initWithFrame: CGRectZero];
	[indicator setAutoresizingMask: UIViewAutoresizingFlexibleLeftMargin | UIViewAutoresizingFlexibleRightMargin | UIViewAutoresizingFlexibleTopMargin];
	[indicator setText: @"0000 of 9999"];
	[indicator sizeToFit];
	[indicator setCenter: CGPointMake(0, INDICATOR_Y)];
	[indicator setTextAlignment: NSTextAlignmentCenter];
	[indicator setBackgroundColor: [[UIColor blackColor] colorWithAlphaComponent: 0.5]];
	[indicator setTextColor: [UIColor whiteColor]];

	[view addSubview: canvas];
	[view addSubview: indicator];

	slider = [[UISlider alloc] initWithFrame: CGRectZero];
	[slider setMinimumValue: 0];
	[slider setMaximumValue: fz_count_pages(ctx, doc) - 1];
	[slider addTarget: self action: @selector(onSlide:) forControlEvents: UIControlEventValueChanged];

	if ([[[UIDevice currentDevice] systemVersion] floatValue] < 7.0)
	{
		sliderWrapper = [[UIBarButtonItem alloc] initWithCustomView: slider];

		[self setToolbarItems: [NSArray arrayWithObjects: sliderWrapper, nil]];
	}

	// Set up the buttons on the navigation and search bar

	if (outline) {
		outlineButton = [self newResourceBasedButton:@"ic_list" withAction:@selector(onShowOutline:)];
	}
	linkButton = [self newResourceBasedButton:@"ic_link" withAction:@selector(onToggleLinks:)];
	cancelButton = [self newResourceBasedButton:@"ic_cancel" withAction:@selector(onCancel:)];
	searchButton = [self newResourceBasedButton:@"ic_magnifying_glass" withAction:@selector(onShowSearch:)];
	prevButton = [self newResourceBasedButton:@"ic_arrow_left" withAction:@selector(onSearchPrev:)];
	nextButton = [self newResourceBasedButton:@"ic_arrow_right" withAction:@selector(onSearchNext:)];
	reflowButton = [self newResourceBasedButton:@"ic_reflow" withAction:@selector(onToggleReflow:)];
	moreButton = [self newResourceBasedButton:@"ic_more" withAction:@selector(onMore:)];
	annotButton = [self newResourceBasedButton:@"ic_annotation" withAction:@selector(onAnnot:)];
	shareButton = [self newResourceBasedButton:@"ic_share" withAction:@selector(onShare:)];
	printButton = [self newResourceBasedButton:@"ic_print" withAction:@selector(onPrint:)];
	highlightButton = [self newResourceBasedButton:@"ic_highlight" withAction:@selector(onHighlight:)];
	underlineButton = [self newResourceBasedButton:@"ic_underline" withAction:@selector(onUnderline:)];
	strikeoutButton = [self newResourceBasedButton:@"ic_strike" withAction:@selector(onStrikeout:)];
	inkButton = [self newResourceBasedButton:@"ic_pen" withAction:@selector(onInk:)];
	tickButton = [self newResourceBasedButton:@"ic_check" withAction:@selector(onTick:)];
	deleteButton = [self newResourceBasedButton:@"ic_trash" withAction:@selector(onDelete:)];
	searchBar = [[UISearchBar alloc] initWithFrame: CGRectMake(0,0,50,32)];
	backButton = [self newResourceBasedButton:@"ic_arrow_left" withAction:@selector(onBack:)];
	[searchBar setPlaceholder: @"Search"];
	[searchBar setDelegate: self];

	[prevButton setEnabled: NO];
	[nextButton setEnabled: NO];

	[self addMainMenuButtons];

	// TODO: add activityindicator to search bar

	[self setView: view];
	[view release];
}

- (void) dealloc
{
	[docRef release]; docRef = nil; doc = NULL;
	[indicator release]; indicator = nil;
	[slider release]; slider = nil;
	[sliderWrapper release]; sliderWrapper = nil;
	[reflowButton release]; reflowButton = nil;
	[backButton release]; backButton = nil;
	[moreButton release]; moreButton = nil;
	[searchBar release]; searchBar = nil;
	[outlineButton release]; outlineButton = nil;
	[linkButton release]; linkButton = nil;
	[searchButton release]; searchButton = nil;
	[cancelButton release]; cancelButton = nil;
	[prevButton release]; prevButton = nil;
	[nextButton release]; nextButton = nil;
	[shareButton release]; shareButton = nil;
	[printButton release]; printButton = nil;
	[annotButton release]; annotButton = nil;
	[highlightButton release]; highlightButton = nil;
	[underlineButton release]; underlineButton = nil;
	[strikeoutButton release]; strikeoutButton = nil;
	[inkButton release]; inkButton = nil;
	[tickButton release]; tickButton = nil;
	[deleteButton release]; deleteButton = nil;
	[canvas release]; canvas = nil;
	free(filePath); filePath = NULL;

	[outline release];
	[key release];
	[super dealloc];
}

- (void) viewWillAppear: (BOOL)animated
{
	[super viewWillAppear:animated];
	[self setTitle: [key lastPathComponent]];

	[slider setValue: current];

	if ([[[UIDevice currentDevice] systemVersion] floatValue] >= 7.0)
		[[[self navigationController] toolbar] addSubview:slider];

	[indicator setText: [NSString stringWithFormat: @" %d of %d ", current+1, fz_count_pages(ctx, doc)]];

	[[self navigationController] setToolbarHidden: NO animated: animated];
}

- (void) viewWillLayoutSubviews
{
	CGSize size = [canvas frame].size;
	int max_width = fz_max(width, size.width);

	width = size.width;
	height = size.height;

	[canvas setContentInset: UIEdgeInsetsZero];
	[canvas setContentSize: CGSizeMake(fz_count_pages(ctx, doc) * width, height)];
	[canvas setContentOffset: CGPointMake(current * width, 0)];

	[sliderWrapper setWidth: SLIDER_W];
	[searchBar setFrame: CGRectMake(0,0,SEARCH_W,32)];
	if ([[[UIDevice currentDevice] systemVersion] floatValue] >= 7.0)
	{
		CGRect r = [[self navigationController] toolbar].frame;
		r.origin.x = 0;
		r.origin.y = 0;
		[slider setFrame:r];
	}

	[[[self navigationController] toolbar] setNeedsLayout]; // force layout!

	// use max_width so we don't clamp the content offset too early during animation
	[canvas setContentSize: CGSizeMake(fz_count_pages(ctx, doc) * max_width, height)];
	[canvas setContentOffset: CGPointMake(current * width, 0)];

	for (UIView<MuPageView> *view in [canvas subviews]) {
		if ([view number] == current) {
			[view setFrame: CGRectMake([view number] * width, 0, width-GAP, height)];
			[view willRotate];
		}
	}
	for (UIView<MuPageView> *view in [canvas subviews]) {
		if ([view number] != current) {
			[view setFrame: CGRectMake([view number] * width, 0, width-GAP, height)];
			[view willRotate];
		}
	}
}

- (void) viewDidAppear: (BOOL)animated
{
	[super viewDidAppear:animated];
	[self scrollViewDidScroll: canvas];
}

- (void) viewWillDisappear: (BOOL)animated
{
	[super viewWillDisappear:animated];
	if ([[[UIDevice currentDevice] systemVersion] floatValue] >= 7.0)
		[slider removeFromSuperview];

	[self setTitle: @"Resume"];
	[[NSUserDefaults standardUserDefaults] removeObjectForKey: @"OpenDocumentKey"];
	[[self navigationController] setToolbarHidden: YES animated: animated];
}

- (void) showNavigationBar
{
	if ([[self navigationController] isNavigationBarHidden]) {
		[sliderWrapper setWidth: SLIDER_W];
		if ([[[UIDevice currentDevice] systemVersion] floatValue] >= 7.0)
		{
			CGRect r = [[self navigationController] toolbar].frame;
			r.origin.x = 0;
			r.origin.y = 0;
			[slider setFrame:r];
		}
		[[self navigationController] setNavigationBarHidden: NO];
		[[self navigationController] setToolbarHidden: NO];
		[indicator setHidden: NO];

		[UIView beginAnimations: @"MuNavBar" context: NULL];

		[[[self navigationController] navigationBar] setAlpha: 1];
		[[[self navigationController] toolbar] setAlpha: 1];
		[indicator setAlpha: 1];

		[UIView commitAnimations];
	}
}

- (void) hideNavigationBar
{
	if (![[self navigationController] isNavigationBarHidden]) {
		[searchBar resignFirstResponder];

		[UIView beginAnimations: @"MuNavBar" context: NULL];
		[UIView setAnimationDelegate: self];
		[UIView setAnimationDidStopSelector: @selector(onHideNavigationBarFinished)];

		[[[self navigationController] navigationBar] setAlpha: 0];
		[[[self navigationController] toolbar] setAlpha: 0];
		[indicator setAlpha: 0];

		[UIView commitAnimations];
	}
}

- (void) onHideNavigationBarFinished
{
	[[self navigationController] setNavigationBarHidden: YES];
	[[self navigationController] setToolbarHidden: YES];
	[indicator setHidden: YES];
}

- (void) onShowOutline: (id)sender
{
	[[self navigationController] pushViewController: outline animated: YES];
}

- (void) onToggleLinks: (id)sender
{
	showLinks = !showLinks;
	for (UIView<MuPageView> *view in [canvas subviews])
	{
		if (showLinks)
			[view showLinks];
		else
			[view hideLinks];
	}
}

- (void) onToggleReflow: (id)sender
{
	reflowMode = !reflowMode;

	[annotButton setEnabled:!reflowMode];
	[searchButton setEnabled:!reflowMode];
	[linkButton setEnabled:!reflowMode];
	[moreButton setEnabled:!reflowMode];

	[[canvas subviews] makeObjectsPerformSelector:@selector(removeFromSuperview)];
	[self scrollViewDidScroll:canvas];
}

- (void) showMoreMenu
{
	NSMutableArray *rightbuttons = [NSMutableArray arrayWithObjects:printButton, shareButton, nil];
	if (docRef->interactive)
		[rightbuttons insertObject:annotButton atIndex:0];
	[[self navigationItem] setRightBarButtonItems:rightbuttons];
	[[self navigationItem] setLeftBarButtonItem:cancelButton];

	barmode = BARMODE_MORE;
}

- (void) showAnnotationMenu
{
	[[self navigationItem] setRightBarButtonItems:[NSArray arrayWithObjects:inkButton, strikeoutButton, underlineButton, highlightButton, nil]];
	[[self navigationItem] setLeftBarButtonItem:cancelButton];

	for (UIView<MuPageView> *view in [canvas subviews])
	{
		if ([view number] == current)
			[view deselectAnnotation];
	}

	barmode = BARMODE_ANNOTATION;
}

- (void) update
{
	for (UIView<MuPageView> *view in [canvas subviews])
		[view update];
}

- (void) onMore: (id)sender
{
	[self showMoreMenu];
}

- (void) onAnnot: (id)sender
{
	[self showAnnotationMenu];
}

- (void) onPrint: (id)sender
{
	UIPrintInteractionController *pic = [UIPrintInteractionController sharedPrintController];
	if (pic) {
		UIPrintInfo *printInfo = [UIPrintInfo printInfo];
		printInfo.outputType = UIPrintInfoOutputGeneral;
		printInfo.jobName = key;
		printInfo.duplex = UIPrintInfoDuplexLongEdge;
		pic.printInfo = printInfo;
		pic.showsPageRange = YES;
		pic.printPageRenderer = [[[MuPrintPageRenderer alloc] initWithDocRef:docRef] autorelease];

		void (^completionHandler)(UIPrintInteractionController *, BOOL, NSError *) =
			^(UIPrintInteractionController *pic, BOOL completed, NSError *error) {
				if (!completed && error)
					NSLog(@"FAILED! due to error in domain %@ with error code %u",
							error.domain, (unsigned int)error.code);
			};
		if (UI_USER_INTERFACE_IDIOM() == UIUserInterfaceIdiomPad) {
			[pic presentFromBarButtonItem:printButton animated:YES
				completionHandler:completionHandler];
		} else {
			[pic presentAnimated:YES completionHandler:completionHandler];
		}
	}
}

- (void) shareDocument
{
	NSURL *url = [NSURL fileURLWithPath:[NSString stringWithUTF8String:filePath]];
	UIActivityViewController *cont = [[UIActivityViewController alloc] initWithActivityItems:[NSArray arrayWithObject:url] applicationActivities:nil];
	cont.popoverPresentationController.barButtonItem = shareButton;
	[self presentViewController:cont animated:YES completion:nil];
	[cont release];
}

- (void) onShare: (id)sender
{
	pdf_document *idoc = pdf_specifics(ctx, doc);
	if (idoc && pdf_has_unsaved_changes(ctx, idoc))
	{
		UIAlertView *alertView = [[UIAlertView alloc] initWithTitle:AlertTitle message:ShareAlertMessage delegate:self cancelButtonTitle:@"Cancel" otherButtonTitles:@"Save and Share", nil];
		[alertView show];
		[alertView release];
	}
	else
	{
		[self shareDocument];
	}
}

- (void) textSelectModeOn
{
	[[self navigationItem] setRightBarButtonItems:[NSArray arrayWithObject:tickButton]];
	for (UIView<MuPageView> *view in [canvas subviews])
	{
		if ([view number] == current)
			[view textSelectModeOn];
	}
}

- (void) textSelectModeOff
{
	for (UIView<MuPageView> *view in [canvas subviews])
	{
		[view textSelectModeOff];
	}
}

- (void) inkModeOn
{
	[[self navigationItem] setRightBarButtonItems:[NSArray arrayWithObject:tickButton]];
	for (UIView<MuPageView> *view in [canvas subviews])
	{
		if ([view number] == current)
			[view inkModeOn];
	}
}

- (void) deleteModeOn
{
	[[self navigationItem] setRightBarButtonItems:[NSArray arrayWithObject:deleteButton]];
	barmode = BARMODE_DELETE;
}

- (void) inkModeOff
{
	for (UIView<MuPageView> *view in [canvas subviews])
	{
		[view inkModeOff];
	}
}

- (void) onHighlight: (id)sender
{
	barmode = BARMODE_HIGHLIGHT;
	[self textSelectModeOn];
}

- (void) onUnderline: (id)sender
{
	barmode = BARMODE_UNDERLINE;
	[self textSelectModeOn];
}

- (void) onStrikeout: (id)sender
{
	barmode = BARMODE_STRIKE;
	[self textSelectModeOn];
}

- (void) onInk: (id)sender
{
	barmode = BARMODE_INK;
	[self inkModeOn];
}

- (void) onShowSearch: (id)sender
{
	[[self navigationItem] setRightBarButtonItems:
		[NSArray arrayWithObjects: nextButton, prevButton, nil]];
	[[self navigationItem] setLeftBarButtonItem: cancelButton];
	[[self navigationItem] setTitleView: searchBar];
	[searchBar becomeFirstResponder];
	barmode = BARMODE_SEARCH;
}

- (void) onTick: (id)sender
{

	for (UIView<MuPageView> *view in [canvas subviews])
	{
		if ([view number] == current)
		{
			switch (barmode)
			{
				case BARMODE_HIGHLIGHT:
					[view saveSelectionAsMarkup:FZ_ANNOT_HIGHLIGHT];
					break;

				case BARMODE_UNDERLINE:
					[view saveSelectionAsMarkup:FZ_ANNOT_UNDERLINE];
					break;

				case BARMODE_STRIKE:
					[view saveSelectionAsMarkup:FZ_ANNOT_STRIKEOUT];
					break;

				case BARMODE_INK:
					[view saveInk];
			}
		}
	}

	[self showAnnotationMenu];
}

- (void) onDelete: (id)sender
{
	for (UIView<MuPageView> *view in [canvas subviews])
	{
		if ([view number] == current)
			[view deleteSelectedAnnotation];
	}
	[self showAnnotationMenu];
}

- (void) onCancel: (id)sender
{
	switch (barmode)
	{
		case BARMODE_SEARCH:
			cancelSearch = YES;
			[searchBar resignFirstResponder];
			[self resetSearch];
			/* fallthrough */
		case BARMODE_ANNOTATION:
		case BARMODE_MORE:
			[[self navigationItem] setTitleView: nil];
			[self addMainMenuButtons];
			barmode = BARMODE_MAIN;
			break;

		case BARMODE_HIGHLIGHT:
		case BARMODE_UNDERLINE:
		case BARMODE_STRIKE:
		case BARMODE_DELETE:
			[self showAnnotationMenu];
			[self textSelectModeOff];
			break;

		case BARMODE_INK:
			[self showAnnotationMenu];
			[self inkModeOff];
			break;
	}
}

- (void) onBack: (id)sender
{
	pdf_document *idoc = pdf_specifics(ctx, doc);
	if (idoc && pdf_has_unsaved_changes(ctx, idoc))
	{
		UIAlertView *saveAlert = [[UIAlertView alloc]
			initWithTitle:AlertTitle message:CloseAlertMessage delegate:self
			cancelButtonTitle:@"Discard" otherButtonTitles:@"Save", nil];
		[saveAlert show];
		[saveAlert release];
	}
	else
	{
		[[self navigationController] popViewControllerAnimated:YES];
	}
}

- (void) alertView:(UIAlertView *)alertView clickedButtonAtIndex:(NSInteger)buttonIndex
{
	if ([CloseAlertMessage isEqualToString:alertView.message])
	{
		if (buttonIndex == 1)
			saveDoc(filePath, doc);

		[alertView dismissWithClickedButtonIndex:buttonIndex animated:YES];
		[[self navigationController] popViewControllerAnimated:YES];
	}

	if ([ShareAlertMessage isEqualToString:alertView.message])
	{
		[alertView dismissWithClickedButtonIndex:buttonIndex animated:NO];
		if (buttonIndex == 1)
		{
			saveDoc(filePath, doc);
			[self shareDocument];
		}
	}
}

- (void) resetSearch
{
	searchPage = -1;
	for (UIView<MuPageView> *view in [canvas subviews])
		[view clearSearchResults];
}

- (void) showSearchResults: (int)count forPage: (int)number
{
	printf("search found match on page %d\n", number);
	searchPage = number;
	[self gotoPage: number animated: NO];
	for (UIView<MuPageView> *view in [canvas subviews])
		if ([view number] == number)
			[view showSearchResults: count];
		else
			[view clearSearchResults];
}

- (void) searchInDirection: (int)dir
{
	UITextField *searchField;
	char *needle;
	int start;

	[searchBar resignFirstResponder];

	if (searchPage == current)
		start = current + dir;
	else
		start = current;

	needle = strdup([[searchBar text] UTF8String]);

	searchField = nil;
	for (id view in [searchBar subviews])
		if ([view isKindOfClass: [UITextField class]])
			searchField = view;

	[prevButton setEnabled: NO];
	[nextButton setEnabled: NO];
	[searchField setEnabled: NO];

	cancelSearch = NO;

	dispatch_async(queue, ^{
		for (int i = start; i >= 0 && i < fz_count_pages(ctx, doc); i += dir) {
			int n = search_page(doc, i, needle, NULL);
			if (n) {
				dispatch_async(dispatch_get_main_queue(), ^{
					[prevButton setEnabled: YES];
					[nextButton setEnabled: YES];
					[searchField setEnabled: YES];
					[self showSearchResults: n forPage: i];
					free(needle);
				});
				return;
			}
			if (cancelSearch) {
				dispatch_async(dispatch_get_main_queue(), ^{
					[prevButton setEnabled: YES];
					[nextButton setEnabled: YES];
					[searchField setEnabled: YES];
					free(needle);
				});
				return;
			}
		}
		dispatch_async(dispatch_get_main_queue(), ^{
			printf("no search results found\n");
			[prevButton setEnabled: YES];
			[nextButton setEnabled: YES];
			[searchField setEnabled: YES];
			UIAlertView *alert = [[UIAlertView alloc]
				initWithTitle: @"No matches found for:"
				message: [NSString stringWithUTF8String: needle]
				delegate: nil
				cancelButtonTitle: @"Close"
				otherButtonTitles: nil];
			[alert show];
			[alert release];
			free(needle);
		});
	});
}

- (void) onSearchPrev: (id)sender
{
	[self searchInDirection: -1];
}

- (void) onSearchNext: (id)sender
{
	[self searchInDirection: 1];
}

- (void) searchBarSearchButtonClicked: (UISearchBar*)sender
{
	[self onSearchNext: sender];
}

- (void) searchBar: (UISearchBar*)sender textDidChange: (NSString*)searchText
{
	[self resetSearch];
	if ([[searchBar text] length] > 0) {
		[prevButton setEnabled: YES];
		[nextButton setEnabled: YES];
	} else {
		[prevButton setEnabled: NO];
		[nextButton setEnabled: NO];
	}
}

- (void) onSlide: (id)sender
{
	int number = [slider value];
	if ([slider isTracking])
		[indicator setText: [NSString stringWithFormat: @" %d of %d ", number+1, fz_count_pages(ctx, doc)]];
	else
		[self gotoPage: number animated: NO];
}

- (BOOL) gestureRecognizer:(UIGestureRecognizer *)gestureRecognizer shouldRecognizeSimultaneouslyWithGestureRecognizer:(UIGestureRecognizer *)otherGestureRecognizer
{
	// For reflow mode, we load UIWebViews into the canvas. Returning YES
	// here prevents them stealing our tap and pinch events.
	return YES;
}

- (void) onTap: (UITapGestureRecognizer*)sender
{
	CGPoint p = [sender locationInView: canvas];
	CGPoint ofs = [canvas contentOffset];
	float x0 = (width - GAP) / 5;
	float x1 = (width - GAP) - x0;
	p.x -= ofs.x;
	p.y -= ofs.y;
	__block BOOL tapHandled = NO;
	for (UIView<MuPageView> *view in [canvas subviews])
	{
		CGPoint pp = [sender locationInView:view];
		if (CGRectContainsPoint(view.bounds, pp))
		{
			MuTapResult *result = [view handleTap:pp];
			__block BOOL hitAnnot = NO;
			[result switchCaseInternal:^(MuTapResultInternalLink *link) {
				[self gotoPage:link.pageNumber animated:NO];
				tapHandled = YES;
			} caseExternal:^(MuTapResultExternalLink *link) {
				// Not currently supported
			} caseRemote:^(MuTapResultRemoteLink *link) {
				// Not currently supported
			} caseWidget:^(MuTapResultWidget *widget) {
				tapHandled = YES;
			} caseAnnotation:^(MuTapResultAnnotation *annot) {
				hitAnnot = YES;
			}];

			switch (barmode)
			{
				case BARMODE_ANNOTATION:
					if (hitAnnot)
						[self deleteModeOn];
					tapHandled = YES;
					break;

				case BARMODE_DELETE:
					if (!hitAnnot)
						[self showAnnotationMenu];
					tapHandled = YES;
					break;

				default:
					if (hitAnnot)
					{
						// Annotation will have been selected, which is wanted
						// only in annotation-editing mode
						[view deselectAnnotation];
					}
					break;
			}

			if (tapHandled)
				break;
		}
	}
	if (tapHandled) {
		// Do nothing further
	} else if (p.x < x0) {
		[self gotoPage: current-1 animated: YES];
	} else if (p.x > x1) {
		[self gotoPage: current+1 animated: YES];
	} else {
		if ([[self navigationController] isNavigationBarHidden])
			[self showNavigationBar];
		else if (barmode == BARMODE_MAIN)
			[self hideNavigationBar];
	}
}

- (void) onPinch:(UIPinchGestureRecognizer*)sender
{
	if (sender.state == UIGestureRecognizerStateBegan)
		sender.scale = scale;

	if (sender.scale < MIN_SCALE)
		sender.scale = MIN_SCALE;

	if (sender.scale > MAX_SCALE)
		sender.scale = MAX_SCALE;

	if (sender.state == UIGestureRecognizerStateEnded)
		scale = sender.scale;

	for (UIView<MuPageView> *view in [canvas subviews])
	{
		// Zoom only the visible page until end of gesture
		if (view.number == current || sender.state == UIGestureRecognizerStateEnded)
			[view setScale:sender.scale];
	}
}

- (void) scrollViewWillBeginDragging: (UIScrollView *)scrollView
{
	if (barmode == BARMODE_MAIN)
		[self hideNavigationBar];
}

- (void) scrollViewDidScroll: (UIScrollView*)scrollview
{
	// scrollViewDidScroll seems to get called part way through a screen rotation.
	// (This is possibly a UIScrollView bug - see
	// http://stackoverflow.com/questions/4123991/uiscrollview-disable-scrolling-while-rotating-on-iphone-ipad/8141423#8141423 ).
	// This ends up corrupting the current page number, because the calculation
	// 'current = x / width' is using the new value of 'width' before the
	// pages have been resized/repositioned. To avoid this problem, we filter out
	// calls to scrollViewDidScroll during rotation.
	if (_isRotating)
		return;

	if (width == 0)
		return; // not visible yet

	if (scroll_animating)
		return; // don't mess with layout during animations

	float x = [canvas contentOffset].x + width * 0.5f;
	current = x / width;

	[[NSUserDefaults standardUserDefaults] setInteger: current forKey: key];

	[indicator setText: [NSString stringWithFormat: @" %d of %d ", current+1, fz_count_pages(ctx, doc)]];
	[slider setValue: current];

	// swap the distant page views out

	NSMutableSet *invisiblePages = [[NSMutableSet alloc] init];
	for (UIView<MuPageView> *view in [canvas subviews]) {
		if ([view number] != current)
			[view resetZoomAnimated: YES];
		if ([view number] < current - 2 || [view number] > current + 2)
			[invisiblePages addObject: view];
	}
	for (UIView<MuPageView> *view in invisiblePages)
		[view removeFromSuperview];
	[invisiblePages release]; // don't bother recycling them...

	[self createPageView: current];
	[self createPageView: current - 1];
	[self createPageView: current + 1];

	// reset search results when page has flipped
	if (current != searchPage)
		[self resetSearch];
}

- (void) createPageView: (int)number
{
	if (number < 0 || number >= fz_count_pages(ctx, doc))
		return;
	int found = 0;
	for (UIView<MuPageView> *view in [canvas subviews])
		if ([view number] == number)
			found = 1;
	if (!found) {
		UIView<MuPageView> *view
			= reflowMode
				? [[MuPageViewReflow alloc] initWithFrame:CGRectMake(number * width, 0, width-GAP, height) document:docRef page:number]
		: [[MuPageViewNormal alloc] initWithFrame:CGRectMake(number * width, 0, width-GAP, height) dialogCreator:self updater:self document:docRef page:number];
		[view setScale:scale];
		[canvas addSubview: view];
		if (showLinks)
			[view showLinks];
		[view release];
	}
}

- (void) gotoPage: (int)number animated: (BOOL)animated
{
	if (number < 0)
		number = 0;
	if (number >= fz_count_pages(ctx, doc))
		number = fz_count_pages(ctx, doc) - 1;
	if (current == number)
		return;
	if (animated) {
		// setContentOffset:animated: does not use the normal animation
		// framework. It also doesn't play nice with the tap gesture
		// recognizer. So we do our own page flipping animation here.
		// We must set the scroll_animating flag so that we don't create
		// or remove subviews until after the animation, or they'll
		// swoop in from origo during the animation.

		scroll_animating = YES;
		[UIView beginAnimations: @"MuScroll" context: NULL];
		[UIView setAnimationDuration: 0.4];
		[UIView setAnimationBeginsFromCurrentState: YES];
		[UIView setAnimationDelegate: self];
		[UIView setAnimationDidStopSelector: @selector(onGotoPageFinished)];

		for (UIView<MuPageView> *view in [canvas subviews])
			[view resetZoomAnimated: NO];

		[canvas setContentOffset: CGPointMake(number * width, 0)];
		[slider setValue: number];
		[indicator setText: [NSString stringWithFormat: @" %d of %d ", number+1, fz_count_pages(ctx, doc)]];

		[UIView commitAnimations];
	} else {
		for (UIView<MuPageView> *view in [canvas subviews])
			[view resetZoomAnimated: NO];
		[canvas setContentOffset: CGPointMake(number * width, 0)];
	}
	current = number;
}

- (void) invokeTextDialog:(NSString *)aString okayAction:(void (^)(NSString *))block
{
	MuTextFieldController *tf = [[MuTextFieldController alloc] initWithText:aString okayAction:block];
	tf.modalPresentationStyle = UIModalPresentationFormSheet;
	[self presentViewController:tf animated:YES completion:nil];
	[tf release];
}

- (void) invokeChoiceDialog:(NSArray *)anArray okayAction:(void (^)(NSArray *))block
{
	MuChoiceFieldController *cf = [[MuChoiceFieldController alloc] initWithChoices:anArray okayAction:block];
	cf.modalPresentationStyle = UIModalPresentationFormSheet;
	[self presentViewController:cf animated:YES completion:nil];
	[cf release];
}

- (void) onGotoPageFinished
{
	scroll_animating = NO;
	[self scrollViewDidScroll: canvas];
}

- (BOOL) shouldAutorotateToInterfaceOrientation: (UIInterfaceOrientation)o
{
	return YES;
}

- (void) willRotateToInterfaceOrientation:(UIInterfaceOrientation)toInterfaceOrientation duration:(NSTimeInterval)duration
{
	_isRotating = YES;
}

- (void) didRotateFromInterfaceOrientation: (UIInterfaceOrientation)o
{
	_isRotating = NO;

	// We need to set these here, because during the animation we may use a wider
	// size (the maximum of the landscape/portrait widths), to avoid clipping during
	// the rotation.
	[canvas setContentSize: CGSizeMake(fz_count_pages(ctx, doc) * width, height)];
	[canvas setContentOffset: CGPointMake(current * width, 0)];
}

@end
