#include "common.h"
#import "MuDocumentController.h"
#import "MuLibraryController.h"

static void showAlert(NSString *msg, NSString *filename)
{
	UIAlertView *alert = [[UIAlertView alloc]
		initWithTitle: msg
		message: filename
		delegate: nil
		cancelButtonTitle: @"Okay"
		otherButtonTitles: nil];
	[alert show];
	[alert release];
}

@implementation MuLibraryController
{
	NSArray *files;
	NSTimer *timer;
	MuDocRef *doc;
	NSString *_filename;
	char *_filePath;
}

- (void) viewWillAppear: (BOOL)animated
{
	[super viewWillAppear:animated];
	[self setTitle: @"PDF, XPS, CBZ and EPUB Documents"];
	[self reload];
	printf("library viewWillAppear (starting reload timer)\n");
	timer = [NSTimer timerWithTimeInterval: 3
		target: self selector: @selector(reload) userInfo: nil
		repeats: YES];
	[[NSRunLoop currentRunLoop] addTimer: timer forMode: NSDefaultRunLoopMode];
}

- (void) viewWillDisappear: (BOOL)animated
{
	[super viewWillDisappear:animated];
	printf("library viewWillDisappear (stopping reload timer)\n");
	[timer invalidate];
	timer = nil;
}

- (void) reload
{
	if (files) {
		[files release];
		files = nil;
	}

	NSFileManager *fileman = [NSFileManager defaultManager];
	NSString *docdir = [NSString stringWithFormat: @"%@/Documents", NSHomeDirectory()];
	NSMutableArray *outfiles = [[NSMutableArray alloc] init];
	NSDirectoryEnumerator *direnum = [fileman enumeratorAtPath:docdir];
	NSString *file;
	BOOL isdir;
	while (file = [direnum nextObject]) {
		NSString *filepath = [docdir stringByAppendingPathComponent:file];
		if ([fileman fileExistsAtPath:filepath isDirectory:&isdir] && !isdir) {
			[outfiles addObject:file];
		}
	}

	files = outfiles;

	[[self tableView] reloadData];
}

- (void) dealloc
{
	[doc release];
	[files release];
	[super dealloc];
}

- (BOOL) shouldAutorotateToInterfaceOrientation: (UIInterfaceOrientation)o
{
	return YES;
}

- (NSInteger) numberOfSectionsInTableView: (UITableView*)tableView
{
	return 1;
}

- (NSInteger) tableView: (UITableView*)tableView numberOfRowsInSection: (NSInteger)section
{
	return [files count];
}

- (void) actionSheet:(UIActionSheet *)actionSheet clickedButtonAtIndex:(NSInteger)buttonIndex
{
	if (buttonIndex == [actionSheet destructiveButtonIndex])
	{
		char filename[PATH_MAX];
		NSInteger row = [actionSheet tag];

		dispatch_sync(queue, ^{});

		strcpy(filename, [NSHomeDirectory() UTF8String]);
		strcat(filename, "/Documents/");
		strcat(filename, [[files objectAtIndex: row] UTF8String]);

		printf("delete document '%s'\n", filename);

		unlink(filename);

		[self reload];
	}
}

- (void) onTapDelete: (UIControl*)sender
{
	NSInteger row = [sender tag];
	NSString *title = [NSString stringWithFormat: @"Delete %@?", [files objectAtIndex:row]];
	UIActionSheet *sheet = [[UIActionSheet alloc]
							initWithTitle: title
							delegate: self
							cancelButtonTitle: @"Cancel"
							destructiveButtonTitle: @"Delete"
							otherButtonTitles: nil];
	[sheet setTag: row];
	[sheet showInView: [self tableView]];
	[sheet release];
}

- (UITableViewCell*) tableView: (UITableView*)tableView cellForRowAtIndexPath: (NSIndexPath*)indexPath
{
	static NSString *cellid = @"MuCellIdent";
	UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier: cellid];
	if (!cell)
		cell = [[[UITableViewCell alloc] initWithStyle: UITableViewCellStyleDefault reuseIdentifier: cellid] autorelease];
	NSInteger row = [indexPath row];
	[[cell textLabel] setText: [files objectAtIndex: row]];
	[[cell textLabel] setFont: [UIFont systemFontOfSize: 20]];

	UIButton *deleteButton = [UIButton buttonWithType:UIButtonTypeCustom];
	[deleteButton setImage: [UIImage imageNamed: @"x_alt_blue.png"] forState: UIControlStateNormal];
	[deleteButton setFrame: CGRectMake(0, 0, 35, 35)];
	[deleteButton addTarget: self action: @selector(onTapDelete:) forControlEvents: UIControlEventTouchUpInside];
	[deleteButton setTag: row];
	[cell setAccessoryView: deleteButton];

	return cell;
}

- (void) tableView: (UITableView*)tableView didSelectRowAtIndexPath: (NSIndexPath*)indexPath
{
	NSInteger row = [indexPath row];
	[self openDocument: [files objectAtIndex: row]];
}

static NSString *alteredfilename(NSString *name, int i)
{
	if (i == 0)
		return name;

	NSString *nam = [name stringByDeletingPathExtension];
	NSString *e = [name pathExtension];
	return [[[NSString alloc] initWithFormat:@"%@(%d).%@", nam, i, e] autorelease];
}

static NSString *moveOutOfInbox(NSString *docpath)
{
	if ([docpath hasPrefix:@"Inbox/"])
	{
		NSFileManager *fileMan = [NSFileManager defaultManager];
		NSString *base = [docpath stringByReplacingOccurrencesOfString:@"Inbox/" withString:@""];

		for (int i = 0; YES; i++)
		{
			NSString *newname = alteredfilename(base, i);
			NSString *newfullpath = [NSString pathWithComponents:[NSArray arrayWithObjects:NSHomeDirectory(), @"Documents", newname, nil]];

			if (![fileMan fileExistsAtPath:newfullpath])
			{
				NSString *fullpath = [NSString pathWithComponents:[NSArray arrayWithObjects:NSHomeDirectory(), @"Documents", docpath, nil]];
				[fileMan copyItemAtPath:fullpath toPath:newfullpath error:nil];
				[fileMan removeItemAtPath:fullpath error:nil];
				return newname;
			}
		}
	}

	return docpath;
}

- (void) openDocument: (NSString*)nsfilename
{
	nsfilename = moveOutOfInbox(nsfilename);
	NSString *nspath = [[NSArray arrayWithObjects:NSHomeDirectory(), @"Documents", nsfilename, nil]
							componentsJoinedByString:@"/"];
	_filePath = malloc(strlen([nspath UTF8String])+1);
	if (_filePath == NULL) {
		showAlert(@"Out of memory in openDocument", nsfilename);
		return;
	}

	strcpy(_filePath, [nspath UTF8String]);

	dispatch_sync(queue, ^{});

	printf("open document '%s'\n", _filePath);

	_filename = [nsfilename retain];
	[doc release];
	doc = [[MuDocRef alloc] initWithFilename:_filePath];
	if (!doc) {
		showAlert(@"Cannot open document", nsfilename);
		return;
	}

	if (fz_needs_password(ctx, doc->doc))
		[self askForPassword: @"'%@' needs a password:"];
	else
		[self onPasswordOkay];
}

- (void) askForPassword: (NSString*)prompt
{
	UIAlertView *passwordAlertView = [[UIAlertView alloc]
		initWithTitle: @"Password Protected"
		message: [NSString stringWithFormat: prompt, [_filename lastPathComponent]]
		delegate: self
		cancelButtonTitle: @"Cancel"
		otherButtonTitles: @"Done", nil];
	[passwordAlertView setAlertViewStyle: UIAlertViewStyleSecureTextInput];
	[passwordAlertView show];
	[passwordAlertView release];
}

- (void)alertView:(UIAlertView *)alertView clickedButtonAtIndex:(NSInteger)buttonIndex
{
	char *password = (char*) [[[alertView textFieldAtIndex: 0] text] UTF8String];
	[alertView dismissWithClickedButtonIndex: buttonIndex animated: TRUE];
	if (buttonIndex == 1) {
		if (fz_authenticate_password(ctx, doc->doc, password))
			[self onPasswordOkay];
		else
			[self askForPassword: @"Wrong password for '%@'. Try again:"];
	} else {
		[self onPasswordCancel];
	}
}

- (void) onPasswordOkay
{
	MuDocumentController *document = [[MuDocumentController alloc] initWithFilename: _filename path:_filePath document: doc];
	if (document) {
		[self setTitle: @"Library"];
		[[self navigationController] pushViewController: document animated: YES];
		[document release];
	}
	[_filename release];
	free(_filePath);
}

- (void) onPasswordCancel
{
	[_filename release];
	free(_filePath);
	printf("close document (password cancel)\n");
}

@end
