#import "MuDocumentController.h"
#import "MuOutlineController.h"

@implementation MuOutlineController
{
	MuDocumentController *target;
	NSMutableArray *titles;
	NSMutableArray *pages;
}

- (instancetype) initWithTarget: (id)aTarget titles: (NSMutableArray*)aTitles pages: (NSMutableArray*)aPages
{
	self = [super initWithStyle: UITableViewStylePlain];
	if (self) {
		self.title = @"Table of Contents";
		target = aTarget; // only keep a weak reference, to avoid retain cycles
		titles = [aTitles retain];
		pages = [aPages retain];
		self.tableView.separatorStyle = UITableViewCellSeparatorStyleNone;
	}
	return self;
}

- (void) dealloc
{
	[titles release];
	[pages release];
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
	return titles.count;
}

- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath
{
	return 28;
}

- (UITableViewCell*) tableView: (UITableView*)tableView cellForRowAtIndexPath: (NSIndexPath*)indexPath
{
	static NSString *cellid = @"MuCellIdent";
	UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier: cellid];
	if (!cell)
	{
		cell = [[[UITableViewCell alloc] initWithStyle: UITableViewCellStyleValue1 reuseIdentifier: cellid] autorelease];
		cell.textLabel.font = [UIFont systemFontOfSize: 16];
		cell.detailTextLabel.font = [UIFont systemFontOfSize: 16];
	}
	NSString *title = titles[indexPath.row];
	NSString *page = pages[indexPath.row];
	cell.textLabel.text = title;
	cell.detailTextLabel.text = [NSString stringWithFormat: @"%d", page.intValue+1];
	return cell;
}

- (void) tableView: (UITableView*)tableView didSelectRowAtIndexPath: (NSIndexPath*)indexPath
{
	NSNumber *page = pages[indexPath.row];
	[target gotoPage: page.intValue animated: NO];
	[self.navigationController popViewControllerAnimated: YES];
}

@end
