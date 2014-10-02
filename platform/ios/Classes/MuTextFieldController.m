#import "MuTextFieldController.h"

@interface MuTextFieldController ()
@property (retain, nonatomic) IBOutlet UINavigationBar *navBar;
- (IBAction)onCancel:(id)sender;
- (IBAction)onOkay:(id)sender;
@property (retain, nonatomic) IBOutlet UITextView *textView;

@end

@implementation MuTextFieldController
{
	void (^okayBlock)(NSString *);
	NSString *initialText;
}

-(id)initWithText:(NSString *)text okayAction:(void (^)(NSString *))block
{
	self = [super initWithNibName:@"MuTextFieldController" bundle:nil];
	if (self)
	{
		okayBlock = Block_copy(block);
		initialText = [text retain];
	}
	return self;
}

- (void)viewDidLoad
{
	[super viewDidLoad];
	_textView.text = initialText;
	[_textView becomeFirstResponder];
}

- (void)didReceiveMemoryWarning
{
	[super didReceiveMemoryWarning];
}

- (void)dealloc
{
	[okayBlock release];
	[initialText release];
	[_navBar release];
	[_textView release];
	[super dealloc];
}

- (IBAction)onOkay:(id)sender
{
	okayBlock(_textView.text);
	[self dismissViewControllerAnimated:YES completion:nil];
}

- (IBAction)onCancel:(id)sender
{
	[self dismissViewControllerAnimated:YES completion:nil];
}
@end
