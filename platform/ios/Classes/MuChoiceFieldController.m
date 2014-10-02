#import "MuChoiceFieldController.h"

@interface MuChoiceFieldController ()
- (IBAction)onCancel:(id)sender;
- (IBAction)onOkay:(id)sender;
@property (retain, nonatomic) IBOutlet UIPickerView *picker;
@end

@implementation MuChoiceFieldController
{
	void (^okayBlock)(NSArray *);
	NSArray *choices;
	NSInteger selected;
}

- (id)initWithChoices:(NSArray *)_choices okayAction:(void (^)(NSArray *))block
{
	self = [super initWithNibName:@"MuChoiceFieldController" bundle:nil];
	if (self)
	{
		okayBlock = Block_copy(block);
		choices = [_choices retain];
		selected = 0;
	}
	return self;
}

- (void)viewDidLoad
{
	[super viewDidLoad];
	_picker.dataSource = self;
	_picker.delegate = self;
	// Do any additional setup after loading the view from its nib.
}

- (void)dealloc
{
	[okayBlock release];
	[choices release];
	[_picker release];
	[super dealloc];
}

- (NSInteger)numberOfComponentsInPickerView:(UIPickerView *)pickerView
{
	return 1;
}

- (NSInteger)pickerView:(UIPickerView *)pickerView numberOfRowsInComponent:(NSInteger)component
{
	return [choices count];
}

- (NSString *)pickerView:(UIPickerView *)pickerView titleForRow:(NSInteger)row forComponent:(NSInteger)component
{
	return [choices objectAtIndex:row];
}

- (void) pickerView:(UIPickerView *)pickerView didSelectRow:(NSInteger)row inComponent:(NSInteger)component
{
	selected = row;
}

- (IBAction)onOkay:(id)sender
{
	if (selected >= 0 && selected < [choices count])
		okayBlock([NSArray arrayWithObject:[choices objectAtIndex:selected]]);
	[self dismissViewControllerAnimated:YES completion:nil];
}

- (IBAction)onCancel:(id)sender
{
	[self dismissViewControllerAnimated:YES completion:nil];
}

@end
