#include "common.h"
#include "mupdf/pdf.h"
#import "MuDocRef.h"

@implementation MuDocRef

-(id) initWithFilename:(char *)aFilename;
{
	self = [super init];
	if (self)
	{
		dispatch_sync(queue, ^{});

		fz_var(self);

		fz_try(ctx)
		{
			doc = fz_open_document(ctx, aFilename);
			if (!doc)
			{
				[self release];
				self = nil;
			}
			else
			{
				pdf_document *idoc = pdf_specifics(ctx, doc);
				if (idoc) pdf_enable_js(ctx, idoc);
				interactive = (idoc != NULL) && (pdf_crypt_version(ctx, idoc) == 0);
			}
		}
		fz_catch(ctx)
		{
			if (self)
			{
				if (doc != NULL)
					fz_drop_document(ctx, doc);
				[self release];
				self = nil;
			}
		}
	}
	return self;
}

-(void) dealloc
{
	__block fz_document *block_doc = doc;
	dispatch_async(queue, ^{
		fz_drop_document(ctx, block_doc);
	});
	[super dealloc];
}

@end
