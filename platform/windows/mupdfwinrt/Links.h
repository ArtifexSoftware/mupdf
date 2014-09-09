#pragma once

#include "utils.h"
#include "status.h"

using namespace Windows::Foundation;

namespace mupdfwinrt
{
	public ref class Links sealed
	{
	private:
		int type;
		Point upper_left;
		Point lower_right;
		Windows::Foundation::Uri ^uri;
		int page_num;
	public:
		Links(void);

		property int Type
		{
			int get()
			{
				return (type);
			}

			void set(int value)
			{
				if (value > NOT_SET)
					throw ref new Platform::InvalidArgumentException();
				type = value;
			}
		}

		property Point UpperLeft
		{
			Point get()
			{
				return upper_left;
			}

			void set(Point value)
			{
				upper_left = value;
			}
		}

		property Point LowerRight
		{
			Point get()
			{
				return lower_right;
			}

			void set(Point value)
			{
				lower_right = value;
			}
		}

		property int PageNum
		{
			int get()
			{
				return page_num;
			}

			void set(int value)
			{
				page_num = value;
			}
		}

		property Windows::Foundation::Uri^ Uri
		{
			Windows::Foundation::Uri^ get()
			{
				return uri;
			}

			void set(Windows::Foundation::Uri^ value)
			{
				uri = value;
			}
		}
	};
}
