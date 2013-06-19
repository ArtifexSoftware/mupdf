#pragma once

/* WinRT RectList class for binding a collection of rects to the xaml ui */
using namespace Windows::UI::Xaml::Media::Imaging;
using namespace Windows::UI::Xaml::Controls;
using namespace Platform;  /* For String */

namespace mupdf_cpp
{
	[Windows::UI::Xaml::Data::Bindable] // in c++, adding this attribute to ref classes enables data binding for more info search for 'Bindable' on the page http://go.microsoft.com/fwlink/?LinkId=254639

	public ref class RectList sealed
	{
	private:
		int height;
		int width;
		int x;
		int y;
		String^ color;
		/* These are used to store the link infomation */
		int type;
		int pagenum;
		Windows::Foundation::Uri ^uri;
		String^ index; // For identify which rectangle was tapped
	public:
		RectList(void);

		property String^ Index
		{
			String^ get()
			{
				return ((String^) index);
			}

			void set(String^ value)
			{
				index = value;
			}
		}

		property String^ Color
		{
			String^ get()
			{
				return (color);
			}

			void set(String^ value)
			{
				color = value;
			}
		}

		property int Height
		{
			int get()
			{
				return ((int) height);
			}

			void set(int value)
			{
				if (value < 0)
				{
					throw ref new Platform::InvalidArgumentException();
				}
				height = value;
			}
		}

		property int Width
		{
			int get()
			{
				return width;
			}

			void set(int value)
			{
				if (value < 0)
				{
					throw ref new Platform::InvalidArgumentException();
				}
				width = value;
			}
		}

		property int X
		{
			int get()
			{
				return x;
			}

			void set(int value)
			{
				x = value;
			}
		}

		property int Y
		{
			int get()
			{
				return y;
			}

			void set(int value)
			{
				y = value;
			}
		}

		property int Type
		{
			int get()
			{
				return type;
			}

			void set(int value)
			{
				type = value;
			}
		}

		property int PageNum
		{
			int get()
			{
				return pagenum;
			}

			void set(int value)
			{
				pagenum = value;
			}
		}

		property Windows::Foundation::Uri^ Urilink
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
