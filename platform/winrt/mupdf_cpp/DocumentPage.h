#pragma once

#include "RectList.h"
#include <collection.h>

/* Used for binding to the xaml in the scroll view. */
using namespace Windows::UI::Xaml::Media::Imaging;
using namespace Windows::UI::Xaml::Controls;
using namespace Windows::Foundation::Collections;
using namespace Windows::UI::Xaml::Data;

typedef enum {
	FULL_RESOLUTION = 0,
	THUMBNAIL,
	DUMMY,
	OLD_RESOLUTION,
	NOTSET
} Page_Content_t;

namespace mupdf_cpp
{
	// enables data binding with this class
	[Windows::UI::Xaml::Data::Bindable]
	public ref class DocumentPage sealed : Windows::UI::Xaml::Data::INotifyPropertyChanged
	{
	private:
		int height;
		int width;
		double zoom;
		WriteableBitmap^ image;
		Page_Content_t content;
		IVector<RectList^>^ textbox;
		IVector<RectList^>^ linkbox;
	public:
		DocumentPage(void);

		/* Note IVector needed for WinRT interface */
		property IVector<RectList^>^ TextBox
		{
			IVector<RectList^>^ get()
			{
				return (textbox);
			}

			void set(IVector<RectList^>^ value)
			{
				textbox = value;
				DocumentPage::OnPropertyChanged("TextBox");
			}
		}

		property IVector<RectList^>^ LinkBox
		{
			IVector<RectList^>^ get()
			{
				return (linkbox);
			}

			void set(IVector<RectList^>^ value)
			{
				linkbox = value;
				DocumentPage::OnPropertyChanged("LinkBox");
			}
		}

		property int Content
		{
			int get()
			{
				return ((int) content);
			}

			void set(int value)
			{
				if (value > NOTSET)
				{
					throw ref new Platform::InvalidArgumentException();
				}
				content = (Page_Content_t) value;
			}
		}

		property int Height
		{
			int get()
			{
				return height;
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

		property double Zoom
		{
			double get()
			{
				return zoom;
			}

			void set(double value)
			{
				if (value < 0)
				{
					throw ref new Platform::InvalidArgumentException();
				}
				zoom = value;
			}
		}

		property WriteableBitmap^ Image
		{
			WriteableBitmap^ get()
			{
				return image;
			}

			void set(WriteableBitmap^ value)
			{
				image = value;
				DocumentPage::OnPropertyChanged("Image");
			}
		}

		private:
			bool _isPropertyChangedObserved;
			event Windows::UI::Xaml::Data::PropertyChangedEventHandler^ _privatePropertyChanged;

		protected:
			/// <summary>
			/// Notifies listeners that a property value has changed.
			/// </summary>
			/// <param name="propertyName">Name of the property used to notify listeners.</param>
			void OnPropertyChanged(String^ propertyName)
			{
				if (_isPropertyChangedObserved)
				{
					PropertyChanged(this, ref new PropertyChangedEventArgs(propertyName));
				}
			}

		public:

			// in c++, it is not neccessary to include definitions
			// of add, remove, and raise. These definitions have
			// been made explicitly here so that we can check if
			// the event has listeners before firing the event.
			virtual event Windows::UI::Xaml::Data::PropertyChangedEventHandler^ PropertyChanged
			{
				virtual Windows::Foundation::EventRegistrationToken add(Windows::UI::Xaml::Data::PropertyChangedEventHandler^ e)
				{
					_isPropertyChangedObserved = true;
					return _privatePropertyChanged += e;
				}

				virtual void remove(Windows::Foundation::EventRegistrationToken t)
				{
					_privatePropertyChanged -= t;
				}

			protected:
				virtual void raise(Object^ sender, Windows::UI::Xaml::Data::PropertyChangedEventArgs^ e)
				{
					if (_isPropertyChangedObserved)
					{
						_privatePropertyChanged(sender, e);
					}
				}
			}
#pragma endregion
	};
}
