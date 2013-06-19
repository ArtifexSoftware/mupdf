#pragma once

using namespace Platform;  /* For String */

namespace mupdfwinrt {
	[Windows::UI::Xaml::Data::Bindable]
	public ref class ContentItem sealed
	{
		private:
			int page;
			String^ string_orig;
			String^ string_margin;

		public:
			ContentItem(void);

		property int Page
		{
			int get()
			{
				return (page);
			}

			void set(int value)
		        {
				if (value < 0)
					throw ref new Platform::InvalidArgumentException();
				page = value;
			}
		}

		property String^ StringOrig
		{
			String^ get()
			{
				return (string_orig);
			}

			void set(String^ value)
			{
				string_orig = value;
			}
		}

		property String^ StringMargin
		{
			String^ get()
			{
				return (string_margin);
			}

			void set(String^ value)
			{
				string_margin = value;
			}
		}
	};
}
