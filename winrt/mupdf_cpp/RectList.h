#pragma once


/* Used for binding to the xaml in the scroll view. */
using namespace Windows::UI::Xaml::Media::Imaging;
using namespace Windows::UI::Xaml::Controls;


        
namespace mupdf_cpp
{
    [Windows::UI::Xaml::Data::Bindable] // in c++, adding this attribute to ref classes enables data binding for more info search for 'Bindable' on the page http://go.microsoft.com/fwlink/?LinkId=254639 

    public ref class RectList sealed
    {
    private:
        int heightr;
        int widthr;
        int x;
        int y; 
    public:
        RectList(void);

        property int HeightR
        {
            int get() { return ((int) heightr); }
            void set(int value)
            {
                if (value < 0)
                { 
                    throw ref new Platform::InvalidArgumentException(); 
                }
                heightr = value;
            }
        }

        property int WidthR
        {
            int get() { return widthr; }
            void set(int value)
            {
                if (value < 0) 
                { 
                    throw ref new Platform::InvalidArgumentException(); 
                }
                widthr = value;
            }
        }

        property int X
        {
            int get() { return x; }
            void set(int value)
            {
                x = value;
            }
        }

        property int Y
        {
            int get() { return y; }
            void set(int value)
            {
                y = value;
            }
        }
    };
}
