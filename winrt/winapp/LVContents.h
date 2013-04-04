#pragma once
namespace ListViewContents {
  [Windows::UI::Xaml::Data::Bindable]
  public ref class LVContents sealed
  {
  public:
    LVContents(void);
    property Platform::String^ ContentItem;
    property int Page;

  };
}
