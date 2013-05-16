#include "pch.h"
#include "DocumentPage.h"

namespace mupdf_cpp
{
	DocumentPage::DocumentPage(void)
	{
		this->Image = nullptr;
		this->Height = 0;
		this->Width = 0;
		this->Zoom = 1.0;
		this->Content = NOTSET;
		_isPropertyChangedObserved = false;
	}
}
