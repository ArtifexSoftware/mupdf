#pragma once
#include <windows.graphics.printing.h>
#include <printpreview.h>
#include <documentsource.h>
#include "MainPage.xaml.h"

using namespace Microsoft::WRL;
using namespace mupdf_cpp;

/* This is the interface to the print thread calls */
class PrintPages : public Microsoft::WRL::RuntimeClass<Microsoft::WRL::RuntimeClassFlags<Microsoft::WRL::WinRtClassicComMix>,
															ABI::Windows::Graphics::Printing::IPrintDocumentSource,
															IPrintDocumentPageSource,
															IPrintPreviewPageCollection>
{
private:
	InspectableClass(L"Windows.Graphics.Printing.IPrintDocumentSource", BaseTrust);

public:
	HRESULT RuntimeClassInitialize(IUnknown* pageRenderer)
	{
		HRESULT hr = (pageRenderer != nullptr) ? S_OK : E_INVALIDARG;

		if (SUCCEEDED(hr))
		{
			m_paginate_called = false;
			m_totalpages = 1;
			m_height = 0.f;
			m_width = 0.f;
			m_renderer = reinterpret_cast<MainPage^>(pageRenderer);
		}
		return hr;
	}
	IFACEMETHODIMP GetPreviewPageCollection(IPrintDocumentPackageTarget*  doc_target,
											IPrintPreviewPageCollection** doc_collection);
	IFACEMETHODIMP MakeDocument(IInspectable* doc_options, 
								IPrintDocumentPackageTarget* doc_target);
	IFACEMETHODIMP Paginate(uint32 current_jobpage, IInspectable* doc_options);
	IFACEMETHODIMP MakePage(uint32 desired_jobpage, float  width, float  height);
	void ResetPreview();

private:
	float TransformedPageSize(float desired_width, float desired_height, 
								Windows::Foundation::Size* preview_size);
	uint32 m_totalpages;
	bool m_paginate_called;
	float m_height;
	float m_width;
	D2D1_RECT_F m_imageable_rect;
	MainPage^ m_renderer;

	Microsoft::WRL::ComPtr<IPrintPreviewDxgiPackageTarget> m_dxgi_previewtarget;

	void DrawPreviewSurface(float width, float height, float scale_in, 
								  D2D1_RECT_F contentBox, uint32 page_num, 
								  IPrintPreviewDxgiPackageTarget* previewTarget);
};
