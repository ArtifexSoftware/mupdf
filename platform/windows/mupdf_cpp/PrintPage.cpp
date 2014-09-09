#include "pch.h"
#include "PrintPage.h"

using namespace Microsoft::WRL;
using namespace Windows::Graphics::Printing;

#pragma region IDocumentPageSource Methods

/* This is the interface to the print thread calls */
IFACEMETHODIMP
PrintPages::GetPreviewPageCollection(IPrintDocumentPackageTarget*  doc_target,
										IPrintPreviewPageCollection** doc_collection)
{
	HRESULT hr = (doc_target != nullptr) ? S_OK : E_INVALIDARG;

	if (SUCCEEDED(hr))
	{
		hr = doc_target->GetPackageTarget(ID_PREVIEWPACKAGETARGET_DXGI,
												IID_PPV_ARGS(&m_dxgi_previewtarget));
	}
	ComPtr<IPrintPreviewPageCollection> page_collection;
	if (SUCCEEDED(hr))
	{
		ComPtr<PrintPages> docSource(this);
		hr = docSource.As<IPrintPreviewPageCollection>(&page_collection);
	}
	if (SUCCEEDED(hr))
		hr = page_collection.CopyTo(doc_collection);

	if (SUCCEEDED(hr))
		this->m_renderer->SetPrintTarget((void*) this);
	return hr;
}

IFACEMETHODIMP
PrintPages::MakeDocument(IInspectable* doc_options, IPrintDocumentPackageTarget* doc_target)
{
	if (doc_options == nullptr || doc_target == nullptr)
		return E_INVALIDARG;

	PrintTaskOptions^ option = reinterpret_cast<PrintTaskOptions^>(doc_options);
	PrintPageDescription page_desc = option->GetPageDescription(1);

	D2D1_PRINT_CONTROL_PROPERTIES print_properties;

	print_properties.rasterDPI  = (float)(min(page_desc.DpiX, page_desc.DpiY));
	print_properties.colorSpace = D2D1_COLOR_SPACE_SRGB;
	print_properties.fontSubset = D2D1_PRINT_FONT_SUBSET_MODE_DEFAULT;

	HRESULT hr = S_OK;

	try
	{
		m_renderer->CreatePrintControl(doc_target, &print_properties);

		D2D1_RECT_F imageableRect = D2D1::RectF(page_desc.ImageableRect.X, 
												page_desc.ImageableRect.Y,
							page_desc.ImageableRect.X + page_desc.ImageableRect.Width,
							page_desc.ImageableRect.Y + page_desc.ImageableRect.Height);

		D2D1_SIZE_F pageSize = D2D1::SizeF(page_desc.PageSize.Width, page_desc.PageSize.Height);
		m_totalpages = m_renderer->GetPrintPageCount();

		for (uint32 page_num = 1; page_num <= m_totalpages; ++page_num)
			m_renderer->PrintPage(page_num, imageableRect, pageSize, (float) page_desc.DpiX, nullptr);
	}
	catch (Platform::Exception^ e)
	{
		hr = e->HResult;
	}

	HRESULT hrClose = m_renderer->ClosePrintControl();
	if (SUCCEEDED(hr))
	{
		hr = hrClose;
	}
	return hr;
}

#pragma endregion IDocumentPageSource Methods

#pragma region IPrintPreviewPageCollection Methods

IFACEMETHODIMP
PrintPages::Paginate(uint32 current_jobpage, IInspectable* doc_options)
{
	HRESULT hr = (doc_options != nullptr) ? S_OK : E_INVALIDARG;

	if (SUCCEEDED(hr))
	{
		PrintTaskOptions^ option = reinterpret_cast<PrintTaskOptions^>(doc_options);
		PrintPageDescription page_desc = option->GetPageDescription(current_jobpage);

		hr = m_dxgi_previewtarget->InvalidatePreview();
		m_totalpages = m_renderer->GetPrintPageCount();

		if (SUCCEEDED(hr))
			hr = m_dxgi_previewtarget->SetJobPageCount(PageCountType::FinalPageCount, m_totalpages);

		if (SUCCEEDED(hr))
		{
			m_width = page_desc.PageSize.Width;
			m_height = page_desc.PageSize.Height;
			m_imageable_rect = D2D1::RectF(page_desc.ImageableRect.X, page_desc.ImageableRect.Y,
										page_desc.ImageableRect.X + page_desc.ImageableRect.Width,
										page_desc.ImageableRect.Y + page_desc.ImageableRect.Height);
			m_paginate_called = true;
		}
	}
	return hr;
}

float
PrintPages::TransformedPageSize(float desired_width, float desired_height, 
									Windows::Foundation::Size* preview_size)
{
	float scale = 1.0f;

	if (desired_width > 0 && desired_height > 0)
	{
		preview_size->Width  = desired_width;
		preview_size->Height = desired_height;
		scale = m_width / desired_width;
	}
	else
	{
		preview_size->Width = 0;
		preview_size->Height = 0;
	}
	return scale;
}

void
PrintPages::ResetPreview()
{
	m_dxgi_previewtarget->InvalidatePreview();
}

IFACEMETHODIMP
PrintPages::MakePage(uint32 desired_jobpage, float  width, float  height)
{
	HRESULT hr = (width > 0 && height > 0) ? S_OK : E_INVALIDARG;

	if (desired_jobpage == JOB_PAGE_APPLICATION_DEFINED && m_paginate_called)
		desired_jobpage = 1;

	if (SUCCEEDED(hr) && m_paginate_called)
	{
		Windows::Foundation::Size preview_size;
		float scale = TransformedPageSize(width, height, &preview_size);

		try
		{
			m_renderer->DrawPreviewSurface(preview_size.Width, preview_size.Height,
											scale, m_imageable_rect, desired_jobpage,
											m_dxgi_previewtarget.Get());
		}
		catch (Platform::Exception^ e)
		{
			hr = e->HResult;
		}
	}
	return hr;
}
#pragma region IPrintPreviewPageCollection Methods
