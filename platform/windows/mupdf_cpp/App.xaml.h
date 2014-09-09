//
// App.xaml.h
// Declaration of the App class.
//

#pragma once

#include "App.g.h"

namespace mupdf_cpp
{
	/// <summary>
	/// Provides application-specific behavior to supplement the default Application class.
	/// </summary>
	ref class App sealed
	{
	public:
		App();
		virtual void OnLaunched(Windows::ApplicationModel::Activation::LaunchActivatedEventArgs^ args) override;
	virtual void App::OnFileActivated(Windows::ApplicationModel::Activation::FileActivatedEventArgs^ args) override;
	private:
		void OnSuspending(Platform::Object^ sender, Windows::ApplicationModel::SuspendingEventArgs^ e);
	};
}
