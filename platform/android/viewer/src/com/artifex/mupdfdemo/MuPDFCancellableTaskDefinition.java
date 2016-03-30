package com.artifex.mupdfdemo;

public abstract class MuPDFCancellableTaskDefinition<Params, Result> implements CancellableTaskDefinition<Params, Result>
{
	private MuPDFCore.Cookie cookie;

	public MuPDFCancellableTaskDefinition(MuPDFCore core)
	{
		this.cookie = core.new Cookie();
	}

	@Override
	public void doCancel()
	{
		if (cookie == null)
			return;

		cookie.abort();
	}

	@Override
	public void doCleanup()
	{
		if (cookie == null)
			return;

		cookie.destroy();
		cookie = null;
	}

	@Override
	public final Result doInBackground(Params ... params)
	{
		return doInBackground(cookie, params);
	}

	public abstract Result doInBackground(MuPDFCore.Cookie cookie, Params ... params);
}
