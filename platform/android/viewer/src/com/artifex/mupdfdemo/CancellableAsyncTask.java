package com.artifex.mupdfdemo;

import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;

// Ideally this would be a subclass of AsyncTask, however the cancel() method is final, and cannot
// be overridden. I felt that having two different, but similar cancel methods was a bad idea.
public class CancellableAsyncTask<Params, Result>
{
	private final AsyncTask<Params, Void, Result> asyncTask;
	private final CancellableTaskDefinition<Params, Result> ourTask;

	public void onPreExecute()
	{

	}

	public void onPostExecute(Result result)
	{

	}

	public CancellableAsyncTask(final CancellableTaskDefinition<Params, Result> task)
	{
		if (task == null)
				throw new IllegalArgumentException();

		this.ourTask = task;
		asyncTask = new AsyncTask<Params, Void, Result>()
				{
					@Override
					protected Result doInBackground(Params... params)
					{
						return task.doInBackground(params);
					}

					@Override
					protected void onPreExecute()
					{
						CancellableAsyncTask.this.onPreExecute();
					}

					@Override
					protected void onPostExecute(Result result)
					{
						CancellableAsyncTask.this.onPostExecute(result);
						task.doCleanup();
					}

					@Override
					protected void onCancelled(Result result)
					{
						task.doCleanup();
					}
				};
	}

	public void cancel()
	{
		this.asyncTask.cancel(true);
		ourTask.doCancel();

		try
		{
			this.asyncTask.get();
		}
		catch (InterruptedException e)
		{
		}
		catch (ExecutionException e)
		{
		}
		catch (CancellationException e)
		{
		}
	}

	public void execute(Params ... params)
	{
		asyncTask.execute(params);
	}

}
