package com.artifex.mupdf.example;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.res.Resources;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.os.FileObserver;
import android.os.Handler;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ListView;

import java.io.File;
import java.io.FileFilter;
import java.util.Arrays;
import java.util.Comparator;

public class ChooseDocActivity
		extends Activity
{
	private ListView mListView;
	private ChooseDocAdapter adapter;
	static private File mDirectory;
	static private File mStartingDirectory;
	private File mParent;
	private File[] mDirs;
	private File[] mFiles;
	private Handler mHandler;
	private Runnable mUpdateFiles;

	@Override
	protected void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);

		setContentView(R.layout.choose_doc);

		mHandler = new Handler();

		String storageState = Environment.getExternalStorageState();
		if (!Environment.MEDIA_MOUNTED.equals(storageState) &&
			!Environment.MEDIA_MOUNTED_READ_ONLY.equals(storageState))
		{
			showMessage(getResources().getString(R.string.no_media_warning),
						getResources().getString(R.string.no_media_hint),
						getResources().getString(R.string.dismiss));

			return;
		}

		if (mDirectory == null) {
			mDirectory = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
			mStartingDirectory = mDirectory;  //  remember where we started
		}

		// Create the list...
		mListView = (ListView)findViewById(R.id.fileListView);
		mListView.setOnItemClickListener(new AdapterView.OnItemClickListener() {
			@Override
			public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
				onListItemClick(mListView, view, position, id);
			}
		});

		// Create a list adapter...
		adapter = new ChooseDocAdapter(getLayoutInflater());
		mListView.setAdapter(adapter);

		// ...that is updated dynamically when files are scanned
		mUpdateFiles = new Runnable() {
			public void run() {
				Resources res = getResources();
				String appName = res.getString(R.string.app_name);
				String version = res.getString(R.string.version);
				String title = res.getString(R.string.picker_title_App_Ver_Dir);
				setTitle(String.format(title, appName, version, mDirectory));

				mParent = mDirectory.getParentFile();

				mDirs = mDirectory.listFiles(new FileFilter() {

					public boolean accept(File file) {
						return file.isDirectory();
					}
				});
				if (mDirs == null)
					mDirs = new File[0];

				mFiles = mDirectory.listFiles(new FileFilter() {

					public boolean accept(File file) {
						if (file.isDirectory())
							return false;

						String fname = file.getName().toLowerCase();

						if (fname.endsWith(".pdf"))
							return true;
						if (fname.endsWith(".xps"))
							return true;
						if (fname.endsWith(".cbz"))
							return true;
						if (fname.endsWith(".epub"))
							return true;
						if (fname.endsWith(".png"))
							return true;
						if (fname.endsWith(".jpe"))
							return true;
						if (fname.endsWith(".jpeg"))
							return true;
						if (fname.endsWith(".jpg"))
							return true;
						if (fname.endsWith(".jfif"))
							return true;
						if (fname.endsWith(".jfif-tbnl"))
							return true;
						if (fname.endsWith(".tif"))
							return true;
						if (fname.endsWith(".tiff"))
							return true;

						return false;
					}
				});
				if (mFiles == null)
					mFiles = new File[0];

				Arrays.sort(mFiles, new Comparator<File>() {
					public int compare(File arg0, File arg1) {
						return arg0.getName().compareToIgnoreCase(arg1.getName());
					}
				});

				Arrays.sort(mDirs, new Comparator<File>() {
					public int compare(File arg0, File arg1) {
						return arg0.getName().compareToIgnoreCase(arg1.getName());
					}
				});

				adapter.clear();

				//  add a button for going up one level
				if (mParent != null)
					if (!mDirectory.getAbsolutePath().equals(mStartingDirectory.getAbsolutePath()))
						adapter.add(new ChooseDocItem(ChooseDocItem.Type.PARENT, getString(R.string.parent_directory), mParent.getAbsolutePath()));

				for (File f : mDirs)
					adapter.add(new ChooseDocItem(ChooseDocItem.Type.DIR, f.getName(), f.getAbsolutePath()));
				for (File f : mFiles)
					adapter.add(new ChooseDocItem(ChooseDocItem.Type.DOC, f.getName(), f.getAbsolutePath()));
			}
		};

		//  Start initial file scan...
		mHandler.post(mUpdateFiles);

		// ...and observe the directory and scan files upon changes.
		FileObserver observer = new FileObserver(mDirectory.getPath(), FileObserver.CREATE | FileObserver.DELETE) {
			public void onEvent(int event, String path) {
				mHandler.post(mUpdateFiles);
			}
		};
		observer.startWatching();
	}

	private void onListItemClick(ListView l, View v, int position, long id)
	{
		ChooseDocItem item = (ChooseDocItem) v.getTag();
		File f = new File(item.path);
		if (item.type== ChooseDocItem.Type.PARENT || item.type== ChooseDocItem.Type.DIR)
		{
			mDirectory = f;
			mHandler.post(mUpdateFiles);
			return;
		}

		//  start a viewing activity
		Uri uri = Uri.parse(f.getAbsolutePath());
		Intent intent;
		intent = new Intent(this, DocViewActivity.class);
		intent.setAction(Intent.ACTION_VIEW);
		intent.setData(uri);
		startActivity(intent);
	}

	@Override
	protected void onPause() {
		super.onPause();
	}

	@Override
	protected void onResume() {
		super.onResume();

		// do another file scan to pick up changes to files since we were away
		mHandler.post(mUpdateFiles);
	}

	//  this hides the activity
	@Override
	public void onBackPressed() {
		moveTaskToBack (true);
	}

	private void showMessage(final String title, final String body, final String okLabel)
	{
		final Activity activity = this;
		runOnUiThread(new Runnable() {
			@Override
			public void run() {
				new AlertDialog.Builder(activity)
						.setTitle(title)
						.setMessage(body)
						.setCancelable(false)
						.setPositiveButton(okLabel, new DialogInterface.OnClickListener() {
							@Override
							public void onClick(DialogInterface dialog, int which) {
								dialog.dismiss();
							}
						}).create().show();
			}
		});
	}
}
