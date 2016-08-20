package com.artifex.mupdf.android;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.view.LayoutInflater;
import android.view.View;
import android.webkit.MimeTypeMap;
import android.widget.EditText;

import com.artifex.mupdf.fitz.R;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class Utilities
{
	public static boolean copyFile(String src, String dst, boolean overwrite)
	{
		File dstf = new File(dst);
		File srcf = new File(src);

		//  if we can't overwrite, error
		if (!overwrite && dstf.exists())
			return false;

		//  if we must overwrite but can't delete, error
		if (overwrite && dstf.exists()) {
			boolean deleted = deleteFile(dst);
			if (!deleted)
				return false;
		}

		//  now copy
		copyWithStreams(srcf, dstf);

		return true;
	}

	private static void copyWithStreams(File aSourceFile, File aTargetFile)
	{
		InputStream inStream = null;
		OutputStream outStream = null;

		try
		{
			try
			{
				byte[] bucket = new byte[32*1024];
				inStream = new BufferedInputStream(new FileInputStream(aSourceFile));
				outStream = new BufferedOutputStream(new FileOutputStream(aTargetFile, false));
				int bytesRead = 0;
				while(bytesRead != -1)
				{
					bytesRead = inStream.read(bucket); //-1, 0, or more
					if(bytesRead > 0){
						outStream.write(bucket, 0, bytesRead);
					}
				}
			}
			finally
			{
				if (inStream != null)
					inStream.close();
				if (outStream != null)
					outStream.close();
			}
		}
		catch (FileNotFoundException ex){
		}
		catch (IOException ex){
		}
	}

	public static boolean deleteFile (String path)
	{
		try
		{
			File fileToDelete = new File(path);
			if (fileToDelete.exists()) {
				fileToDelete.delete();
			}
		}
		catch(Exception e)
		{
			return false;
		}

		return true;
	}

	public static boolean renameFile (String oldPath, String newPath)
	{
		File fOld = new File(oldPath);
		File fNew = new File(newPath);
		return fOld.renameTo(fNew);
	}

	//  this function safely replaces a file by first renaming it
	//  and, if the copy fails, renaming it back.
	public static boolean replaceFile (String srcPath, String dstPath)
	{
		//  source file must exist
		File srcFile = new File(srcPath);
		if (!srcFile.exists())
			return false;

		//  destination file may or may not exist
		File dstFile = new File(dstPath);
		boolean dstExists = dstFile.exists();
		String tmp = dstPath+"xxx";

		//  if tmp exists, error
		File tmpFile = new File(tmp);
		if (tmpFile.exists())
			return false;

		//  rename the destination temporarily
		if (dstExists) {
			if (!renameFile(dstPath,tmp)) {
				//  rename error, do nothing else.
				return false;
			}
		}

		//  copy the file
		if (!copyFile(srcPath,dstPath,true)) {
			//  copy failed, put the destination back
			if (dstExists) {
				if (!renameFile(tmp,dstPath)) {
					//  bad mojo here.  Can't rename back,
					//  file appears lost.
				}
			}
			return false;
		}

		//  copy succeeded, now delete the tmp file
		deleteFile(tmp);

		return true;
	}

	//  get the extension part of the filename, not including the "."
	public static  String getExtension(String filename)
	{
		String filenameArray[] = filename.split("\\.");

		if (filenameArray.length<=1)
		{
			//  no extension
			return "";
		}

		String extension = filenameArray[filenameArray.length-1];
		extension = extension.toLowerCase();
		return extension;
	}

	public static void showMessage(final Activity activity, final String title, final String body)
	{
		showMessage(activity, title, body, activity.getResources().getString(R.string.ok));
	}
	public static void showMessage(final Activity activity, final String title, final String body, final String okLabel)
	{
		activity.runOnUiThread(new Runnable() {
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

	public static void showMessageAndFinish(final Activity activity, final String title, final String body)
	{
		activity.runOnUiThread(new Runnable() {
			@Override
			public void run() {
				new AlertDialog.Builder(activity)
						.setTitle(title)
						.setMessage(body)
						.setCancelable(false)
						.setPositiveButton(R.string.ok, new DialogInterface.OnClickListener() {
							@Override
							public void onClick(DialogInterface dialog, int which) {
								dialog.dismiss();
								activity.finish();
							}
						}).create().show();
			}
		});
	}

	public static void passwordDialog( final Activity activity, final passwordDialogListener listener)
	{
		activity.runOnUiThread(new Runnable()
		{
			@Override
			public void run()
			{
				AlertDialog.Builder dialog = new AlertDialog.Builder(activity);
				LayoutInflater li = LayoutInflater.from(activity);
				View promptsView = li.inflate(R.layout.password_prompt, null);

				final EditText et = (EditText)(promptsView.findViewById(R.id.editTextDialogUserInput));

				dialog.setView(promptsView);

				dialog.setTitle("");

				dialog.setPositiveButton(activity.getResources().getString(R.string.ok), new DialogInterface.OnClickListener() {
					@Override
					public void onClick(DialogInterface dialog, int which) {
						dialog.dismiss();
						if (listener!=null)
						{
							String password = et.getText().toString();
							listener.onOK(password);
						}
					}
				});

				dialog.setNegativeButton(activity.getResources().getString(R.string.cancel), new DialogInterface.OnClickListener() {
					@Override
					public void onClick(DialogInterface dialog, int which) {
						dialog.dismiss();
						if (listener!=null)
							listener.onCancel();
					}
				});

				dialog.create().show();
			}
		});
	}

	public interface passwordDialogListener
	{
		void onOK(String password);
		void onCancel();
	}

	public static void yesNoMessage(final Activity activity, final String title, final String body,
									final String yesButtonLabel, final String noButtonLabel,
									final Runnable yesRunnable, final Runnable noRunnable)
	{
		activity.runOnUiThread(new Runnable() {
			@Override
			public void run() {

				AlertDialog.Builder dialog = new AlertDialog.Builder(activity);

				dialog.setTitle(title);
				dialog.setMessage(body);

				dialog.setPositiveButton(yesButtonLabel, new DialogInterface.OnClickListener() {
					@Override
					public void onClick(DialogInterface dialog, int which) {
						dialog.dismiss();
						if (yesRunnable!=null)
							yesRunnable.run();
					}
				});

				dialog.setNegativeButton(noButtonLabel, new DialogInterface.OnClickListener() {
					@Override
					public void onClick(DialogInterface dialog, int which) {
						dialog.dismiss();
						if (noRunnable!=null)
							noRunnable.run();
					}
				});

				dialog.create();
				dialog.show();
			}
		});
	}

	public static File extractAssetToFile(Context context, String file)
	{
		File cacheFile = new File(context.getCacheDir(), file);
		try
		{
			InputStream inputStream = context.getAssets().open(file);
			try
			{
				FileOutputStream outputStream = new FileOutputStream(cacheFile);
				try
				{
					byte[] buf = new byte[1024];
					int len;
					while ((len = inputStream.read(buf)) > 0)
					{
						outputStream.write(buf, 0, len);
					}
				} finally
				{
					outputStream.close();
				}
			} finally
			{
				inputStream.close();
			}
		}
		catch (IOException e)
		{
			e.printStackTrace();
			return null;
		}
		return cacheFile;
	}

	public static String extractAssetToString(Context context, String file)
	{
		String json;
		try {
			InputStream is = context.getAssets().open(file);
			int size = is.available();
			byte[] buffer = new byte[size];
			is.read(buffer);
			is.close();
			json = new String(buffer, "UTF-8");
		} catch (IOException ex) {
			ex.printStackTrace();
			return null;
		}
		return json;
	}

	public static String removeExtention(String filePath)
	{
		File f = new File(filePath);

		// if it's a directory, don't remove the extention
		if (f.isDirectory())
			return filePath;

		String name = f.getName();

		// Now we know it's a file - don't need to do any special hidden
		// checking or contains() checking because of:
		final int lastPeriodPos = name.lastIndexOf('.');
		if (lastPeriodPos <= 0)
		{
			// No period after first character - return name as it was passed in
			return filePath;
		}
		else
		{
			// Remove the last period and everything after it
			File renamed = new File(f.getParent(), name.substring(0, lastPeriodPos));
			return renamed.getPath();
		}
	}

	public static String getMimeType (String path)
	{
		String ext = Utilities.getExtension(path);
		String mime = null;
		if (ext != null) {
			mime = MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext);
		}
		return mime;
	}
}
