package com.artifex.mupdf.example;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;

public class MainActivity extends Activity
{
	@Override
	protected void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);

		//  just show the document chooser activity
		Intent intent = new Intent(this, ChooseDocActivity.class);
		startActivity(intent);
		finish();
	}

}
