package com.artifex.mupdfdemo;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnCancelListener;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.Resources;
import android.database.Cursor;
import android.graphics.Color;
import android.graphics.Rect;
import android.graphics.drawable.ShapeDrawable;
import android.graphics.drawable.shapes.RectShape;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.text.Editable;
import android.text.TextWatcher;
import android.text.method.PasswordTransformationMethod;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.view.MenuItem.OnMenuItemClickListener;
import android.view.View;
import android.view.animation.Animation;
import android.view.animation.TranslateAnimation;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.PopupMenu;
import android.widget.RelativeLayout;
import android.widget.SeekBar;
import android.widget.TextView;
import android.widget.ViewAnimator;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.concurrent.Executor;

class ThreadPerTaskExecutor implements Executor {
	public void execute(Runnable r) {
		new Thread(r).start();
	}
}

public class MuPDFActivity extends Activity implements FilePicker.FilePickerSupport
{
	/* The core rendering instance */
	enum TopBarMode {Main, Search, Annot, Delete, More, Accept};
	enum AcceptMode {Highlight, Underline, StrikeOut, Ink, CopyText};

	private final int    OUTLINE_REQUEST=0;
	private final int    PRINT_REQUEST=1;
	private final int    FILEPICK_REQUEST=2;
	private final int    PROOF_REQUEST=3;
	private MuPDFCore    core;
	private String       mFileName;
	private MuPDFReaderView mDocView;
	private View         mButtonsView;
	private boolean      mButtonsVisible;
	private EditText     mPasswordView;
	private TextView     mFilenameView;
	private SeekBar      mPageSlider;
	private int          mPageSliderRes;
	private TextView     mPageNumberView;
	private TextView     mInfoView;
	private ImageButton  mSearchButton;
	private ImageButton  mReflowButton;
	private ImageButton  mOutlineButton;
	private ImageButton	mMoreButton;
	private TextView     mAnnotTypeText;
	private ImageButton mAnnotButton;
	private ViewAnimator mTopBarSwitcher;
	private ImageButton  mLinkButton;
	private TopBarMode   mTopBarMode = TopBarMode.Main;
	private AcceptMode   mAcceptMode;
	private ImageButton  mSearchBack;
	private ImageButton  mSearchFwd;
	private EditText     mSearchText;
	private SearchTask   mSearchTask;
	private ImageButton  mProofButton;
	private ImageButton  mSepsButton;
	private AlertDialog.Builder mAlertBuilder;
	private boolean    mLinkHighlight = false;
	private final Handler mHandler = new Handler();
	private boolean mAlertsActive= false;
	private boolean mReflow = false;
	private AsyncTask<Void,Void,MuPDFAlert> mAlertTask;
	private AlertDialog mAlertDialog;
	private FilePicker mFilePicker;
	private String     mProofFile;
	private boolean mSepEnabled[][];

	static private AlertDialog.Builder gAlertBuilder;
	static public AlertDialog.Builder getAlertBuilder() {return gAlertBuilder;}

	public void createAlertWaiter() {
		mAlertsActive = true;
		// All mupdf library calls are performed on asynchronous tasks to avoid stalling
		// the UI. Some calls can lead to javascript-invoked requests to display an
		// alert dialog and collect a reply from the user. The task has to be blocked
		// until the user's reply is received. This method creates an asynchronous task,
		// the purpose of which is to wait of these requests and produce the dialog
		// in response, while leaving the core blocked. When the dialog receives the
		// user's response, it is sent to the core via replyToAlert, unblocking it.
		// Another alert-waiting task is then created to pick up the next alert.
		if (mAlertTask != null) {
			mAlertTask.cancel(true);
			mAlertTask = null;
		}
		if (mAlertDialog != null) {
			mAlertDialog.cancel();
			mAlertDialog = null;
		}
		mAlertTask = new AsyncTask<Void,Void,MuPDFAlert>() {

			@Override
			protected MuPDFAlert doInBackground(Void... arg0) {
				if (!mAlertsActive)
					return null;

				return core.waitForAlert();
			}

			@Override
			protected void onPostExecute(final MuPDFAlert result) {
				// core.waitForAlert may return null when shutting down
				if (result == null)
					return;
				final MuPDFAlert.ButtonPressed pressed[] = new MuPDFAlert.ButtonPressed[3];
				for(int i = 0; i < 3; i++)
					pressed[i] = MuPDFAlert.ButtonPressed.None;
				DialogInterface.OnClickListener listener = new DialogInterface.OnClickListener() {
					public void onClick(DialogInterface dialog, int which) {
						mAlertDialog = null;
						if (mAlertsActive) {
							int index = 0;
							switch (which) {
							case AlertDialog.BUTTON1: index=0; break;
							case AlertDialog.BUTTON2: index=1; break;
							case AlertDialog.BUTTON3: index=2; break;
							}
							result.buttonPressed = pressed[index];
							// Send the user's response to the core, so that it can
							// continue processing.
							core.replyToAlert(result);
							// Create another alert-waiter to pick up the next alert.
							createAlertWaiter();
						}
					}
				};
				mAlertDialog = mAlertBuilder.create();
				mAlertDialog.setTitle(result.title);
				mAlertDialog.setMessage(result.message);
				switch (result.iconType)
				{
				case Error:
					break;
				case Warning:
					break;
				case Question:
					break;
				case Status:
					break;
				}
				switch (result.buttonGroupType)
				{
				case OkCancel:
					mAlertDialog.setButton(AlertDialog.BUTTON2, getString(R.string.cancel), listener);
					pressed[1] = MuPDFAlert.ButtonPressed.Cancel;
				case Ok:
					mAlertDialog.setButton(AlertDialog.BUTTON1, getString(R.string.okay), listener);
					pressed[0] = MuPDFAlert.ButtonPressed.Ok;
					break;
				case YesNoCancel:
					mAlertDialog.setButton(AlertDialog.BUTTON3, getString(R.string.cancel), listener);
					pressed[2] = MuPDFAlert.ButtonPressed.Cancel;
				case YesNo:
					mAlertDialog.setButton(AlertDialog.BUTTON1, getString(R.string.yes), listener);
					pressed[0] = MuPDFAlert.ButtonPressed.Yes;
					mAlertDialog.setButton(AlertDialog.BUTTON2, getString(R.string.no), listener);
					pressed[1] = MuPDFAlert.ButtonPressed.No;
					break;
				}
				mAlertDialog.setOnCancelListener(new DialogInterface.OnCancelListener() {
					public void onCancel(DialogInterface dialog) {
						mAlertDialog = null;
						if (mAlertsActive) {
							result.buttonPressed = MuPDFAlert.ButtonPressed.None;
							core.replyToAlert(result);
							createAlertWaiter();
						}
					}
				});

				mAlertDialog.show();
			}
		};

		mAlertTask.executeOnExecutor(new ThreadPerTaskExecutor());
	}

	public void destroyAlertWaiter() {
		mAlertsActive = false;
		if (mAlertDialog != null) {
			mAlertDialog.cancel();
			mAlertDialog = null;
		}
		if (mAlertTask != null) {
			mAlertTask.cancel(true);
			mAlertTask = null;
		}
	}

	private MuPDFCore openFile(String path)
	{
		int lastSlashPos = path.lastIndexOf('/');
		mFileName = new String(lastSlashPos == -1
					? path
					: path.substring(lastSlashPos+1));
		System.out.println("Trying to open " + path);
		try
		{
			core = new MuPDFCore(this, path);
			// New file: drop the old outline data
			OutlineActivityData.set(null);
		}
		catch (Exception e)
		{
			System.out.println(e);
			return null;
		}
		catch (java.lang.OutOfMemoryError e)
		{
			//  out of memory is not an Exception, so we catch it separately.
			System.out.println(e);
			return null;
		}
		return core;
	}

	private MuPDFCore openBuffer(byte buffer[], String magic)
	{
		System.out.println("Trying to open byte buffer");
		try
		{
			core = new MuPDFCore(this, buffer, magic);
			// New file: drop the old outline data
			OutlineActivityData.set(null);
		}
		catch (Exception e)
		{
			System.out.println(e);
			return null;
		}
		return core;
	}

	//  determine whether the current activity is a proofing activity.
	public boolean isProofing()
	{
		String format = core.fileFormat();
		return (format.equals("GPROOF"));
	}

	/** Called when the activity is first created. */
	@Override
	public void onCreate(final Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);

		mAlertBuilder = new AlertDialog.Builder(this);
		gAlertBuilder = mAlertBuilder; //  keep a static copy of this that other classes can use

		if (core == null) {
			core = (MuPDFCore)getLastNonConfigurationInstance();

			if (savedInstanceState != null && savedInstanceState.containsKey("FileName")) {
				mFileName = savedInstanceState.getString("FileName");
			}
		}
		if (core == null) {
			Intent intent = getIntent();
			byte buffer[] = null;

			if (Intent.ACTION_VIEW.equals(intent.getAction())) {
				Uri uri = intent.getData();
				System.out.println("URI to open is: " + uri);
				if (uri.toString().startsWith("content://")) {
					String reason = null;
					try {
						InputStream is = getContentResolver().openInputStream(uri);
						int len;
						ByteArrayOutputStream bufferStream = new ByteArrayOutputStream();
						byte[] data = new byte[16384];
						while ((len = is.read(data, 0, data.length)) != -1) {
							bufferStream.write(data, 0, len);
						}
						bufferStream.flush();
						buffer = bufferStream.toByteArray();
						is.close();
					}
					catch (java.lang.OutOfMemoryError e) {
						System.out.println("Out of memory during buffer reading");
						reason = e.toString();
					}
					catch (Exception e) {
						System.out.println("Exception reading from stream: " + e);

						// Handle view requests from the Transformer Prime's file manager
						// Hopefully other file managers will use this same scheme, if not
						// using explicit paths.
						// I'm hoping that this case below is no longer needed...but it's
						// hard to test as the file manager seems to have changed in 4.x.
						try {
							Cursor cursor = getContentResolver().query(uri, new String[]{"_data"}, null, null, null);
							if (cursor.moveToFirst()) {
								String str = cursor.getString(0);
								if (str == null) {
									reason = "Couldn't parse data in intent";
								}
								else {
									uri = Uri.parse(str);
								}
							}
						}
						catch (Exception e2) {
							System.out.println("Exception in Transformer Prime file manager code: " + e2);
							reason = e2.toString();
						}
					}
					if (reason != null) {
						buffer = null;
						Resources res = getResources();
						AlertDialog alert = mAlertBuilder.create();
						setTitle(String.format(res.getString(R.string.cannot_open_document_Reason), reason));
						alert.setButton(AlertDialog.BUTTON_POSITIVE, getString(R.string.dismiss),
								new DialogInterface.OnClickListener() {
									public void onClick(DialogInterface dialog, int which) {
										finish();
									}
								});
						alert.show();
						return;
					}
				}
				if (buffer != null) {
					core = openBuffer(buffer, intent.getType());
				} else {
					String path = Uri.decode(uri.getEncodedPath());
					if (path == null) {
						path = uri.toString();
					}
					core = openFile(path);
				}
				SearchTaskResult.set(null);
			}
			if (core != null && core.needsPassword()) {
				requestPassword(savedInstanceState);
				return;
			}
			if (core != null && core.countPages() == 0)
			{
				core = null;
			}
		}
		if (core == null)
		{
			AlertDialog alert = mAlertBuilder.create();
			alert.setTitle(R.string.cannot_open_document);
			alert.setButton(AlertDialog.BUTTON_POSITIVE, getString(R.string.dismiss),
					new DialogInterface.OnClickListener() {
						public void onClick(DialogInterface dialog, int which) {
							finish();
						}
					});
			alert.setOnCancelListener(new OnCancelListener() {

				@Override
				public void onCancel(DialogInterface dialog) {
					finish();
				}
			});
			alert.show();
			return;
		}

		createUI(savedInstanceState);

		//  hide the proof button if this file can't be proofed
		if (!core.canProof()) {
			mProofButton.setVisibility(View.INVISIBLE);
		}

		if (isProofing()) {

			//  start the activity with a new array
			mSepEnabled = null;

			//  show the separations button
			mSepsButton.setVisibility(View.VISIBLE);

			//  hide some other buttons
			mLinkButton.setVisibility(View.INVISIBLE);
			mReflowButton.setVisibility(View.INVISIBLE);
			mOutlineButton.setVisibility(View.INVISIBLE);
			mSearchButton.setVisibility(View.INVISIBLE);
			mMoreButton.setVisibility(View.INVISIBLE);
		}
		else {
			//  hide the separations button
			mSepsButton.setVisibility(View.INVISIBLE);
		}

	}

	public void requestPassword(final Bundle savedInstanceState) {
		mPasswordView = new EditText(this);
		mPasswordView.setInputType(EditorInfo.TYPE_TEXT_VARIATION_PASSWORD);
		mPasswordView.setTransformationMethod(new PasswordTransformationMethod());

		AlertDialog alert = mAlertBuilder.create();
		alert.setTitle(R.string.enter_password);
		alert.setView(mPasswordView);
		alert.setButton(AlertDialog.BUTTON_POSITIVE, getString(R.string.okay),
				new DialogInterface.OnClickListener() {
					public void onClick(DialogInterface dialog, int which) {
						if (core.authenticatePassword(mPasswordView.getText().toString())) {
							createUI(savedInstanceState);
						} else {
							requestPassword(savedInstanceState);
						}
					}
				});
		alert.setButton(AlertDialog.BUTTON_NEGATIVE, getString(R.string.cancel),
				new DialogInterface.OnClickListener() {

			public void onClick(DialogInterface dialog, int which) {
				finish();
			}
		});
		alert.show();
	}

	public void createUI(Bundle savedInstanceState) {
		if (core == null)
			return;

		// Now create the UI.
		// First create the document view
		mDocView = new MuPDFReaderView(this) {
			@Override
			protected void onMoveToChild(int i) {
				if (core == null)
					return;

				mPageNumberView.setText(String.format("%d / %d", i + 1,
						core.countPages()));
				mPageSlider.setMax((core.countPages() - 1) * mPageSliderRes);
				mPageSlider.setProgress(i * mPageSliderRes);
				super.onMoveToChild(i);
			}

			@Override
			protected void onTapMainDocArea() {
				if (!mButtonsVisible) {
					showButtons();
				} else {
					if (mTopBarMode == TopBarMode.Main)
						hideButtons();
				}
			}

			@Override
			protected void onDocMotion() {
				hideButtons();
			}

			@Override
			protected void onHit(Hit item) {
				switch (mTopBarMode) {
				case Annot:
					if (item == Hit.Annotation) {
						showButtons();
						mTopBarMode = TopBarMode.Delete;
						mTopBarSwitcher.setDisplayedChild(mTopBarMode.ordinal());
					}
					break;
				case Delete:
					mTopBarMode = TopBarMode.Annot;
					mTopBarSwitcher.setDisplayedChild(mTopBarMode.ordinal());
				// fall through
				default:
					// Not in annotation editing mode, but the pageview will
					// still select and highlight hit annotations, so
					// deselect just in case.
					MuPDFView pageView = (MuPDFView) mDocView.getDisplayedView();
					if (pageView != null)
						pageView.deselectAnnotation();
					break;
				}
			}
		};
		mDocView.setAdapter(new MuPDFPageAdapter(this, this, core));

		mSearchTask = new SearchTask(this, core) {
			@Override
			protected void onTextFound(SearchTaskResult result) {
				SearchTaskResult.set(result);
				// Ask the ReaderView to move to the resulting page
				mDocView.setDisplayedViewIndex(result.pageNumber);
				// Make the ReaderView act on the change to SearchTaskResult
				// via overridden onChildSetup method.
				mDocView.resetupChildren();
			}
		};

		// Make the buttons overlay, and store all its
		// controls in variables
		makeButtonsView();

		// Set up the page slider
		int smax = Math.max(core.countPages()-1,1);
		mPageSliderRes = ((10 + smax - 1)/smax) * 2;

		// Set the file-name text
		mFilenameView.setText(mFileName);

		// Activate the seekbar
		mPageSlider.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
			public void onStopTrackingTouch(SeekBar seekBar) {
				mDocView.setDisplayedViewIndex((seekBar.getProgress()+mPageSliderRes/2)/mPageSliderRes);
			}

			public void onStartTrackingTouch(SeekBar seekBar) {}

			public void onProgressChanged(SeekBar seekBar, int progress,
					boolean fromUser) {
				updatePageNumView((progress+mPageSliderRes/2)/mPageSliderRes);
			}
		});

		// Activate the search-preparing button
		mSearchButton.setOnClickListener(new View.OnClickListener() {
			public void onClick(View v) {
				searchModeOn();
			}
		});

		// Activate the reflow button
		mReflowButton.setOnClickListener(new View.OnClickListener() {
			public void onClick(View v) {
				toggleReflow();
			}
		});

		if (core.fileFormat().startsWith("PDF") && core.isUnencryptedPDF() && !core.wasOpenedFromBuffer())
		{
			mAnnotButton.setOnClickListener(new View.OnClickListener() {
				public void onClick(View v) {
					mTopBarMode = TopBarMode.Annot;
					mTopBarSwitcher.setDisplayedChild(mTopBarMode.ordinal());
				}
			});
		}
		else
		{
			mAnnotButton.setVisibility(View.GONE);
		}

		// Search invoking buttons are disabled while there is no text specified
		mSearchBack.setEnabled(false);
		mSearchFwd.setEnabled(false);
		mSearchBack.setColorFilter(Color.argb(255, 128, 128, 128));
		mSearchFwd.setColorFilter(Color.argb(255, 128, 128, 128));

		// React to interaction with the text widget
		mSearchText.addTextChangedListener(new TextWatcher() {

			public void afterTextChanged(Editable s) {
				boolean haveText = s.toString().length() > 0;
				setButtonEnabled(mSearchBack, haveText);
				setButtonEnabled(mSearchFwd, haveText);

				// Remove any previous search results
				if (SearchTaskResult.get() != null && !mSearchText.getText().toString().equals(SearchTaskResult.get().txt)) {
					SearchTaskResult.set(null);
					mDocView.resetupChildren();
				}
			}
			public void beforeTextChanged(CharSequence s, int start, int count,
					int after) {}
			public void onTextChanged(CharSequence s, int start, int before,
					int count) {}
		});

		//React to Done button on keyboard
		mSearchText.setOnEditorActionListener(new TextView.OnEditorActionListener() {
			public boolean onEditorAction(TextView v, int actionId, KeyEvent event) {
				if (actionId == EditorInfo.IME_ACTION_DONE)
					search(1);
				return false;
			}
		});

		mSearchText.setOnKeyListener(new View.OnKeyListener() {
			public boolean onKey(View v, int keyCode, KeyEvent event) {
				if (event.getAction() == KeyEvent.ACTION_DOWN && keyCode == KeyEvent.KEYCODE_ENTER)
					search(1);
				return false;
			}
		});

		// Activate search invoking buttons
		mSearchBack.setOnClickListener(new View.OnClickListener() {
			public void onClick(View v) {
				search(-1);
			}
		});
		mSearchFwd.setOnClickListener(new View.OnClickListener() {
			public void onClick(View v) {
				search(1);
			}
		});

		mLinkButton.setOnClickListener(new View.OnClickListener() {
			public void onClick(View v) {
				setLinkHighlight(!mLinkHighlight);
			}
		});

		if (core.hasOutline()) {
			mOutlineButton.setOnClickListener(new View.OnClickListener() {
				public void onClick(View v) {
					OutlineItem outline[] = core.getOutline();
					if (outline != null) {
						OutlineActivityData.get().items = outline;
						Intent intent = new Intent(MuPDFActivity.this, OutlineActivity.class);
						startActivityForResult(intent, OUTLINE_REQUEST);
					}
				}
			});
		} else {
			mOutlineButton.setVisibility(View.GONE);
		}

		// Reenstate last state if it was recorded
		SharedPreferences prefs = getPreferences(Context.MODE_PRIVATE);
		mDocView.setDisplayedViewIndex(prefs.getInt("page"+mFileName, 0));

		if (savedInstanceState == null || !savedInstanceState.getBoolean("ButtonsHidden", false))
			showButtons();

		if(savedInstanceState != null && savedInstanceState.getBoolean("SearchMode", false))
			searchModeOn();

		if(savedInstanceState != null && savedInstanceState.getBoolean("ReflowMode", false))
			reflowModeSet(true);

		// Stick the document view and the buttons overlay into a parent view
		RelativeLayout layout = new RelativeLayout(this);
		layout.addView(mDocView);
		layout.addView(mButtonsView);
		setContentView(layout);

		if (isProofing()) {
			//  go to the current page
			int currentPage = getIntent().getIntExtra("startingPage", 0);
			mDocView.setDisplayedViewIndex(currentPage);
		}

	}

	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data) {
		switch (requestCode) {
		case OUTLINE_REQUEST:
			if (resultCode >= 0)
				mDocView.setDisplayedViewIndex(resultCode);
			break;
		case PRINT_REQUEST:
			if (resultCode == RESULT_CANCELED)
				showInfo(getString(R.string.print_failed));
			break;
		case FILEPICK_REQUEST:
			if (mFilePicker != null && resultCode == RESULT_OK)
				mFilePicker.onPick(data.getData());
		case PROOF_REQUEST:
			//  we're returning from a proofing activity

			if (mProofFile != null)
			{
				core.endProof(mProofFile);
				mProofFile = null;
			}

			//  return the top bar to default
			mTopBarMode = TopBarMode.Main;
			mTopBarSwitcher.setDisplayedChild(mTopBarMode.ordinal());
		}

		super.onActivityResult(requestCode, resultCode, data);
	}

	public Object onRetainNonConfigurationInstance()
	{
		MuPDFCore mycore = core;
		core = null;
		return mycore;
	}

	private void reflowModeSet(boolean reflow)
	{
		mReflow = reflow;
		mDocView.setAdapter(mReflow ? new MuPDFReflowAdapter(this, core) : new MuPDFPageAdapter(this, this, core));
		mReflowButton.setColorFilter(mReflow ? Color.argb(0xFF, 172, 114, 37) : Color.argb(0xFF, 255, 255, 255));
		setButtonEnabled(mAnnotButton, !reflow);
		setButtonEnabled(mSearchButton, !reflow);
		if (reflow) setLinkHighlight(false);
		setButtonEnabled(mLinkButton, !reflow);
		setButtonEnabled(mMoreButton, !reflow);
		mDocView.refresh(mReflow);
	}

	private void toggleReflow() {
		reflowModeSet(!mReflow);
		showInfo(mReflow ? getString(R.string.entering_reflow_mode) : getString(R.string.leaving_reflow_mode));
	}

	@Override
	protected void onSaveInstanceState(Bundle outState) {
		super.onSaveInstanceState(outState);

		if (mFileName != null && mDocView != null) {
			outState.putString("FileName", mFileName);

			// Store current page in the prefs against the file name,
			// so that we can pick it up each time the file is loaded
			// Other info is needed only for screen-orientation change,
			// so it can go in the bundle
			SharedPreferences prefs = getPreferences(Context.MODE_PRIVATE);
			SharedPreferences.Editor edit = prefs.edit();
			edit.putInt("page"+mFileName, mDocView.getDisplayedViewIndex());
			edit.commit();
		}

		if (!mButtonsVisible)
			outState.putBoolean("ButtonsHidden", true);

		if (mTopBarMode == TopBarMode.Search)
			outState.putBoolean("SearchMode", true);

		if (mReflow)
			outState.putBoolean("ReflowMode", true);
	}

	@Override
	protected void onPause() {
		super.onPause();

		if (mSearchTask != null)
			mSearchTask.stop();

		if (mFileName != null && mDocView != null) {
			SharedPreferences prefs = getPreferences(Context.MODE_PRIVATE);
			SharedPreferences.Editor edit = prefs.edit();
			edit.putInt("page"+mFileName, mDocView.getDisplayedViewIndex());
			edit.commit();
		}
	}

	public void onDestroy()
	{
		if (mDocView != null) {
			mDocView.applyToChildren(new ReaderView.ViewMapper() {
				void applyToView(View view) {
					((MuPDFView)view).releaseBitmaps();
				}
			});
		}
		if (core != null)
			core.onDestroy();
		if (mAlertTask != null) {
			mAlertTask.cancel(true);
			mAlertTask = null;
		}
		core = null;
		super.onDestroy();
	}

	private void setButtonEnabled(ImageButton button, boolean enabled) {
		button.setEnabled(enabled);
		button.setColorFilter(enabled ? Color.argb(255, 255, 255, 255) : Color.argb(255, 128, 128, 128));
	}

	private void setLinkHighlight(boolean highlight) {
		mLinkHighlight = highlight;
		// LINK_COLOR tint
		mLinkButton.setColorFilter(highlight ? Color.argb(0xFF, 172, 114, 37) : Color.argb(0xFF, 255, 255, 255));
		// Inform pages of the change.
		mDocView.setLinksEnabled(highlight);
	}

	private void showButtons() {
		if (core == null)
			return;
		if (!mButtonsVisible) {
			mButtonsVisible = true;
			// Update page number text and slider
			int index = mDocView.getDisplayedViewIndex();
			updatePageNumView(index);
			mPageSlider.setMax((core.countPages()-1)*mPageSliderRes);
			mPageSlider.setProgress(index * mPageSliderRes);
			if (mTopBarMode == TopBarMode.Search) {
				mSearchText.requestFocus();
				showKeyboard();
			}

			Animation anim = new TranslateAnimation(0, 0, -mTopBarSwitcher.getHeight(), 0);
			anim.setDuration(200);
			anim.setAnimationListener(new Animation.AnimationListener() {
				public void onAnimationStart(Animation animation) {
					mTopBarSwitcher.setVisibility(View.VISIBLE);
				}
				public void onAnimationRepeat(Animation animation) {}
				public void onAnimationEnd(Animation animation) {}
			});
			mTopBarSwitcher.startAnimation(anim);

			anim = new TranslateAnimation(0, 0, mPageSlider.getHeight(), 0);
			anim.setDuration(200);
			anim.setAnimationListener(new Animation.AnimationListener() {
				public void onAnimationStart(Animation animation) {
					mPageSlider.setVisibility(View.VISIBLE);
				}
				public void onAnimationRepeat(Animation animation) {}
				public void onAnimationEnd(Animation animation) {
					mPageNumberView.setVisibility(View.VISIBLE);
				}
			});
			mPageSlider.startAnimation(anim);
		}
	}

	private void hideButtons() {
		if (mButtonsVisible) {
			mButtonsVisible = false;
			hideKeyboard();

			Animation anim = new TranslateAnimation(0, 0, 0, -mTopBarSwitcher.getHeight());
			anim.setDuration(200);
			anim.setAnimationListener(new Animation.AnimationListener() {
				public void onAnimationStart(Animation animation) {}
				public void onAnimationRepeat(Animation animation) {}
				public void onAnimationEnd(Animation animation) {
					mTopBarSwitcher.setVisibility(View.INVISIBLE);
				}
			});
			mTopBarSwitcher.startAnimation(anim);

			anim = new TranslateAnimation(0, 0, 0, mPageSlider.getHeight());
			anim.setDuration(200);
			anim.setAnimationListener(new Animation.AnimationListener() {
				public void onAnimationStart(Animation animation) {
					mPageNumberView.setVisibility(View.INVISIBLE);
				}
				public void onAnimationRepeat(Animation animation) {}
				public void onAnimationEnd(Animation animation) {
					mPageSlider.setVisibility(View.INVISIBLE);
				}
			});
			mPageSlider.startAnimation(anim);
		}
	}

	private void searchModeOn() {
		if (mTopBarMode != TopBarMode.Search) {
			mTopBarMode = TopBarMode.Search;
			//Focus on EditTextWidget
			mSearchText.requestFocus();
			showKeyboard();
			mTopBarSwitcher.setDisplayedChild(mTopBarMode.ordinal());
		}
	}

	private void searchModeOff() {
		if (mTopBarMode == TopBarMode.Search) {
			mTopBarMode = TopBarMode.Main;
			hideKeyboard();
			mTopBarSwitcher.setDisplayedChild(mTopBarMode.ordinal());
			SearchTaskResult.set(null);
			// Make the ReaderView act on the change to mSearchTaskResult
			// via overridden onChildSetup method.
			mDocView.resetupChildren();
		}
	}

	private void updatePageNumView(int index) {
		if (core == null)
			return;
		mPageNumberView.setText(String.format("%d / %d", index + 1, core.countPages()));
	}

	private void printDoc() {
		if (!core.fileFormat().startsWith("PDF")) {
			showInfo(getString(R.string.format_currently_not_supported));
			return;
		}

		Intent myIntent = getIntent();
		Uri docUri = myIntent != null ? myIntent.getData() : null;

		if (docUri == null) {
			showInfo(getString(R.string.print_failed));
		}

		if (docUri.getScheme() == null)
			docUri = Uri.parse("file://"+docUri.toString());

		Intent printIntent = new Intent(this, PrintDialogActivity.class);
		printIntent.setDataAndType(docUri, "aplication/pdf");
		printIntent.putExtra("title", mFileName);
		startActivityForResult(printIntent, PRINT_REQUEST);
	}

	private void showInfo(String message) {
		mInfoView.setText(message);

		int currentApiVersion = android.os.Build.VERSION.SDK_INT;
		if (currentApiVersion >= android.os.Build.VERSION_CODES.HONEYCOMB) {
			SafeAnimatorInflater safe = new SafeAnimatorInflater((Activity)this, R.animator.info, (View)mInfoView);
		} else {
			mInfoView.setVisibility(View.VISIBLE);
			mHandler.postDelayed(new Runnable() {
				public void run() {
					mInfoView.setVisibility(View.INVISIBLE);
				}
			}, 500);
		}
	}

	private void makeButtonsView() {
		mButtonsView = getLayoutInflater().inflate(R.layout.buttons,null);
		mFilenameView = (TextView)mButtonsView.findViewById(R.id.docNameText);
		mPageSlider = (SeekBar)mButtonsView.findViewById(R.id.pageSlider);
		mPageNumberView = (TextView)mButtonsView.findViewById(R.id.pageNumber);
		mInfoView = (TextView)mButtonsView.findViewById(R.id.info);
		mSearchButton = (ImageButton)mButtonsView.findViewById(R.id.searchButton);
		mReflowButton = (ImageButton)mButtonsView.findViewById(R.id.reflowButton);
		mOutlineButton = (ImageButton)mButtonsView.findViewById(R.id.outlineButton);
		mAnnotButton = (ImageButton)mButtonsView.findViewById(R.id.editAnnotButton);
		mAnnotTypeText = (TextView)mButtonsView.findViewById(R.id.annotType);
		mTopBarSwitcher = (ViewAnimator)mButtonsView.findViewById(R.id.switcher);
		mSearchBack = (ImageButton)mButtonsView.findViewById(R.id.searchBack);
		mSearchFwd = (ImageButton)mButtonsView.findViewById(R.id.searchForward);
		mSearchText = (EditText)mButtonsView.findViewById(R.id.searchText);
		mLinkButton = (ImageButton)mButtonsView.findViewById(R.id.linkButton);
		mMoreButton = (ImageButton)mButtonsView.findViewById(R.id.moreButton);
		mProofButton = (ImageButton)mButtonsView.findViewById(R.id.proofButton);
		mSepsButton = (ImageButton)mButtonsView.findViewById(R.id.sepsButton);
		mTopBarSwitcher.setVisibility(View.INVISIBLE);
		mPageNumberView.setVisibility(View.INVISIBLE);
		mInfoView.setVisibility(View.INVISIBLE);

		mPageSlider.setVisibility(View.INVISIBLE);
		if (!core.gprfSupported()) {
			mProofButton.setVisibility(View.INVISIBLE);
		}
		mSepsButton.setVisibility(View.INVISIBLE);
	}

	public void OnMoreButtonClick(View v) {
		mTopBarMode = TopBarMode.More;
		mTopBarSwitcher.setDisplayedChild(mTopBarMode.ordinal());
	}

	public void OnCancelMoreButtonClick(View v) {
		mTopBarMode = TopBarMode.Main;
		mTopBarSwitcher.setDisplayedChild(mTopBarMode.ordinal());
	}

	public void OnPrintButtonClick(View v) {
		printDoc();
	}

	//  start a proof activity with the given resolution.
	public void proofWithResolution (int resolution)
	{
		mProofFile = core.startProof(resolution);
		Uri uri = Uri.parse("file://"+mProofFile);
		Intent intent = new Intent(this, MuPDFActivity.class);
		intent.setAction(Intent.ACTION_VIEW);
		intent.setData(uri);
		// add the current page so it can be found when the activity is running
		intent.putExtra("startingPage", mDocView.getDisplayedViewIndex());
		startActivityForResult(intent, PROOF_REQUEST);
	}

	public void OnProofButtonClick(final View v)
	{
		//  set up the menu or resolutions.
		final PopupMenu popup = new PopupMenu(this, v);
		popup.getMenu().add(0, 1,    0, "Select a resolution:");
		popup.getMenu().add(0, 72,   0, "72");
		popup.getMenu().add(0, 96,   0, "96");
		popup.getMenu().add(0, 150,  0, "150");
		popup.getMenu().add(0, 300,  0, "300");
		popup.getMenu().add(0, 600,  0, "600");
		popup.getMenu().add(0, 1200, 0, "1200");
		popup.getMenu().add(0, 2400, 0, "2400");

		//  prevent the first item from being dismissed.
		//  is there not a better way to do this?  It requires minimum API 14
		MenuItem item = popup.getMenu().getItem(0);
		item.setShowAsAction(MenuItem.SHOW_AS_ACTION_COLLAPSE_ACTION_VIEW);
		item.setActionView(new View(v.getContext()));
		item.setOnActionExpandListener(new MenuItem.OnActionExpandListener() {
			@Override
			public boolean onMenuItemActionExpand(MenuItem item) {
				return false;
			}

			@Override
			public boolean onMenuItemActionCollapse(MenuItem item) {
				return false;
			}
		});

		popup.setOnMenuItemClickListener(new PopupMenu.OnMenuItemClickListener() {
			@Override
			public boolean onMenuItemClick(MenuItem item) {
				int id = item.getItemId();
				if (id != 1) {
					//  it's a resolution.  The id is also the resolution value
					proofWithResolution(id);
					return true;
				}
				return false;
			}
		});

		popup.show();
	}

	public void OnSepsButtonClick(final View v)
	{
		if (isProofing()) {

			//  get the current page
			final int currentPage = mDocView.getDisplayedViewIndex();

			//  buid a popup menu based on the given separations
			final PopupMenu menu = new PopupMenu(this, v);

			//  This makes the popup menu display icons, which by default it does not do.
			//  I worry that this relies on the internals of PopupMenu, which could change.
			try {
				Field[] fields = menu.getClass().getDeclaredFields();
				for (Field field : fields) {
					if ("mPopup".equals(field.getName())) {
						field.setAccessible(true);
						Object menuPopupHelper = field.get(menu);
						Class<?> classPopupHelper = Class.forName(menuPopupHelper
								.getClass().getName());
						Method setForceIcons = classPopupHelper.getMethod(
								"setForceShowIcon", boolean.class);
						setForceIcons.invoke(menuPopupHelper, true);
						break;
					}
				}
			} catch (Exception e) {
				e.printStackTrace();
			}

			//  get the maximum number of seps on any page.
			//  We use this to dimension an array further down
			int maxSeps = 0;
			int numPages = core.countPages();
			for (int page=0; page<numPages; page++) {
				int numSeps = core.getNumSepsOnPage(page);
				if (numSeps>maxSeps)
					maxSeps = numSeps;
			}

			//  if this is the first time, create the "enabled" array
			if (mSepEnabled==null) {
				mSepEnabled = new boolean[numPages][maxSeps];
				for (int page=0; page<numPages; page++) {
					for (int i = 0; i < maxSeps; i++)
						mSepEnabled[page][i] = true;
				}
			}

			//  count the seps on this page
			int numSeps = core.getNumSepsOnPage(currentPage);

			//  for each sep,
			for (int i = 0; i < numSeps; i++) {

//				//  Robin use this to skip separations
//				if (i==12)
//					break;

				//  get the name
				Separation sep = core.getSep(currentPage,i);
				String name = sep.name;

				//  make a checkable menu item with that name
				//  and the separation index as the id
				MenuItem item = menu.getMenu().add(0, i, 0, name+"    ");
				item.setCheckable(true);

				//  set an icon that's the right color
				int iconSize = 48;
				int alpha = (sep.rgba >> 24) & 0xFF;
				int red   = (sep.rgba >> 16) & 0xFF;
				int green = (sep.rgba >> 8 ) & 0xFF;
				int blue  = (sep.rgba >> 0 ) & 0xFF;
				int color = (alpha << 24) | (red << 16) | (green << 8) | (blue << 0);

				ShapeDrawable swatch = new ShapeDrawable (new RectShape());
				swatch.setIntrinsicHeight(iconSize);
				swatch.setIntrinsicWidth(iconSize);
				swatch.setBounds(new Rect(0, 0, iconSize, iconSize));
				swatch.getPaint().setColor(color);
				item.setShowAsAction(MenuItem.SHOW_AS_ACTION_ALWAYS);
				item.setIcon(swatch);

				//  check it (or not)
				item.setChecked(mSepEnabled[currentPage][i]);

				//  establishing a menu item listener
				item.setOnMenuItemClickListener(new OnMenuItemClickListener() {
					@Override
					public boolean onMenuItemClick(MenuItem item) {
						//  someone tapped a menu item.  get the ID
						int sep = item.getItemId();

						//  toggle the sep
						mSepEnabled[currentPage][sep] = !mSepEnabled[currentPage][sep];
						item.setChecked(mSepEnabled[currentPage][sep]);
						core.controlSepOnPage(currentPage, sep, !mSepEnabled[currentPage][sep]);

						//  prevent the menu from being dismissed by these items
						item.setShowAsAction(MenuItem.SHOW_AS_ACTION_COLLAPSE_ACTION_VIEW);
						item.setActionView(new View(v.getContext()));
						item.setOnActionExpandListener(new MenuItem.OnActionExpandListener() {
							@Override
							public boolean onMenuItemActionExpand(MenuItem item) {
								return false;
							}

							@Override
							public boolean onMenuItemActionCollapse(MenuItem item) {
								return false;
							}
						});
						return false;
					}
				});

				//  tell core to enable or disable each sep as appropriate
				//  but don't refresh the page yet.
				core.controlSepOnPage(currentPage, i, !mSepEnabled[currentPage][i]);
			}

			//  add one for done
			MenuItem itemDone = menu.getMenu().add(0, 0, 0, "Done");
			itemDone.setOnMenuItemClickListener(new OnMenuItemClickListener() {
				@Override
				public boolean onMenuItemClick(MenuItem item) {
					//  refresh the view
					mDocView.refresh(false);
					return true;
				}
			});

			//  show the menu
			menu.show();
		}

	}

	public void OnCopyTextButtonClick(View v) {
		mTopBarMode = TopBarMode.Accept;
		mTopBarSwitcher.setDisplayedChild(mTopBarMode.ordinal());
		mAcceptMode = AcceptMode.CopyText;
		mDocView.setMode(MuPDFReaderView.Mode.Selecting);
		mAnnotTypeText.setText(getString(R.string.copy_text));
		showInfo(getString(R.string.select_text));
	}

	public void OnEditAnnotButtonClick(View v) {
		mTopBarMode = TopBarMode.Annot;
		mTopBarSwitcher.setDisplayedChild(mTopBarMode.ordinal());
	}

	public void OnCancelAnnotButtonClick(View v) {
		mTopBarMode = TopBarMode.More;
		mTopBarSwitcher.setDisplayedChild(mTopBarMode.ordinal());
	}

	public void OnHighlightButtonClick(View v) {
		mTopBarMode = TopBarMode.Accept;
		mTopBarSwitcher.setDisplayedChild(mTopBarMode.ordinal());
		mAcceptMode = AcceptMode.Highlight;
		mDocView.setMode(MuPDFReaderView.Mode.Selecting);
		mAnnotTypeText.setText(R.string.highlight);
		showInfo(getString(R.string.select_text));
	}

	public void OnUnderlineButtonClick(View v) {
		mTopBarMode = TopBarMode.Accept;
		mTopBarSwitcher.setDisplayedChild(mTopBarMode.ordinal());
		mAcceptMode = AcceptMode.Underline;
		mDocView.setMode(MuPDFReaderView.Mode.Selecting);
		mAnnotTypeText.setText(R.string.underline);
		showInfo(getString(R.string.select_text));
	}

	public void OnStrikeOutButtonClick(View v) {
		mTopBarMode = TopBarMode.Accept;
		mTopBarSwitcher.setDisplayedChild(mTopBarMode.ordinal());
		mAcceptMode = AcceptMode.StrikeOut;
		mDocView.setMode(MuPDFReaderView.Mode.Selecting);
		mAnnotTypeText.setText(R.string.strike_out);
		showInfo(getString(R.string.select_text));
	}

	public void OnInkButtonClick(View v) {
		mTopBarMode = TopBarMode.Accept;
		mTopBarSwitcher.setDisplayedChild(mTopBarMode.ordinal());
		mAcceptMode = AcceptMode.Ink;
		mDocView.setMode(MuPDFReaderView.Mode.Drawing);
		mAnnotTypeText.setText(R.string.ink);
		showInfo(getString(R.string.draw_annotation));
	}

	public void OnCancelAcceptButtonClick(View v) {
		MuPDFView pageView = (MuPDFView) mDocView.getDisplayedView();
		if (pageView != null) {
			pageView.deselectText();
			pageView.cancelDraw();
		}
		mDocView.setMode(MuPDFReaderView.Mode.Viewing);
		switch (mAcceptMode) {
		case CopyText:
			mTopBarMode = TopBarMode.More;
			break;
		default:
			mTopBarMode = TopBarMode.Annot;
			break;
		}
		mTopBarSwitcher.setDisplayedChild(mTopBarMode.ordinal());
	}

	public void OnAcceptButtonClick(View v) {
		MuPDFView pageView = (MuPDFView) mDocView.getDisplayedView();
		boolean success = false;
		switch (mAcceptMode) {
		case CopyText:
			if (pageView != null)
				success = pageView.copySelection();
			mTopBarMode = TopBarMode.More;
			showInfo(success?getString(R.string.copied_to_clipboard):getString(R.string.no_text_selected));
			break;

		case Highlight:
			if (pageView != null)
				success = pageView.markupSelection(Annotation.Type.HIGHLIGHT);
			mTopBarMode = TopBarMode.Annot;
			if (!success)
				showInfo(getString(R.string.no_text_selected));
			break;

		case Underline:
			if (pageView != null)
				success = pageView.markupSelection(Annotation.Type.UNDERLINE);
			mTopBarMode = TopBarMode.Annot;
			if (!success)
				showInfo(getString(R.string.no_text_selected));
			break;

		case StrikeOut:
			if (pageView != null)
				success = pageView.markupSelection(Annotation.Type.STRIKEOUT);
			mTopBarMode = TopBarMode.Annot;
			if (!success)
				showInfo(getString(R.string.no_text_selected));
			break;

		case Ink:
			if (pageView != null)
				success = pageView.saveDraw();
			mTopBarMode = TopBarMode.Annot;
			if (!success)
				showInfo(getString(R.string.nothing_to_save));
			break;
		}
		mTopBarSwitcher.setDisplayedChild(mTopBarMode.ordinal());
		mDocView.setMode(MuPDFReaderView.Mode.Viewing);
	}

	public void OnCancelSearchButtonClick(View v) {
		searchModeOff();
	}

	public void OnDeleteButtonClick(View v) {
		MuPDFView pageView = (MuPDFView) mDocView.getDisplayedView();
		if (pageView != null)
			pageView.deleteSelectedAnnotation();
		mTopBarMode = TopBarMode.Annot;
		mTopBarSwitcher.setDisplayedChild(mTopBarMode.ordinal());
	}

	public void OnCancelDeleteButtonClick(View v) {
		MuPDFView pageView = (MuPDFView) mDocView.getDisplayedView();
		if (pageView != null)
			pageView.deselectAnnotation();
		mTopBarMode = TopBarMode.Annot;
		mTopBarSwitcher.setDisplayedChild(mTopBarMode.ordinal());
	}

	private void showKeyboard() {
		InputMethodManager imm = (InputMethodManager)getSystemService(Context.INPUT_METHOD_SERVICE);
		if (imm != null)
			imm.showSoftInput(mSearchText, 0);
	}

	private void hideKeyboard() {
		InputMethodManager imm = (InputMethodManager)getSystemService(Context.INPUT_METHOD_SERVICE);
		if (imm != null)
			imm.hideSoftInputFromWindow(mSearchText.getWindowToken(), 0);
	}

	private void search(int direction) {
		hideKeyboard();
		int displayPage = mDocView.getDisplayedViewIndex();
		SearchTaskResult r = SearchTaskResult.get();
		int searchPage = r != null ? r.pageNumber : -1;
		mSearchTask.go(mSearchText.getText().toString(), direction, displayPage, searchPage);
	}

	@Override
	public boolean onSearchRequested() {
		if (mButtonsVisible && mTopBarMode == TopBarMode.Search) {
			hideButtons();
		} else {
			showButtons();
			searchModeOn();
		}
		return super.onSearchRequested();
	}

	@Override
	public boolean onPrepareOptionsMenu(Menu menu) {
		if (mButtonsVisible && mTopBarMode != TopBarMode.Search) {
			hideButtons();
		} else {
			showButtons();
			searchModeOff();
		}
		return super.onPrepareOptionsMenu(menu);
	}

	@Override
	protected void onStart() {
		if (core != null)
		{
			core.startAlerts();
			createAlertWaiter();
		}

		super.onStart();
	}

	@Override
	protected void onStop() {
		if (core != null)
		{
			destroyAlertWaiter();
			core.stopAlerts();
		}

		super.onStop();
	}

	@Override
	public void onBackPressed() {
		if (core != null && core.hasChanges()) {
			DialogInterface.OnClickListener listener = new DialogInterface.OnClickListener() {
				public void onClick(DialogInterface dialog, int which) {
					if (which == AlertDialog.BUTTON_POSITIVE)
						core.save();

					finish();
				}
			};
			AlertDialog alert = mAlertBuilder.create();
			alert.setTitle("MuPDF");
			alert.setMessage(getString(R.string.document_has_changes_save_them_));
			alert.setButton(AlertDialog.BUTTON_POSITIVE, getString(R.string.yes), listener);
			alert.setButton(AlertDialog.BUTTON_NEGATIVE, getString(R.string.no), listener);
			alert.show();
		} else {
			super.onBackPressed();
		}
	}

	@Override
	public void performPickFor(FilePicker picker) {
		mFilePicker = picker;
		Intent intent = new Intent(this, ChoosePDFActivity.class);
		intent.setAction(ChoosePDFActivity.PICK_KEY_FILE);
		startActivityForResult(intent, FILEPICK_REQUEST);
	}

}
