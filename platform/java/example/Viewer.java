package example;

import com.artifex.mupdf.fitz.*;

import java.io.File;

import java.awt.Frame;
import java.awt.Label;
import java.awt.Button;
import java.awt.Panel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.ActionListener;
import java.awt.event.WindowListener;
import java.awt.event.WindowEvent;
import java.awt.event.ActionEvent;
import java.awt.GraphicsEnvironment;
import java.awt.GraphicsDevice;
import java.awt.Toolkit;

import javax.swing.JFileChooser;
import javax.swing.filechooser.FileFilter;
import javax.swing.JOptionPane;
import java.lang.reflect.Field;

public class Viewer extends Frame implements WindowListener, ActionListener
{
	protected Document doc;
	protected Panel toolbar;
	protected PageCanvas pageCanvas;
	protected Label pageLabel;
	protected Button firstButton, prevButton, nextButton, lastButton, zoomInButton, zoomOutButton;
	protected int pageCount;
	protected int pageNumber;

	private float retinaScale;

	public Viewer(Document doc_) {
		super("MuPDF");

		retinaScale = getRetinaScale();
		
		this.doc = doc_;

		pageCount = doc.countPages();
		pageNumber = 0;

		setSize(1200, 900);
		setTitle("MuPDF: " + doc.getMetaData(Document.META_INFO_TITLE));

		toolbar = new Panel();
		toolbar.setLayout(new FlowLayout(FlowLayout.LEFT));
		firstButton = new Button("|<");
		firstButton.addActionListener(this);
		prevButton = new Button("<");
		prevButton.addActionListener(this);
		nextButton = new Button(">");
		nextButton.addActionListener(this);
		lastButton = new Button(">|");
		lastButton.addActionListener(this);
		zoomInButton = new Button("+");
		zoomInButton.addActionListener(this);
		zoomOutButton = new Button("-");
		zoomOutButton.addActionListener(this);
		pageLabel = new Label();

		toolbar.add(firstButton);
		toolbar.add(prevButton);
		toolbar.add(nextButton);
		toolbar.add(lastButton);
		toolbar.add(zoomInButton);
		toolbar.add(zoomOutButton);
		toolbar.add(pageLabel);

		add(toolbar, BorderLayout.NORTH);

		addWindowListener(this);

		stuff();
	}

	public void stuff() {
		pageLabel.setText("Page " + (pageNumber + 1) + " / " + pageCount);
		if (pageCanvas != null)
			remove(pageCanvas);
		pageCanvas = new PageCanvas(doc.loadPage(pageNumber), retinaScale);
		add(pageCanvas, BorderLayout.CENTER);
		validate();
	}

	public void actionPerformed(ActionEvent event) {
		Object source = event.getSource();
		int oldPageNumber = pageNumber;

		if (source == firstButton)
			pageNumber = 0;

		if (source == lastButton)
			pageNumber = pageCount - 1;

		if (source == prevButton) {
			pageNumber = pageNumber - 1;
			if (pageNumber < 0)
				pageNumber = 0;
		}

		if (source == nextButton) {
			pageNumber = pageNumber + 1;
			if (pageNumber >= pageCount)
				pageNumber = pageCount - 1;
		}

		if (source == zoomInButton) {
			pageCanvas.zoomIn();
		}

		if (source == zoomOutButton) {
			pageCanvas.zoomOut();
		}

		if (pageNumber != oldPageNumber)
			stuff();
	}

	public void windowClosing(WindowEvent event) {
		System.exit(0);
	}

	public void windowActivated(WindowEvent event) { }
	public void windowDeactivated(WindowEvent event) { }
	public void windowIconified(WindowEvent event) { }
	public void windowDeiconified(WindowEvent event) { }
	public void windowOpened(WindowEvent event) { }
	public void windowClosed(WindowEvent event) { }

	public static void main(String[] args)
	{
		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setDialogTitle("Choose a file to open");
		fileChooser.setFileFilter(new FileFilter()
		{
			public String getDescription()
			{
				return "Supported files (*.pdf, *,xps, *.jpg, *.jpeg, *.png, *.epub, *.cbz, *.cbr)";
			}

			public boolean accept(File f)
			{
				if (f.isDirectory())
					return true;

				String filename = f.getName().toLowerCase();
				if (filename.endsWith(".pdf"))
					return true;
				if (filename.endsWith(".xps"))
					return true;
				if (filename.endsWith(".jpg"))
					return true;
				if (filename.endsWith(".jpeg"))
					return true;
				if (filename.endsWith(".png"))
					return true;
				if (filename.endsWith(".epub"))
					return true;
				if (filename.endsWith(".cbz"))
					return true;
				if (filename.endsWith(".cbr"))
					return true;

				return false;
			}
		});

		while (true)
		{
			try
			{
				// get a file to open
				int result = fileChooser.showOpenDialog(null);
				if (result == JFileChooser.APPROVE_OPTION)
				{
					// user selects a file
					File selectedFile = fileChooser.getSelectedFile();
					if (selectedFile != null)
					{
						Document doc = new Document(selectedFile.getAbsolutePath());
						if (doc != null)
						{
							Viewer app = new Viewer(doc);
							if (app != null)
							{
								app.setVisible(true);
								return;
							}
							else
							{
								infoBox("Cannot create Viewer for "+selectedFile.getAbsolutePath(),"Error");
							}
						}
						else
						{
							infoBox("Cannot open "+selectedFile.getAbsolutePath(),"Error");
						}
					}
					else
					{
						infoBox("Selected file not found.","Error");
					}
				}
				else
				{
					infoBox("File selection cancelled.","Error");
					return;
				}

			}
			catch (Exception e)
			{
				infoBox("Exception: "+e.getMessage(),"Error");
			}
		}
	}

	private static void infoBox(String infoMessage, String titleBar)
	{
		JOptionPane.showMessageDialog(null, infoMessage, "InfoBox: " + titleBar, JOptionPane.INFORMATION_MESSAGE);
	}

	public float getRetinaScale()
	{
		//  first try Oracle's VM (we should also test for 1.7.0_40 or higher)
		final String vendor = System.getProperty("java.vm.vendor");
		boolean isOracle = vendor != null && vendor.toLowerCase().contains("Oracle".toLowerCase());
		if (isOracle)
		{
			GraphicsEnvironment env = GraphicsEnvironment.getLocalGraphicsEnvironment();
			final GraphicsDevice device = env.getDefaultScreenDevice();
			try {
				Field field = device.getClass().getDeclaredField("scale");
				if (field != null) {
					field.setAccessible(true);
					Object scale = field.get(device);
					if (scale instanceof Integer && ((Integer)scale).intValue() == 2) {
						return 2.0f;
					}
				}
			}
			catch (Exception ignore) {
			}
			return 1.0f;
		}

		//  try Apple VM
		final Float scaleFactor = (Float)Toolkit.getDefaultToolkit().getDesktopProperty("apple.awt.contentScaleFactor");
		if (scaleFactor != null && scaleFactor.intValue() == 2) {
			return 2.0f;
		}

		return 1.0f;
	}

}
