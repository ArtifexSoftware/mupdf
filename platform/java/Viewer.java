import com.artifex.mupdf.fitz.*;

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

public class Viewer extends Frame implements WindowListener, ActionListener
{
	protected Document doc;
	protected Panel toolbar;
	protected PageCanvas pageCanvas;
	protected Label pageLabel;
	protected Button firstButton, prevButton, nextButton, lastButton;
	protected int pageCount;
	protected int pageNumber;

	public Viewer(Document doc_) {
		super("MuPDF");

		this.doc = doc_;

		pageCount = doc.countPages();
		pageNumber = 0;

		setSize(600, 900);
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
		pageLabel = new Label();

		toolbar.add(firstButton);
		toolbar.add(prevButton);
		toolbar.add(nextButton);
		toolbar.add(lastButton);
		toolbar.add(pageLabel);

		add(toolbar, BorderLayout.NORTH);

		addWindowListener(this);

		stuff();
	}

	public void stuff() {
		pageLabel.setText("Page " + (pageNumber + 1) + " / " + pageCount);
		if (pageCanvas != null)
			remove(pageCanvas);
		pageCanvas = new PageCanvas(doc.loadPage(pageNumber));
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

	public static void main(String[] args) {
		Document doc = new Document("pdfref17.pdf");
		Viewer app = new Viewer(doc);
		app.setVisible(true);
	}
}
