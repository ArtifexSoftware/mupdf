using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
//using System.Threading.Tasks;
using System.Drawing;

namespace gsview
{
	public enum link_t
	{
		LINK_GOTO = 0,
		LINK_URI,
		TEXTBOX,	/* Do double duty with this class */
		NOT_SET,
	};

	class Links
	{
		link_t type;
		Uri uri;
		int page_num;

		public Links()
		{
			uri = new Uri("");
			page_num = -1;
			type = link_t.NOT_SET;
		}
	}
}
