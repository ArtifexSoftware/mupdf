using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Windows.Navigation;
using Windows.Phone.Storage.SharedAccess;

namespace winphone
{
	class AutoLaunch : UriMapperBase
	{
        private string tempUri;

        public override Uri MapUri(Uri uri)
        {
            tempUri = uri.ToString();

            // File association launch
            if (tempUri.Contains("/FileTypeAssociation"))
            {
                // Get the file ID (after "fileToken=").
                int fileIDIndex = tempUri.IndexOf("fileToken=") + 10;
                string fileID = tempUri.Substring(fileIDIndex);

				// Redirect to the MainPage.xaml with fileID
				return new Uri("/MainPage.xaml?fileToken=" + fileID, UriKind.Relative);
			}
            // Otherwise perform normal launch.
            return uri;
        }
    }
}
