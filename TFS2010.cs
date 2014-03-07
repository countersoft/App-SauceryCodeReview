using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Countersoft.Gemini.Commons.Entity;
using Countersoft.Gemini.Extensibility.Apps;
using Countersoft.Foundation.Commons.Extensions;
using Countersoft.Gemini.Commons;
using Microsoft.TeamFoundation.Client;
using Microsoft.TeamFoundation.VersionControl.Client;
using System.Net;
using Microsoft.TeamFoundation.Framework.Common;
using Microsoft.TeamFoundation.Framework.Client;
using System.Collections.ObjectModel;
using System.IO;
using Countersoft.Gemini.Contracts;
using Countersoft.Gemini.Commons.Dto;
using Countersoft.Gemini.Commons.System;
using Countersoft.Gemini;

namespace Saucery
{
    public class TFS2010
    {
        private string Username { get; set; }
        
        private string Password { get; set; }
        
        private string Uri { get; set; }

        public string GetFileContent(GeminiContext gemini, int issueid, string filename, string fullfilename, string workspace, string changesetid, string fileid, string repositoryUrl, bool getPreviousRevision = false)
        {
            ConnectByImplementingCredentialsProvider connect = new ConnectByImplementingCredentialsProvider();
            
            ICredentials iCred = new NetworkCredential(Username, Password);
            
            connect.setLoginDetails(Username, Password, workspace);
            
            connect.GetCredentials(new Uri(Uri), iCred);

            TfsConfigurationServer configurationServer = TfsConfigurationServerFactory.GetConfigurationServer(new Uri(Uri));
            
            configurationServer.Credentials = iCred;
            
            configurationServer.ClientCredentials = new TfsClientCredentials(new WindowsCredential(iCred));
            
            configurationServer.EnsureAuthenticated();

            CatalogNode catalogNode = configurationServer.CatalogNode;

            ReadOnlyCollection<CatalogNode> tpcNodes = catalogNode.QueryChildren(new Guid[] { CatalogResourceTypes.ProjectCollection },false, CatalogQueryOptions.None);

            // tpc = Team Project Collection
            foreach (CatalogNode tpcNode in tpcNodes)
            {
                Guid tpcId = new Guid(tpcNode.Resource.Properties["InstanceId"]);
                
                TfsTeamProjectCollection tpc = configurationServer.GetTeamProjectCollection(tpcId);

                VersionControlServer versionControl = (VersionControlServer)tpc.GetService(typeof(VersionControlServer));

                Item file = null;
                
                try
                {
                    //IF file was just added in tfs
                    if (fileid.ToInt() == 0)
                    {
                        Item tmpFile = null;
                        //Need to catch error if file was deleted, we'll get an error and call the file with parameters as below.
                        //This would only happen to newly added file, which will not have a itemid as we wouldn't know what it is on first commit of a file
                        try
                        {
                            tmpFile = versionControl.GetItem(string.Concat(fullfilename, "/", filename));

                        }
                        catch (VersionControlException ex)
                        {
                            tmpFile = versionControl.GetItem(fullfilename + "/" + filename, VersionSpec.Latest, DeletedState.Deleted);
                        }

                        if (tmpFile != null)
                        {
                            fileid = tmpFile.ItemId.ToString();
                        }
                    }

                    if (fileid.ToInt() > 0)
                    {
                        if (getPreviousRevision)
                        {
                            if (changesetid.ToInt() > 1)
                            {
                                file = versionControl.GetItem(fileid.ToInt(), changesetid.ToInt() - 1, true);
                            }
                        }
                        else
                        {
                            file = versionControl.GetItem(fileid.ToInt(), changesetid.ToInt());
                        }

                        if (file != null)
                        {
                            if (file.DeletionId > 0)
                            {
                                return string.Empty;
                            }
                            else
                            {

                                using (Stream stream = file.DownloadFile())
                                {
                                    StreamReader rdr = new StreamReader(stream);
                                    return rdr.ReadToEnd();
                                }
                            }
                        }
                    }
                }
                catch (VersionControlException ex)
                {
                    GeminiApp.LogException(ex, false);
                    
                    return string.Empty;
                }
                catch (Exception ex)
                {
                    GeminiApp.LogException(ex, false);
                    
                    return string.Empty;
                }
            }

            return string.Empty;
        }

        public class ConnectByImplementingCredentialsProvider : ICredentialsProvider
        {
            private string Username { get; set; }
            
            private string Password { get; set; }
            
            private string Workspace { get; set; }

            public ICredentials GetCredentials(Uri uri, ICredentials iCredentials)
            {
                return new NetworkCredential(Username, Password, Workspace);
            }

            public void NotifyCredentialsAuthenticated(Uri uri)
            {
                throw new ApplicationException("Unable to authenticate");
            }

            public void setLoginDetails(string authUsername, string authPassword, string authWorkspace)
            {
                Username = authUsername;
                
                Password = authPassword;
                
                Workspace = authWorkspace;
            }
        }

        public void SaveLoginDetails(UserDto user, UserWidgetDataDetails userData, GeminiContext gemini)
        {
            UserWidgetData<List<UserWidgetDataDetails>> userDataRaw = gemini.UserWidgetStore.Get<List<UserWidgetDataDetails>>(user.Entity.Id, Constants.AppId, Constants.ControlId);

            if (userDataRaw == null)
            {
                var data = new UserWidgetData<List<UserWidgetDataDetails>>();
                
                data.Value = new List<UserWidgetDataDetails>();

                data.Value.Add(userData);
                
                gemini.UserWidgetStore.Save(user.Entity.Id, Constants.AppId, Constants.ControlId, data.Value);
            }
            else
            {
                var tmpUser = userDataRaw.Value.Find(f => f.RepositoryUrl == userData.RepositoryUrl && f.Provider == userData.Provider);

                // If a password for this rep already exist, update the details only
                if (tmpUser != null)
                {
                    var index = userDataRaw.Value.FindIndex(f => f.RepositoryUrl == userData.RepositoryUrl && f.Provider == userData.Provider);

                    userDataRaw.Value[index].Password = userData.Password;
                    
                    userDataRaw.Value[index].Username = userData.Username;

                }
                else
                {
                    // Add a new user authentication for this user
                    userDataRaw.Value.Add(userData);
                }

                gemini.UserWidgetStore.Save(user.Entity.Id, Constants.AppId, Constants.ControlId, userDataRaw.Value);
            }
        }

        public string CreateAuthenticationForm(string url, string repositoryURL, string filename)
        {
            StringBuilder form = new StringBuilder();
            
            form.Append(string.Format("<div><a href='{0}'>{0}<a></div>", repositoryURL));
            
            form.Append(string.Format("<form id='authentication_form' action='apps/saucery/authenticate/{0}' method='post'>", SourceControlProvider.TFS2010));
            
            form.Append("<input type='text' name='username' placeholder='username' id='username'/>");
            
            form.Append("<input class='margin-bottom-5' type='password' name='password' placeholder='password' id='password'/><br />");
            
            form.Append("<input type='button' class='button-primary button-small' name='tfs_login' id='tfs_login' value='Login'/>");
            
            form.Append("<input type='button' class='button-secondary button-small margin-left-5 cancel' name='tfs_cancel' id='tfs_cancel' value='Cancel'/>");
            
            form.Append(string.Format("<input id='repositoryurl' type='hidden' name='repositoryurl' value='{0}'/>", repositoryURL));
            
            form.Append(string.Format("<input id='filename' type='hidden' name='filename' value='{0}'/>", filename));
            
            form.Append("</form>");
            
            return form.ToString();
        }

        public bool AuthenticateUser(UserDto user, string repositoryUrl, GeminiContext gemini)
        {
            UserWidgetData<List<UserWidgetDataDetails>> userDataRaw = gemini.UserWidgetStore.Get<List<UserWidgetDataDetails>>(user.Entity.Id, Constants.AppId, Constants.ControlId);

            if (userDataRaw == null) return false;

            var data = userDataRaw.Value.Find(f => f.RepositoryUrl == repositoryUrl && f.Provider == SourceControlProvider.TFS2010);

            if (data == null) return false;

            Username = data.Username;
            
            Password = SecretsHelper.Decrypt(data.Password, SecretsHelper.EncryptionKey); 
            
            Uri      = data.RepositoryUrl;

            return true;
        }

    }
}
