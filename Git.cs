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
using System.Diagnostics;
using RestSharp;
using Countersoft.Gemini;
using Countersoft.Gemini.Contracts;
using Countersoft.Gemini.Commons.Dto;
using Countersoft.Gemini.Commons.System;

namespace Saucery
{
    public class Git
    {
        private string Username { get; set; }
        
        private string Password { get; set; }

        public string GetFileContent(GeminiContext gemini,int issueid, string repositoryUrl, string filename, string revisionId, bool getPreviousRevision = false)
        {
            if (filename.IsEmpty()) return string.Empty;

           
            var allIssueCommits = gemini.CodeCommits.GetAll(issueid);
                
            if (allIssueCommits == null || allIssueCommits.Count() == 0) return string.Empty;

            var fileCommits = allIssueCommits.Where(f => f.Provider == SourceControlProvider.Git && f.Data.Contains(repositoryUrl) && f.Data.Contains(filename) && f.Data.Contains(string.Concat("\"RevisionId\":\"", revisionId, "\"")));

            if (fileCommits == null || fileCommits.Count() != 1) return string.Empty;

            var fileCommitsJson = fileCommits.First().Data.FromJson<SourceControlCommit>();
                
            var currentFile = fileCommitsJson.Files.Where(s => s.FullFilename == filename);

            

            if (getPreviousRevision)
            {
                if (currentFile.Count() > 0 && currentFile.First().PreviousFileRevisionId.Equals("deleted", StringComparison.InvariantCultureIgnoreCase)) return string.Empty;

                revisionId = fileCommitsJson.PreviousRevisionId;
            }
            else if (currentFile.Count() > 0 && currentFile.First().FileId.IsEmpty())
            {
                //If fileId is empty means the file was deleted
                return string.Empty;
            }

            if (revisionId.IsEmpty()) return string.Empty;
            

            RestSharp.IRestResponse response;

            try
            {
                response = GetResponse(string.Format("{0}/Raw/{1}/{2}?display=True", repositoryUrl, revisionId, Uri.EscapeDataString(filename)), RestSharp.Method.GET);
            }
            catch (FileNotFoundException ex)
            {
                GeminiApp.LogException(ex, false);
                
                return string.Empty;
            }
            catch (UnauthorizedAccessException)
            {
                throw;
            }
            catch (Exception ex)
            {
                GeminiApp.LogException(ex, false);
                
                return string.Empty;
            }

            return response.Content;
        }

        public IRestResponse GetResponse(string url, RestSharp.Method method)
        {          
            RestClient client = new RestClient(url);
 
            client.Authenticator = new HttpBasicAuthenticator(Username, Password);

            RestSharp.RestRequest request = new RestSharp.RestRequest(method);
            
            var response = client.Execute(request);

            if (DebugConstant.DebugModeState)
            {
                GeminiApp.LogException(new Exception(string.Format("Content: {0} FileUrl: {1}", response.Content, url)) { Source = SourceControlProvider.Git.ToString() }, false);
            }

            if (response.StatusCode == HttpStatusCode.OK) return response;

            if (response.StatusCode == System.Net.HttpStatusCode.Forbidden)
            {
                GeminiApp.LogException(new ApplicationException(response.Content) { Source = SourceControlProvider.Git.ToString() }, false);
                
                throw new ApplicationException(response.Content);
            }
            else if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                GeminiApp.LogException(new UnauthorizedAccessException(response.Content) { Source = SourceControlProvider.Git.ToString() }, false);
                
                throw new UnauthorizedAccessException(response.Content);
            }
            else if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                GeminiApp.LogException(new FileNotFoundException(response.Content) { Source = SourceControlProvider.Git.ToString() }, false);
                
                throw new FileNotFoundException(response.Content);
            }
            else
            {
                GeminiApp.LogException(new Exception(response.Content) { Source = SourceControlProvider.Git.ToString() }, false);
                
                throw new Exception(response.Content); 
            }
        }

        public bool AuthenticateUser(UserDto user, string repositoryUrl, GeminiContext gemini)
        {
            UserWidgetData<List<UserWidgetDataDetails>> userDataRaw = gemini.UserWidgetStore.Get<List<UserWidgetDataDetails>>(user.Entity.Id, Constants.AppId, Constants.ControlId);

            if (userDataRaw == null) return false;

            var data = userDataRaw.Value.Find(f => f.RepositoryUrl == repositoryUrl && f.Provider == SourceControlProvider.Git);

            if (data == null) return false;

            Username = data.Username;
            
            Password = SecretsHelper.Decrypt(data.Password, SecretsHelper.EncryptionKey);

            return true;
        }

        public string CreateAuthenticationForm(string url, string repositoryURL, string filename)
        {            
            StringBuilder form = new StringBuilder();
            
            form.Append(string.Format("<div><a href='{0}'>{0}<a></div>", repositoryURL));

            form.Append(string.Format("<form id='authentication_form' action='apps/saucery/authenticate/{0}' method='post'>", SourceControlProvider.Git));
            
            form.Append("<input type='text' name='username' placeholder='username' id='username'/>");
            
            form.Append("<input class='margin-bottom-5' type='password' name='password' placeholder='password' id='password'/><br />");

            form.Append("<input type='button' class='button-primary button-small' name='git_login' id='git_login' value='Login'/>");

            form.Append("<input type='button' class='button-secondary button-small margin-left-5 cancel' name='git_cancel' id='git_cancel' value='Cancel'/>");
            
            form.Append(string.Format("<input id='repositoryurl' type='hidden' name='repositoryurl' value='{0}'/>", repositoryURL));
            
            form.Append(string.Format("<input id='filename' type='hidden' name='filename' value='{0}'/>", filename));
            
            form.Append("</form>");
            
            return form.ToString();
        }

        public void SaveLoginDetails(UserDto user, UserWidgetDataDetails userData, GeminiContext gemini )
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

    }
}
