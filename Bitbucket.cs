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
using RestSharp;
using Countersoft.Gemini;
using Countersoft.Gemini.Contracts;
using Countersoft.Gemini.Commons.Dto;
using Countersoft.Gemini.Commons.System;
using Countersoft.Gemini.Infrastructure.Api;
using System.Web.UI;
using Countersoft.Gemini.Commons.Entity.Security;
using System.Text.RegularExpressions;
using Countersoft.Gemini.Infrastructure.Apps;
using Countersoft.Gemini.Infrastructure;
using System.Web.Mvc;

namespace Saucery
{
    public class Bitbucket
    {
        private string Username { get; set; }
        
        private string Password { get; set; }

        public class BitBucketRepository
        {
            public string website { get; set; }
            public bool fork { get; set; }
            public string name { get; set; }
            public string scm { get; set; }
            public string owner { get; set; }
            public string absolute_url { get; set; }
            public string slug { get; set; }
            public bool is_private { get; set; }
        }

        public class BitBucketFile
        {
            public string type { get; set; }
            public string file { get; set; }
        }

        public class BitBucketCommit
        {
            public string node { get; set; }
            public List<BitBucketFile> files { get; set; }
            public string raw_author { get; set; }
            public string utctimestamp { get; set; }
            public string author { get; set; }
            public string timestamp { get; set; }
            public string raw_node { get; set; }
            public List<string> parents { get; set; }
            public string branch { get; set; }
            public string message { get; set; }
            public object revision { get; set; }
            public int size { get; set; }
        }

        public class Payload
        {
            public BitBucketRepository repository { get; set; }
            public bool truncated { get; set; }
            public List<BitBucketCommit> commits { get; set; }
            public string canon_url { get; set; }
            public string user { get; set; }
        }

        public class BitBucketRootObject
        {
            public Payload payload { get; set; }
        }

        [ValidateInput(false)]
        [OutputCache(Duration = 0, NoStore = false, Location = OutputCacheLocation.None)]
        public class SauceryBitbucketController : BaseApiAppController
        {
            [System.Web.Mvc.HttpPost]
            public List<CodeCommit> CodeCommit(string auth, string payload = "")
            {
                if (auth.IsEmpty())
                {
                    GeminiApp.LogException(new UnauthorizedAccessException() { Source = SourceControlProvider.Bitbucket.ToString() }, false);

                    return null;
                }

                var authDetails = Encoding.Default.GetString(Convert.FromBase64String(auth)).Split(':');

                string apikey = string.Empty;

                if (authDetails.Length == 2)
                {
                    apikey = authDetails[0];                  
                }                
              
                CurrentUser = new UserDto(new User() { ProjectGroups = new List<ProjectGroupMembership>() { new ProjectGroupMembership() { ProjectGroupId = Countersoft.Gemini.Commons.Constants.GlobalGroupAdministrators, UserId = 0 } } });
                UserContext.User = CurrentUser;
                PermissionsManager = PermissionsManager.Copy(CurrentUser);
                UserContext.PermissionsManager = PermissionsManager;

                if (apikey.Length == 0 || GeminiApp.Config.ApiKey.Length == 0 || !apikey.StartsWith(GeminiApp.Config.ApiKey, StringComparison.InvariantCultureIgnoreCase))
                {
                    string error;

                    if (GeminiApp.Config.ApiKey.Length == 0)
                    {
                        error = "Web.config is missing API key.";
                    }
                    else
                    {
                        error = string.Format("Wrong API key: {0}.", apikey);
                    }

                    GeminiApp.LogException(new Exception(error) { Source = SourceControlProvider.Bitbucket.ToString() }, false);

                    return null;
                }

                
                try
                {
                    var body = Request.Content.ReadAsStringAsync();
                    body.Wait();
                    //GeminiApp.LogException("Null CodeCommit", string.Concat("Null CodeCommit - ", body.Result), false);
                }
                catch
                {
                    try
                    {
                        GeminiApp.LogException("Null CodeCommit", "Null CodeCommit - Empty!", false);
                    }
                    catch
                    {
                    }
                }


                Payload commits = System.Web.HttpContext.Current.Request.Form["payload"].FromJson<Payload>();

                if (commits == null) return null;

                List<CodeCommit> allCommits = new List<CodeCommit>();

                foreach (var commit in commits.commits)
                {
                    Regex ex = new Regex("GEM:(?<issueid>[0-9]+)", RegexOptions.IgnoreCase);
                    MatchCollection matches = ex.Matches(commit.message);
                    List<int> issueAdded = new List<int>();

                    List<string> filesModified = new List<string>();

                    foreach (var file in commit.files)
                    {
                        FileCommitType type = FileCommitType.Created;

                        if (file.type.Equals("modified", StringComparison.InvariantCultureIgnoreCase))
                            type = FileCommitType.Modified;
                        else if (file.type.Equals("removed", StringComparison.InvariantCultureIgnoreCase))
                            type = FileCommitType.Deleted;

                        filesModified.Add(string.Concat("{\"Filename\":\"", file.file, "\", \"FileId\":\"", string.Empty, "\",\"PreviousFileRevisionId\":\"", string.Empty, "\", \"Type\":\"", type.ToString(), "\" }"));
                    }

                    var data = commit.ToJson();

                    if (matches.Count > 0)
                    {
                        foreach (Match match in matches)
                        {
                            IssueDto issue = IssueManager.Get(match.ToString().Remove(0, 4).ToInt());
                            if (issue != null)
                            {
                                if (!issueAdded.Contains(issue.Id))
                                {
                                    CodeCommit newCodeCommit = new CodeCommit();
                                    newCodeCommit.Provider = SourceControlProvider.Bitbucket;
                                    newCodeCommit.Comment = commit.message;
                                    newCodeCommit.Fullname = commit.author;
                                    newCodeCommit.Data = string.Concat("{\"RevisionId\":\"", commit.raw_node, "\",\"PreviousRevisionId\":\"", commit.parents[0], "\",\"Files\":[", string.Join(",", filesModified.ToArray()), "],\"RepositoryName\":\"", commits.repository.name, "\",\"RepositoryUrl\":\"", String.Concat(commits.canon_url, commits.repository.absolute_url), "\",\"IsPrivate\":\"", commits.repository.is_private, "\"}"); ;
                                    newCodeCommit.IssueId = issue.Id;

                                    allCommits.Add(GeminiContext.CodeCommits.Create(newCodeCommit));

                                    issueAdded.Add(issue.Id);

                                    try
                                    {
                                        if (match.Index + match.Length + 1 + 5 <= commit.message.Length)
                                        {
                                            var time = commit.message.Substring(match.Index + match.Length + 1, 5);
                                            var timeEx = new System.Text.RegularExpressions.Regex("[0-9][0-9]:[0-9][0-9]");
                                            var m = timeEx.Match(time);
                                            if (m.Success)
                                            {
                                                // Okay, log time!
                                                var timeTypes = MetaManager.TimeTypeGetAll(issue.Project.TemplateId);
                                                if (timeTypes.Count > 0)
                                                {
                                                    // Let's try and find the user
                                                    var user = commit.author.HasValue() ? Cache.Users.Find(u => u.Username.Equals(commit.author, StringComparison.InvariantCultureIgnoreCase)
                                                        || u.Email.Equals(commit.author, StringComparison.InvariantCultureIgnoreCase)
                                                        || u.Fullname.Equals(commit.author, StringComparison.InvariantCultureIgnoreCase)) : null;
                                                    var timeEntry = new IssueTimeTracking();
                                                    timeEntry.IssueId = issue.Id;
                                                    timeEntry.ProjectId = issue.Entity.ProjectId;
                                                    timeEntry.Comment = commit.message.ToMax(1990);
                                                    timeEntry.EntryDate = DateTime.Now;
                                                    timeEntry.Hours = m.Value.Substring(0, 2).ToInt();
                                                    timeEntry.Minutes = m.Value.Substring(3, 2).ToInt();
                                                    timeEntry.TimeTypeId = timeTypes[0].Entity.Id;
                                                    timeEntry.UserId = user == null ? Countersoft.Gemini.Commons.Constants.SystemAccountUserId : user.Id;
                                                    TimeTrackingManager.Create(timeEntry);
                                                }
                                            }
                                        }
                                    }
                                    catch (Exception timeEx)
                                    {
                                        LogManager.LogError(timeEx, "BitBucket - Time log");
                                    }
                                }
                            }
                            else
                            {
                                GeminiApp.LogException(new Exception(string.Concat("Item ID ", match.ToString().Remove(0, 4).ToInt(), " could not be found.")) { Source = "Commit Failed" }, false);
                            }
                        }
                    }
                }

                return allCommits;
            }
        }

        public string GetFileContent(GeminiContext gemini,int issueid, string repositoryUrl, string filename, string revisionId, bool getPreviousRevision = false)
        {
            if (filename.IsEmpty()) return string.Empty;
                        
            var allIssueCommits = gemini.CodeCommits.GetAll(issueid);
                
            if (allIssueCommits == null || allIssueCommits.Count() == 0) return string.Empty;

            var fileCommits = allIssueCommits.Where(f => f.Provider == SourceControlProvider.Bitbucket && f.Data.Contains(repositoryUrl) && f.Data.Contains(filename) && f.Data.Contains(string.Concat("\"RevisionId\":\"", revisionId)));

            if (fileCommits == null || fileCommits.Count() != 1) return string.Empty;

            var fileCommitsJson = fileCommits.First().Data.FromJson<SourceControlCommit>();

            FileCommitType type = fileCommitsJson.Files.Where(f => f.Filename == filename).First().Type;
                
            if (getPreviousRevision)
            {
                if (fileCommitsJson.PreviousRevisionId.IsEmpty() || type == FileCommitType.Created) return string.Empty;

                revisionId = fileCommitsJson.PreviousRevisionId;
            }
            else
            {
                if (type == FileCommitType.Deleted) return string.Empty;
            }

            RestSharp.IRestResponse response;

            try
            {
                response = GetResponse(string.Format("{0}raw/{1}/{2}", repositoryUrl, revisionId, filename), RestSharp.Method.GET);
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
                GeminiApp.LogException(new Exception(string.Format("Content: {0} FileUrl: {1}", response.Content, url)) { Source = SourceControlProvider.Bitbucket.ToString() }, false);
            }

            if (response.StatusCode == HttpStatusCode.OK)
            {
                if (response.ContentLength == -1 && response.ResponseUri.AbsoluteUri.Contains("bitbucket.org/account/signin", StringComparison.InvariantCultureIgnoreCase))
                {
                    GeminiApp.LogException(new UnauthorizedAccessException(response.Content) { Source = SourceControlProvider.Bitbucket.ToString() }, false);

                    throw new UnauthorizedAccessException(response.Content);
                }
                else
                {
                    return response;
                }
            }

            if (response.StatusCode == System.Net.HttpStatusCode.Forbidden)
            {
                GeminiApp.LogException(new ApplicationException(response.Content) { Source = SourceControlProvider.Bitbucket.ToString() }, false);
                
                throw new ApplicationException(response.Content);
            }
            else if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                GeminiApp.LogException(new UnauthorizedAccessException(response.Content) { Source = SourceControlProvider.Bitbucket.ToString() }, false);
                
                throw new UnauthorizedAccessException(response.Content);
            }
            else if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                GeminiApp.LogException(new FileNotFoundException(response.Content) { Source = SourceControlProvider.Bitbucket.ToString() }, false);
                
                throw new FileNotFoundException(response.Content);
            }
            else
            {
                GeminiApp.LogException(new Exception(response.Content) { Source = SourceControlProvider.Bitbucket.ToString() }, false);
                
                throw new Exception(response.Content); 
            }
        }

        public bool AuthenticateUser(UserDto user, string repositoryUrl, GeminiContext gemini)
        {
            UserWidgetData<List<UserWidgetDataDetails>> userDataRaw = gemini.UserWidgetStore.Get<List<UserWidgetDataDetails>>(user.Entity.Id, Constants.AppId, Constants.ControlId);

            if (userDataRaw == null) return false;

            var data = userDataRaw.Value.Find(f => f.RepositoryUrl == repositoryUrl && f.Provider == SourceControlProvider.Bitbucket);

            if (data == null) return false;

            Username = data.Username;
            
            Password = SecretsHelper.Decrypt(data.Password, SecretsHelper.EncryptionKey);

            return true;
        }

        public string CreateAuthenticationForm(string url, string repositoryURL, string filename)
        {            
            StringBuilder form = new StringBuilder();
            
            form.Append(string.Format("<div><a href='{0}'>{0}<a></div>", repositoryURL));

            form.Append(string.Format("<form id='authentication_form' action='apps/saucery/authenticate/{0}' method='post'>", SourceControlProvider.Bitbucket.ToString()));
            
            form.Append("<input type='text' name='username' placeholder='username' id='username'/>");
            
            form.Append("<input class='margin-bottom-5' type='password' name='password' placeholder='password' id='password'/><br />");
            
            form.Append("<input type='button' class='button-primary button-small' name='bitbucket_login' id='bitbucket_login' value='Login'/>");
            
            form.Append("<input type='button' class='button-secondary button-small margin-left-5 cancel' name='bitbucket_cancel' id='bitbucket_cancel' value='Cancel'/>");
            
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
//https://confluence.atlassian.com/bitbucket/write-brokers-services-for-bitbucket-cloud-222724121.html
//https://confluence.atlassian.com/bitbucket/event-payloads-740262817.html#EventPayloads-entity_repository
//https://confluence.atlassian.com/bitbucket/event-payloads-740262817.html#EventPayloads-Push
//https://confluence.atlassian.com/bitbucket/manage-bitbucket-cloud-services-221449732.html