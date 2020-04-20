using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Countersoft.Gemini.Commons.Entity;
using Countersoft.Gemini.Extensibility.Apps;
using Countersoft.Gemini.Infrastructure;
using RestSharp;
using Countersoft.Foundation.Commons.Extensions;
using System.Web.Http;
using System.Web.Mvc;
using Countersoft.Gemini.Contracts;
using Countersoft.Gemini.Commons;
using System.Web;
using Countersoft.Gemini;
using Countersoft.Gemini.Infrastructure.Managers;
using Countersoft.Gemini.Commons.Dto;
using Countersoft.Gemini.Commons.System;
using System.IO;
using Countersoft.Gemini.Infrastructure.Api;
using System.Web.UI;
using Countersoft.Gemini.Commons.Entity.Security;
using System.Text.RegularExpressions;

namespace Saucery
{
    public class GitHub
    {
        private string Username { get; set; }
        private string Password { get; set; }
        private string AccessToken { get; set; }

        public class AuthenticateToken
        {
            public string token_type { get; set; }
            public string access_token { get; set; }
        }

        public class GitHubFileContent
        {
            public string content { get; set; }
        }

        public class Error
        {
            public string error { get; set; }
        }

        public class TreeUrl
        {
            public TreeUrlChild tree { get; set; }
            public CommitParents[] parents { get; set; }
        }

        public class CommitParents
        {
            public string sha { get; set; }
            public string url { get; set; }
        }

        public class TreeFilesChild
        {
            public string type { get; set; }
            public string url { get; set; }
            public string path { get; set; }
            public string mode { get; set; }
            public string sha { get; set; }
            public int size { get; set; }
        }

        public class TreeFiles
        {
            public string url { get; set; }
            public string sha { get; set; }
            public TreeFilesChild[] tree { get; set; }
        }

        public class TreeUrlChild
        {
            public string url { get; set; }
            public string sha { get; set; }

        }

        [ValidateInput(false)]
        [OutputCache(Duration = 0, NoStore = false, Location = OutputCacheLocation.None)]
        public class SauceryGithubController : BaseController
        {
            public ActionResult Authenticate(string code, int state)
            {
                GitHub gitHub = new GitHub(); //Creates a new GitHub object
                
                UserWidgetData<List<UserWidgetDataDetails>> userDataRaw = GeminiContext.UserWidgetStore.Get<List<UserWidgetDataDetails>>(CurrentUser.Entity.Id, Constants.AppId, Constants.ControlId);

                if (userDataRaw != null)
                {
                    var data = userDataRaw.Value.Find(f => f.Provider == SourceControlProvider.GitHub && f.AccessToken.IsEmpty());

                    // Need to check that state is the same as we've sent otherwise ABORT (cross-site request forgery attacks) ! 
                    if (!code.IsEmpty() && CurrentUser.Entity.Id == state)
                    {
                        if (data != null)
                        {
                            var password =  SecretsHelper.Decrypt(data.Password, SecretsHelper.EncryptionKey);

                            try
                            {
                                var response = gitHub.GetResponse(string.Format("https://github.com/login/oauth/access_token?client_id={0}&client_secret={1}&code={2}&state={3}", data.Username, password, code, state), RestSharp.Method.GET);

                                if (response != null)
                                {
                                    var token = response.Content.FromJson<AuthenticateToken>();
                                    
                                    if (token.access_token.IsNullOrWhiteSpace())
                                    {
                                        GeminiApp.LogException(new Exception(response.Content.FromJson<Error>().error) { Source = "GitHub Authentication" }, false);
                                        gitHub.DeleteLoginDetails(CurrentUser, data, GeminiContext);
                                        //If request fails we need to make sure we delete the record associated with this authentication request from DB. Otherwise we'll have several records with empty access token
                                    }
                                    else
                                    {
                                        data.AccessToken = token.access_token;
                                        gitHub.SaveLoginDetails(CurrentUser, data, GeminiContext);
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                GeminiApp.LogException(ex, false);
                            }
                        }                        
                    }
                    else
                    {
                        GeminiApp.LogException(new UnauthorizedAccessException("Code/State invalid") { Source = SourceControlProvider.GitHub.ToString() }, false);
                        
                        gitHub.DeleteLoginDetails(CurrentUser, data, GeminiContext);
                    }
                }

               return Redirect(CurrentProject.HomePageUrl);
            }
        }

        public string GetFileContent(GeminiContext gemini, int issueid, string repositoryUrl,string revisionId, string filename, string fileId, bool getPreviousRevision = false)
        {
            if (filename.IsEmpty() || repositoryUrl.IsEmpty()) return string.Empty;
            
            var result = string.Empty;

            if (getPreviousRevision)
            {
                var allIssueCommits = gemini.CodeCommits.GetAll(issueid);

                if (allIssueCommits == null || allIssueCommits.Count() == 0) return string.Empty;

                var fileCommits = allIssueCommits.Where(f => f.Provider == SourceControlProvider.GitHub && f.Data.Contains(repositoryUrl) && f.Data.Contains(filename) && f.Data.Contains(string.Concat("\"RevisionId\":\"", revisionId,"\"")));

                if (fileCommits == null || fileCommits.Count() != 1) return string.Empty;

                var fileCommitsJson = fileCommits.First().Data.FromJson<SourceControlCommit>();

                fileId = fileCommitsJson.Files.Where(f => f.Filename == filename).First().PreviousFileRevisionId;              
            }

            if (fileId.IsEmpty()) return string.Empty;

            RestSharp.IRestResponse response;
            
            repositoryUrl = repositoryUrl.Replace("https://api.github.com","https://api.github.com/repos");

            try
            {
                response = GetResponse(string.Format("{0}/git/blobs/{1}?access_token={2}", repositoryUrl, fileId, AccessToken), RestSharp.Method.GET);
                
                result = Encoding.Default.GetString(Convert.FromBase64String(response.Content.FromJson<GitHubFileContent>().content));
            }
            catch (Exception ex)
            {
                GeminiApp.LogException(ex, false);
                
                return string.Empty;
            }           
            
            return result;
        }


        public IRestResponse GetResponse(string url, RestSharp.Method method)
        {
            RestClient client = new RestClient(url);
            
            RestSharp.RestRequest request = new RestSharp.RestRequest(method);
            request.AddHeader("Authorization", string.Concat("token ", AccessToken));

            var response = client.Execute(request);

            if (DebugConstant.DebugModeState)
            {
                GeminiApp.LogException(new Exception(string.Format("Content: {0} FileUrl: {1}", response.Content, url)) { Source = SourceControlProvider.SVN.ToString() }, false);
            }

            if (response.StatusCode == System.Net.HttpStatusCode.OK) return response;

            if (response.StatusCode == System.Net.HttpStatusCode.Forbidden)
            {
                GeminiApp.LogException(new ApplicationException(response.Content) { Source = SourceControlProvider.GitHub.ToString() }, false);

                throw new ApplicationException(response.Content);
            }
            else if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                GeminiApp.LogException(new FileNotFoundException(response.Content) { Source = SourceControlProvider.SVN.ToString() }, false);
                
                throw new FileNotFoundException(response.Content);
            }
            else if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                GeminiApp.LogException(new UnauthorizedAccessException(response.Content) { Source = SourceControlProvider.GitHub.ToString() }, false);
                
                throw new UnauthorizedAccessException(response.Content);
            }
            else
            {
                GeminiApp.LogException(new Exception(response.Content) { Source = SourceControlProvider.SVN.ToString() }, false);
                
                throw new Exception(response.Content);
            }
        }

        public string CreateAuthenticationForm(string url, string repositoryURL, string filename)
        {
            StringBuilder form = new StringBuilder();
            
            form.Append(string.Format("<div class='hardBreak'><a href='{0}'>{0}<a></div>", repositoryURL.Replace("api.github.com","github.com")));
            
            form.Append(string.Format("<form id='authentication_form' action='apps/saucery/authenticate/{0}' method='post'>", SourceControlProvider.GitHub));
            
            form.Append("<input type='text' name='username' placeholder='Client ID' id='username'/>");
            
            form.Append("<input class='margin-bottom-5' type='password' name='password' placeholder='Client Secret' id='password'/><br />");
            
            form.Append("<input type='button' class='button-primary button-small' name='github_login' id='github_login' value='Login'/>");
            
            form.Append("<input type='button' class='button-secondary button-small margin-left-5 cancel' name='github_cancel' id='github_cancel' value='Cancel'/>");
            
            form.Append(string.Format("<input id='repositoryurl' type='hidden' name='repositoryurl' value='{0}'/>", repositoryURL));
            
            form.Append(string.Format("<input id='filename' type='hidden' name='filename' value='{0}'/>", filename));
            
            form.Append("</form>");
            
            return form.ToString();
        }

        public bool AuthenticateUser(UserDto user, string repositoryUrl, GeminiContext gemini)
        {
            //UserWidgetData<List<UserWidgetDataDetails>> userDataRaw = gemini.UserWidgetStore.Get<List<UserWidgetDataDetails>>(user.Entity.Id, Constants.AppId, Constants.ControlId);
            
            var allUserDataRaw = gemini.UserWidgetStore.GetAll().Where(f => f.AppId == Constants.AppId && f.ControlId == Constants.ControlId);

            if (allUserDataRaw == null || allUserDataRaw.Count() == 0) return false;
 
            var data = allUserDataRaw.Select(f => f.Value.FromJson<List<UserWidgetDataDetails>>()).First().Find(s => s.Provider == SourceControlProvider.GitHub && s.RepositoryUrl == repositoryUrl);

            if (data == null) return false;

            if (data.AccessToken.IsEmpty()) return false;

            Username = data.Username;
            
            Password = SecretsHelper.Decrypt(data.Password, SecretsHelper.EncryptionKey); 
            
            AccessToken = data.AccessToken;
            
            return true;
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
                /**
                 * We need to make sure there are NO github Authentication records with an empty access token otherwise when we receive the access_token back from them we will not be able to associate that request to the right
                 * Repository with an empty access token
                 * check if there is already an entry for github with empty access token, if yes then delete it
                 */
                var incompleteAuthentication = userDataRaw.Value.Find(f => f.Provider == userData.Provider && f.AccessToken.IsEmpty());

                if (incompleteAuthentication != null)
                {
                    //var index = userDataRaw.Value.FindIndex(f => f.RepositoryUrl == userData.RepositoryUrl && f.Provider == userData.Provider && f.AccessToken.IsEmpty());
                    DeleteLoginDetails(user, incompleteAuthentication, gemini);
                    
                    userDataRaw = gemini.UserWidgetStore.Get<List<UserWidgetDataDetails>>(user.Entity.Id, Constants.AppId, Constants.ControlId);
                }

                var tmpUser = userDataRaw.Value.Find(f => f.RepositoryUrl == userData.RepositoryUrl && f.Provider == userData.Provider);

                // If a password for this rep already exist, update the details only
                if (tmpUser != null)
                {
                    var index = userDataRaw.Value.FindIndex(f => f.RepositoryUrl == userData.RepositoryUrl && f.Provider == userData.Provider);

                    userDataRaw.Value[index].Username = userData.Username;
                    
                    userDataRaw.Value[index].Password = userData.Password;
                    
                    userDataRaw.Value[index].AccessToken = userData.AccessToken;
                }
                else
                {
                    // Add a new user authentication for this user
                    userDataRaw.Value.Add(userData);
                }

                gemini.UserWidgetStore.Save(user.Entity.Id, Constants.AppId, Constants.ControlId, userDataRaw.Value);
            }

        }

        public void DeleteLoginDetails(UserDto user, UserWidgetDataDetails userData, GeminiContext gemini)
        {
            UserWidgetData<List<UserWidgetDataDetails>> userDataRaw = gemini.UserWidgetStore.Get<List<UserWidgetDataDetails>>(user.Entity.Id, Constants.AppId, Constants.ControlId);
            
            if (userDataRaw != null)
            {
                var tmpUser = userDataRaw.Value.FindAll(f => f.RepositoryUrl == userData.RepositoryUrl && f.Provider == userData.Provider);

                // If a password for this rep already exist, update the details only
                if (tmpUser != null)
                {
                    var index = userDataRaw.Value.FindIndex(f => f.RepositoryUrl == userData.RepositoryUrl && f.Provider == userData.Provider);

                    userDataRaw.Value.RemoveAt(index); 
                }

                gemini.UserWidgetStore.Save(user.Entity.Id, Constants.AppId, Constants.ControlId, userDataRaw.Value);
            }
        }


        public string updateFileIds(GeminiContext gemini, string repositoryUrl, string revisionId, string filename, int issueId)
        {
            var allCommits = gemini.CodeCommits.GetAll(issueId);

            string result = string.Empty;

            if (allCommits != null)
            {
                var sourceCommits = allCommits.Where(f => f.Provider == SourceControlProvider.GitHub);
                
                if (sourceCommits != null)
                {
                    var commit = sourceCommits.Where(f => f.Data.Contains(string.Concat("\"RevisionId\":\"", revisionId,"\"")) && f.Data.Contains(filename));
                    
                    if (commit != null && commit.Count() > 0)
                    {
                        var data = commit.First().Data.FromJson<SourceControlCommit>();
                        
                        var emptyFileIds = data.Files.Where(f => f.FileId.IsEmpty());
                        
                        // If there are empty fielid's go and get them
                        if (emptyFileIds.Count() > 0)
                        {
                            var githubCommit = GetResponse(string.Concat(data.RepositoryUrl.ReplaceIgnoreCase("https://api.github.com", "https://api.github.com/repos"), "/git/commits/", revisionId, "?access_token=", AccessToken), RestSharp.Method.GET);
                            
                            var githubCommitJson = githubCommit.Content.FromJson<TreeUrl>();

                            var githubPreviousCommit = GetResponse(string.Concat(data.RepositoryUrl.ReplaceIgnoreCase("https://api.github.com", "https://api.github.com/repos"), "/git/commits/", githubCommitJson.parents.First().sha, "?access_token=", AccessToken), RestSharp.Method.GET);
                            
                            var githubPreviousCommitJson = githubPreviousCommit.Content.FromJson<TreeUrl>();

                            var githubCommitTree = GetResponse(string.Concat(githubCommitJson.tree.url, "?recursive=1", "&access_token=", AccessToken), RestSharp.Method.GET);
                            
                            var githubPreviousCommitTree = GetResponse(string.Concat(githubPreviousCommitJson.tree.url, "?recursive=1", "&access_token=", AccessToken), RestSharp.Method.GET);

                            var gitCommitTreeJson = githubCommitTree.Content.FromJson<TreeFiles>();
                            
                            var gitPreviousCommitTreeJson = githubPreviousCommitTree.Content.FromJson<TreeFiles>();

                            if (gitCommitTreeJson != null || gitPreviousCommitTreeJson != null)
                            {                          
                                foreach (var blob in data.Files)
                                {
                                    if (gitCommitTreeJson != null)
                                    {
                                        var fileExist = gitCommitTreeJson.tree.Where(f => f.path == blob.Filename);
                                        
                                        if (fileExist != null && fileExist.Count() == 1)
                                        {
                                            blob.FileId = fileExist.Select(f => f.sha).First();
                                            
                                            if (filename == blob.Filename) result = blob.FileId;
                                        }
                                    }

                                    if (gitPreviousCommitTreeJson != null)
                                    {
                                        var fileExist = gitPreviousCommitTreeJson.tree.Where(f => f.path == blob.Filename);
                                        
                                        if (fileExist != null && fileExist.Count() == 1) blob.PreviousFileRevisionId = fileExist.Select(f => f.sha).First();
                                    }                                   
                                }

                                if (data.PreviousRevisionId.IsEmpty()) data.PreviousRevisionId = githubCommitJson.parents.First().sha;
                                
                                commit.First().Data = data.ToJson();                                
                            }

                            gemini.CodeCommits.Update(commit.First());
                        }
                        else
                        {
                            result = data.Files.Where(f => f.Filename == filename).Select(f => f.FileId).First();
                        }
                    }
                }
            }

            return result;
        }

    }

    [ValidateInput(false)]
    [OutputCache(Duration = 0, NoStore = false, Location = OutputCacheLocation.None)]
    public class GitHubController : BaseApiController
    {
        [System.Web.Mvc.HttpPost]
        public string Commit(CommitObject commits, [FromUri] string token)
        {
            string apikey = string.Empty;
            string result = string.Empty;

            CurrentUser = new UserDto(new User() { ProjectGroups = new List<ProjectGroupMembership>() { new ProjectGroupMembership() { ProjectGroupId = Countersoft.Gemini.Commons.Constants.GlobalGroupAdministrators, UserId = 0 } } });
            UserContext.User = CurrentUser;
            PermissionsManager = PermissionsManager.Copy(CurrentUser);
            UserContext.PermissionsManager = PermissionsManager;

            if (Request.Headers.Authorization != null && Request.Headers.Authorization.Parameter != null)
            {
                var authDetails = Encoding.Default.GetString(Convert.FromBase64String(Request.Headers.Authorization.Parameter)).Split(':');
                if (authDetails.Length == 2)
                {
                    apikey = authDetails[0];
                }
            }
            else if(token != null)
            {
                apikey = token;
            }

            if (apikey.Length == 0 || GeminiApp.Config.ApiKey.Length == 0 || !apikey.StartsWith(GeminiApp.Config.ApiKey, StringComparison.InvariantCultureIgnoreCase))
            {
                string error;

                if (GeminiApp.Config.ApiKey.Length == 0)
                {
                    error = "Web.config is missing API key";
                }
                else
                {
                    error = "Wrong API key: " + apikey;
                }

                GeminiApp.LogException(new Exception(error) { Source = SourceControlProvider.GitHub.ToString() }, false);

                return error;
            }

            if (commits == null)
            {
                try
                {
                    var body = Request.Content.ReadAsStringAsync();
                    body.Wait();
                    GeminiApp.LogException("Null CodeCommit", string.Concat("Null CodeCommit - ", body.Result), false);
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
                return string.Empty;
            }

            foreach (var commit in commits.commits)
            {
                Regex ex = new Regex("GEM:(?<issueid>[0-9]+)", RegexOptions.IgnoreCase);
                MatchCollection matches = ex.Matches(commit.message);

                if (matches.Count > 0)
                {

                    var baseUrl = commits.repository.url.ReplaceIgnoreCase("https://github.com/", "https://api.github.com/");

                    List<string> filesModified = new List<string>();

                    var commitIndex = commit.url.IndexOf("commit");
                    if (commitIndex != -1)
                    {
                        var url = string.Concat(commit.url.Remove(commitIndex, commit.url.Length - commitIndex), "blob/master/");

                        for (int i = 0; i < commit.added.Length; i++)
                        {
                            filesModified.Add(string.Concat("{\"Filename\":\"", commit.added[i], "\", \"FileId\":\"", string.Empty, "\",\"PreviousFileRevisionId\":\"", string.Empty, "\" }"));
                        }

                        for (int i = 0; i < commit.modified.Length; i++)
                        {
                            filesModified.Add(string.Concat("{\"Filename\":\"", commit.modified[i], "\",\"FileId\":\"", string.Empty, "\",\"PreviousFileRevisionId\":\"", string.Empty, "\"}"));
                        }

                        for (int i = 0; i < commit.removed.Length; i++)
                        {
                            filesModified.Add(string.Concat("{\"Filename\":\"", commit.removed[i], "\",\"FileId\":\"", string.Empty, "\",\"PreviousFileRevisionId\":\"", string.Empty, "\"}"));
                        }
                    }

                    CodeCommit codeCommit = new CodeCommit();
                    codeCommit.Provider = SourceControlProvider.GitHub;
                    codeCommit.Comment = commit.message;
                    codeCommit.Fullname = commit.author.name;
                    codeCommit.Data = string.Concat("{\"RevisionId\":\"", commit.id, "\",\"PreviousRevisionId\":\"", string.Empty, "\",\"Files\":[", string.Join(",", filesModified.ToArray()), "],\"RepositoryName\":\"", commits.repository.name, "\",\"RepositoryUrl\":\"", baseUrl, "\",\"IsPrivate\":\"", commits.repository.PRIVATE, "\"}");

                    commit.message = ex.Replace(commit.message, string.Empty);

                    List<int> issuesAlreadyProcessed = new List<int>();

                    foreach (Match match in matches)
                    {
                        var issue = IssueManager.Get(match.ToString().Remove(0, 4).ToInt());

                        if (issue != null && !issuesAlreadyProcessed.Contains(issue.Id))
                        {
                            codeCommit.IssueId = issue.Id;
                            GeminiContext.CodeCommits.Create(codeCommit);
                            issuesAlreadyProcessed.Add(issue.Id);

                            try
                            {
                                if (match.Index + match.Length + 1 + 5 <= codeCommit.Comment.Length)
                                {
                                    var time = codeCommit.Comment.Substring(match.Index + match.Length + 1, 5);
                                    var timeEx = new System.Text.RegularExpressions.Regex("[0-9][0-9]:[0-9][0-9]");
                                    var m = timeEx.Match(time);
                                    if (m.Success)
                                    {
                                        // Okay, log time!
                                        var timeTypes = MetaManager.TimeTypeGetAll(issue.Project.TemplateId);
                                        if (timeTypes.Count > 0)
                                        {
                                            // Let's try and find the user
                                            var user = commit.author.email.HasValue() ? Cache.Users.Find(u => u.Username.Equals(commit.author.email, StringComparison.InvariantCultureIgnoreCase)
                                                || u.Email.Equals(commit.author.email, StringComparison.InvariantCultureIgnoreCase)
                                                || u.Fullname.Equals(commit.author.email, StringComparison.InvariantCultureIgnoreCase)) : null;

                                            if (user == null)
                                            {
                                                user = commit.author.name.HasValue() ? Cache.Users.Find(u => u.Username.Equals(commit.author.name, StringComparison.InvariantCultureIgnoreCase)
                                                    || u.Email.Equals(commit.author.name, StringComparison.InvariantCultureIgnoreCase)
                                                    || u.Fullname.Equals(commit.author.name, StringComparison.InvariantCultureIgnoreCase)) : null;
                                            }
                                            var timeEntry = new IssueTimeTracking();
                                            timeEntry.IssueId = issue.Id;
                                            timeEntry.ProjectId = issue.Entity.ProjectId;
                                            timeEntry.Comment = codeCommit.Comment.ToMax(1990);
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
                                LogManager.LogError(timeEx, "GitHub - Time log");
                            }
                        }
                    }
                }
            }

            return result;
        }


        public class Author
        {
            public string email { get; set; }
            public string name { get; set; }
            public string username { get; set; }
        }

        public class Committer
        {
            public string email { get; set; }
            public string name { get; set; }
            public string username { get; set; }
        }

        public class AllCommits
        {
            public string[] added { get; set; }
            public Author author { get; set; }
            public Committer committer { get; set; }
            public bool distinct { get; set; }
            public string id { get; set; }
            public string message { get; set; }
            public string[] modified { get; set; }
            public object[] removed { get; set; }
            public DateTime timestamp { get; set; }
            public string url { get; set; }
        }

        public class Repository
        {
            public string description { get; set; }
            public int id { get; set; }
            public string name { get; set; }
            public int size { get; set; }
            public string url { get; set; }
            public bool PRIVATE { get; set; }
        }

        public class CommitObject
        {
            public AllCommits[] commits { get; set; }
            public Repository repository { get; set; }
            public string before { get; set; }
        }


        public class TreeUrlChild
        {
            public string url { get; set; }
            public string sha { get; set; }
        }

        public class TreeUrl
        {
            public TreeUrlChild tree { get; set; }
        }

        public class TreeFilesChild
        {
            public string type { get; set; }
            public string url { get; set; }
            public string path { get; set; }
            public string mode { get; set; }
            public string sha { get; set; }
            public int size { get; set; }
        }

        public class TreeFiles
        {
            public string url { get; set; }
            public string sha { get; set; }
            public TreeFilesChild[] tree { get; set; }
        }

        public IRestResponse GetResponse(string url, RestSharp.Method method)
        {
            RestClient client = new RestClient(url);
            RestSharp.RestRequest request = new RestSharp.RestRequest(method);
            var response = client.Execute(request);

            if (response.StatusCode == System.Net.HttpStatusCode.Forbidden)
            {
                GeminiApp.LogException(new ApplicationException(response.Content) { Source = "GitHub" }, false);
                throw new ApplicationException(response.Content);
            }

            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            {
                GeminiApp.LogException(new UnauthorizedAccessException(response.Content) { Source = "GitHub" }, false);
                throw new UnauthorizedAccessException(response.Content);
            }

            return response;
        }

    }
}
