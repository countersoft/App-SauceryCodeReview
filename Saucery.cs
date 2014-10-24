using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Countersoft.Gemini.Infrastructure.Api;
using Countersoft.Foundation.Commons.Extensions;
using Countersoft.Gemini.Commons;
using Countersoft.Gemini.Commons.Entity;
using Countersoft.Gemini.Commons.Dto;
using Countersoft.Gemini.Controllers.Api;
using Countersoft.Gemini.Extensibility.Apps;
using System.Web.Routing;
using DiffPlex.DiffBuilder;
using System.Web.Mvc;
using System.Web;
using RestSharp;
using Countersoft.Gemini.Infrastructure;
using DiffPlex.DiffBuilder.Model;
using DiffPlex;
using Countersoft.Gemini.Infrastructure.Apps;
using Microsoft.TeamFoundation;
using System.Text.RegularExpressions;
using Countersoft.Gemini.Commons.System;
using Countersoft.Gemini;
using System.Net;
using System.Net.Security;
using System.Web.UI;

namespace Saucery
{
    internal static class Constants
    {
        public static string AppId = "F473D13E-19B7-45F3-98ED-6ED77B6BAB0A";
        public static string ControlId = "18FE1D21-77G0-4067-8A10-F452FCB9D090";
    }

    static class DebugConstant
    {
        public static bool DebugModeState { get; set; }
    }

    public class Comment
    {
        public SourceControlProvider Provider { get; set; }
        public string ChangesetId { get; set; }
        public string FileName { get; set; }
        public string FileId { get; set; }
        public string Message { get; set; }
        public string LineNumber { get; set; }
        public string Fullname { get; set; }
        public DateTime Date { get; set; }
        public string RepositoryUrl { get; set; }
    }

    public class DiffplexComments
    {
        public DiffPlex.DiffBuilder.Model.SideBySideDiffModel data { get; set; }
        public List<Comment> comments { get; set; }
    }

    public class AuthenticationForm
    {
        public string form { get; set; }
    }

    public class SourceControlFile
    {
        public string Filename { get; set; }
        public string FullFilename { get; set; }
        public string Url { get; set; }
        public string FileId { get; set; }
        public string Workspace { get; set; }
        public string PreviousFileRevisionId { get; set; }
    }

    public class SourceControlCommit
    {
        public SourceControlFile[] Files { get; set; }
        public string RevisionId { get; set; }
        public string PreviousRevisionId { get; set; }
        public string RepositoryName { get; set; }
        public string RepositoryUrl { get; set; }
        public string ExtraData { get; set; }
    }

    public class SourceControlContainer
    {
        public SourceControlCommit commits { get; set; }
        public string Fullname { get; set; }
        public string RevisionId { get; set; }
        public SourceControlProvider Provider { get; set; }
        public int IssueId { get; set; }
        public DateTime Created { get; set; }
        public string Comment { get; set; }
        public CodeCommentBlock CommitBlock { get; set; }
    }

    public class UserWidgetDataDetails
    {
        public SourceControlProvider Provider { get; set; }
        public string RepositoryUrl { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string AccessToken { get; set; }
    }

    public class CodeCommentBlock
    {
        public string Comment { get; set; }
        public Dictionary<int, string> Items { get; set; }

        public CodeCommentBlock()
        {
            Comment = string.Empty;
            Items = new Dictionary<int, string>();
        }
    }  

    [AppType(AppTypeEnum.Widget),
    AppGuid("F473D13E-19B7-45F3-98ED-6ED77B6BAB0A"),
    AppControlGuid("18FE1D21-77G0-4067-8A10-F452FCB9D090"),
    AppAuthor("Countersoft"),
    AppKey("Saucery"),
    AppName("Saucery"),
    AppDescription("Saucery"),
    AppRequiresConfigScreen(false)]
    [ValidateInput(false)]
    [OutputCache(Duration = 0, NoStore = false, Location = OutputCacheLocation.None)]
    public class SauceryController : BaseAppController
    {
        private readonly ISideBySideDiffBuilder diffBuilder;
        
        private static bool _sslInitialised = false;
        
        private bool _validLicense;

        public SauceryController()
        {
            InitiateSSLTrust();
            
            diffBuilder = new SideBySideDiffBuilder(new Differ());
        }

        public override WidgetResult Caption(IssueDto item)
        {
            WidgetResult result = new WidgetResult();
            
            result.Success = true;
            
            result.Markup.Html = "Code Review";

            //DebugConstant.DebugModeState = DebugMode;
            return result;
        }

        public override WidgetResult Show(IssueDto item)
        {
            WidgetResult result = GetCommits(item);

            if (!_validLicense)
            {
                _validLicense = new Countersoft.Gemini.Infrastructure.LicenseManager().HasValidLicense("F473D13E-19B7-45F3-98ED-6ED77B6BAB0A", true);
                
                if (!_validLicense)
                {
                    result.Markup = new WidgetMarkup(UnlicensedMessage);
                    
                    result.Success = true;
                }
            }

            return result;
        }

        public override void RegisterRoutes(RouteCollection routes)
        {
            routes.MapRoute(null, "apps/saucery/getfilediff/{issueid}", new { controller = "Saucery", action = "GetFileDiff" }, new { issueid = @"\d{1,10}" });
            
            routes.MapRoute(null, "apps/saucery", new { controller = "Saucery", action = "Saucery" });
            
            routes.MapRoute(null, "apps/saucery/authenticate/{provider}", new { controller = "Saucery", action = "Authenticate" });
            
            routes.MapRoute(null, "apps/saucery/github/authenticate", new { controller = "SauceryGithub", action = "Authenticate" });
            
            routes.MapRoute(null, "apps/saucery/addcomment/{issueid}", new { controller = "Saucery", action = "AddComment" }, new { issueid = @"\d{1,10}" });
            
            routes.MapRoute(null, "apps/saucery/getcomment/{issueid}", new { controller = "Saucery", action = "GetComment" }, new { issueid = @"\d{1,10}" });
        }

        public ActionResult Authenticate(SourceControlProvider provider)
        {
            //Authentication
            string username = Request["username"] ?? string.Empty;
            
            string password = Request["password"] ?? string.Empty;
            
            string repositoryUrl = Request["repositoryurl"] ?? string.Empty;
            
            string filename = Request["filename"] ?? string.Empty;

            string message = string.Empty; //Commit message
            
            bool success = true;
            
            string extraData = string.Empty;    

            if (username.IsEmpty() || password.IsEmpty() || provider.ToString().IsEmpty() || repositoryUrl.IsEmpty())
            {
                message = "Please make sure Username, Password are not empty";
                
                success = false;
            }

            if (success)
            {
                UserWidgetDataDetails userData = new UserWidgetDataDetails();
                
                userData.Username = username.Trim();
                
                userData.Password = SecretsHelper.Encrypt(password.Trim(), SecretsHelper.EncryptionKey);
                
                userData.Provider = provider;
                
                userData.RepositoryUrl = repositoryUrl.Trim();
                
                userData.AccessToken = string.Empty;

                if (provider == SourceControlProvider.SVN)
                {
                    SVN svn = new SVN();
                    
                    svn.SaveLoginDetails(CurrentUser, userData, GeminiContext);
                }
                else if (provider == SourceControlProvider.GitHub)
                {
                    GitHub github = new GitHub();
                    
                    github.SaveLoginDetails(CurrentUser, userData, GeminiContext);

                    extraData = string.Format("https://github.com/login/oauth/authorize?client_id={0}&redirect_uri={1}apps/saucery/github/authenticate?state={2}&scope=repo", username, UserContext.Url, CurrentUser.Entity.Id);
                }
                else if (provider == SourceControlProvider.TFS2012)
                {
                    TFS2012 tfs2012 = new TFS2012();
                    
                    tfs2012.SaveLoginDetails(CurrentUser, userData, GeminiContext);                    
                }
                else if (provider == SourceControlProvider.TFS2010)
                {
                    TFS2010 tfs2010 = new TFS2010();
                    
                    tfs2010.SaveLoginDetails(CurrentUser, userData, GeminiContext);                    
                }
                else if (provider == SourceControlProvider.Git)
                {
                    Git git = new Git();
                    git.SaveLoginDetails(CurrentUser, userData, GeminiContext);
                }
            }

            return JsonSuccess(new { success = success, message = message, extraData =  extraData});
        }

        public WidgetResult GetCommits(IssueDto args)
        {
            var commits = GeminiContext.CodeCommits.GetAll(args.Id);

            var data = new IssueWidgetData<List<SourceControlContainer>>();
            
            data.Value = new List<SourceControlContainer>();
            
            if (commits != null)
            {
                foreach (var commit in commits)
                {
                    var dataHolder = new SourceControlContainer();
                    
                    dataHolder.commits = commit.Data.FromJson<SourceControlCommit>();

                    if (commit.Provider == SourceControlProvider.GitHub)
                    {
                        dataHolder.commits.ExtraData = dataHolder.commits.RepositoryUrl.ReplaceIgnoreCase("https://api.github.com", "https://github.com");
                    }

                    dataHolder.Provider = commit.Provider;
                    
                    dataHolder.Fullname = commit.Fullname;
                    
                    dataHolder.Created = commit.Created.ToLocal(UserContext.User.TimeZone);
                    
                    dataHolder.Comment = commit.Comment;
                    
                    dataHolder.CommitBlock = ParseCommentBlock(commit.Comment, args, dataHolder.commits.RevisionId);
                    
                    data.Value.Add(dataHolder);
                }
            }

            data.IssueId = args.Id;

            WidgetResult result = new WidgetResult();

            result.Markup = new WidgetMarkup("views//index.cshtml", data);
            
            result.Success = true;

            return result;
        }

        private CodeCommentBlock ParseCommentBlock(string comment, IssueDto args, string revisionid)
        {
            CodeCommentBlock block = new CodeCommentBlock();

            Regex ex = new Regex("GEM:(?<issueid>[0-9]+)", RegexOptions.IgnoreCase);
            
            MatchCollection matches = ex.Matches(comment);

            if (matches.Count > 0)
            {
                foreach (var item in matches)
                {
                    int issueId = item.ToString().ReplaceIgnoreCase("gem:", string.Empty).ToInt();

                    if (issueId != args.Id && !block.Items.ContainsKey(issueId))
                    {
                        block.Items.Add(issueId, string.Format("<a href='{0}project/all/0/item/{1}' target='_blank'>{1}</a>", UserContext.Url, issueId));
                    }
                }
            }

            block.Comment = comment;

            return block;
        }

        public ActionResult GetFileDiff(int issueId)
        {      
            string newFile = string.Empty;
            
            string oldFile = string.Empty;

            string fileName = Request["filename"] ?? string.Empty;
            
            string fullfilename = Request["fullfilename"] ?? string.Empty;
            
            string provider = Request["provider"]?? string.Empty;
            
            string revisionid = Request["revisionid"] ?? string.Empty;
            
            string fileid = Request["fileid"] ?? string.Empty;
            
            string repositoryUrl = Request["repositoryurl"] ?? string.Empty;
            
            string workspace = Request["workspace"] ?? string.Empty;

            fileName = fileName.Trim();
            
            fullfilename = fullfilename.Trim();
            
            provider = provider.Trim();
            
            revisionid = revisionid.Trim();
            
            fileid = fileid.Trim();
            
            repositoryUrl = repositoryUrl.Trim();
            
            workspace = workspace.Trim();

            //Authentication details
            string authenticateForm = string.Empty;
            
            bool IsUserAuthorized = false;
            
            bool isFileIdMissing = false;
            
            string data = string.Empty;
            
            string errorMessage = string.Empty;

            if (!repositoryUrl.IsEmpty())
            {
                if (provider == SourceControlProvider.GitHub.ToString())
                {
                    GitHub github = new GitHub();
                    
                    if (github.AuthenticateUser(CurrentUser, repositoryUrl, GeminiContext))
                    {
                        try
                        {
                            if (fileid.IsEmpty())
                            {
                                isFileIdMissing = true;
                                // Need to do this, because when github sends back the committed data there is no fileid(which we need to get the file content) for the files. 
                                // This will go and get the fileids once for each commit where fileid's are empty
                                fileid = github.updateFileIds(GeminiContext, repositoryUrl, revisionid, fileName, issueId);
                            }

                            newFile = github.GetFileContent(GeminiContext, issueId, repositoryUrl, revisionid, fileName, fileid);
                            
                            oldFile = github.GetFileContent(GeminiContext, issueId, repositoryUrl, revisionid, fileName, fileid, true);
                            
                            IsUserAuthorized = true;
                        }
                        catch (UnauthorizedAccessException ex)
                        {
                            authenticateForm = github.CreateAuthenticationForm(UserContext.Url, repositoryUrl, fileName);
                            
                            errorMessage = "Invalid login details";
                        }
                    }
                    else
                    {
                        authenticateForm = github.CreateAuthenticationForm(UserContext.Url, repositoryUrl, fileName);
                        
                        errorMessage = "Invalid login details";
                    }

                }
                else if (provider == SourceControlProvider.TFS2012.ToString())
                {
                    TFS2012 tfs2012 = new TFS2012();
                    
                    if (tfs2012.AuthenticateUser(CurrentUser, repositoryUrl, GeminiContext))
                    {
                        try
                        {
                            oldFile = tfs2012.GetFileContent(GeminiContext, issueId, fileName, fullfilename, workspace, revisionid, fileid,repositoryUrl, true);
                            
                            newFile = tfs2012.GetFileContent(GeminiContext, issueId, fileName, fullfilename, workspace, revisionid, fileid, repositoryUrl);
                            
                            IsUserAuthorized = true;
                        }
                        catch (UnauthorizedAccessException ex)
                        {
                            authenticateForm = tfs2012.CreateAuthenticationForm(UserContext.Url, repositoryUrl, fileName);
                            
                            errorMessage = "Invalid login details";
                        }
                        catch (TeamFoundationServerUnauthorizedException ex)
                        {
                            authenticateForm = tfs2012.CreateAuthenticationForm(UserContext.Url, repositoryUrl, fileName);
                            
                            errorMessage = ex.Message;
                        }
                    }
                    else
                    {
                        authenticateForm = tfs2012.CreateAuthenticationForm(UserContext.Url, repositoryUrl, fileName);
                    }

                }
                else if (provider == SourceControlProvider.TFS2010.ToString())
                {
                    TFS2010 tfs2010 = new TFS2010();
                    
                    if (tfs2010.AuthenticateUser(CurrentUser, repositoryUrl, GeminiContext))
                    {
                        try
                        {
                            oldFile = tfs2010.GetFileContent(GeminiContext, issueId, fileName, fullfilename, workspace, revisionid, fileid, repositoryUrl, true);
                            
                            newFile = tfs2010.GetFileContent(GeminiContext, issueId, fileName, fullfilename, workspace, revisionid, fileid, repositoryUrl);
                            
                            IsUserAuthorized = true;
                        }
                        catch (UnauthorizedAccessException ex)
                        {
                            authenticateForm = tfs2010.CreateAuthenticationForm(UserContext.Url, repositoryUrl, fileName);
                            
                            errorMessage = "Invalid login details";
                        }
                        catch (TeamFoundationServerUnauthorizedException ex)
                        {
                            authenticateForm = tfs2010.CreateAuthenticationForm(UserContext.Url, repositoryUrl, fileName);
                            
                            errorMessage = ex.Message;
                        }

                    }
                    else
                    {
                        authenticateForm = tfs2010.CreateAuthenticationForm(UserContext.Url, repositoryUrl, fileName);
                    }
                }
                else if (provider == SourceControlProvider.SVN.ToString())
                {
                    SVN svn = new SVN();
                    
                    if (svn.AuthenticateUser(CurrentUser, repositoryUrl, GeminiContext))
                    {
                        try
                        {
                            oldFile = svn.GetFileContent(GeminiContext, issueId, repositoryUrl, fileName, revisionid, true);
                            
                            newFile = svn.GetFileContent(GeminiContext, issueId, repositoryUrl, fileName, revisionid);
                            
                            IsUserAuthorized = true;
                        }
                        catch (UnauthorizedAccessException ex)
                        {
                            authenticateForm = svn.CreateAuthenticationForm(UserContext.Url, repositoryUrl, fileName);
                            
                            errorMessage = "Invalid login details";
                        }                        
                    }
                    else
                    {
                        authenticateForm = svn.CreateAuthenticationForm(UserContext.Url, repositoryUrl, fileName);
                        
                        errorMessage = "Invalid login details";
                    }
                }
                else if (provider == SourceControlProvider.Git.ToString())
                {
                    Git git = new Git();

                    if (git.AuthenticateUser(CurrentUser, repositoryUrl, GeminiContext))
                    {
                        try
                        {
                            oldFile = git.GetFileContent(GeminiContext, issueId, repositoryUrl, fileName, revisionid, true);

                            newFile = git.GetFileContent(GeminiContext, issueId, repositoryUrl, fileName, revisionid);
                            
                            IsUserAuthorized = true;
                        }
                        catch (UnauthorizedAccessException ex)
                        {
                            authenticateForm = git.CreateAuthenticationForm(UserContext.Url, repositoryUrl, fileName);
                            
                            errorMessage = "Invalid login details";
                        }                        
                    }
                    else
                    {
                        authenticateForm = git.CreateAuthenticationForm(UserContext.Url, repositoryUrl, fileName);
                        
                        errorMessage = "Invalid login details";
                    }
                }
            }
            else
            {
                errorMessage = "ERROR: Repository Url is missing";
            }

            if (IsUserAuthorized)
            {
                // Handle BOM markers
                oldFile = oldFile.Replace("\x00EF\x00BB\x00BF", "");
                
                newFile = newFile.Replace("\x00EF\x00BB\x00BF", "");

                // Diff
                var tmpModel = diffBuilder.BuildDiffModel(oldFile ?? string.Empty, newFile ?? string.Empty);

                IssueWidgetData<List<Comment>> tmpData = GeminiContext.IssueWidgetStore.Get<List<Comment>>(issueId, Constants.AppId, Constants.ControlId);

                DiffplexComments model = new DiffplexComments();

                if (tmpData != null)
                {
                    SourceControlProvider enumProvider;

                    try
                    {
                        enumProvider = (SourceControlProvider)Enum.Parse(typeof(SourceControlProvider), provider, true);
                    }
                    catch (ArgumentException ex)
                    {
                        enumProvider = 0;
                        
                        GeminiApp.LogException(new Exception(ex.Message) { Source = "Saucery" }, false);              
                    }

                    var comments = tmpData.Value.FindAll(f => f.FileName == fileName && f.RepositoryUrl == repositoryUrl && f.Provider == enumProvider && f.ChangesetId == revisionid);

                    if (comments != null)
                    {
                        model.data = tmpModel;
                        
                        model.comments = comments;
                    }
                }
                else
                {
                    model.data = tmpModel;
                    
                    model.comments = new List<Comment>();
                }

                data = RenderPartialViewToString(this, AppManager.Instance.GetAppUrl("F473D13E-19B7-45F3-98ED-6ED77B6BAB0A", "views/diff.cshtml"), model);                
            }
            else
            {
                data = authenticateForm;            
            }

            return JsonSuccess(new { authenticationSuccess = IsUserAuthorized, fileid = fileid, data = data, isFileIdMissing = isFileIdMissing, errorMessage = errorMessage });         
        }

        public ActionResult AddComment(int issueId)
        {
            IssueWidgetData<List<Comment>> data = GeminiContext.IssueWidgetStore.Get<List<Comment>>(issueId, Constants.AppId, Constants.ControlId);
            
            var formComment = Request.Form["comment"] ?? String.Empty;
            
            var formLineNumber = Request.Form["linenr"] ?? String.Empty;
            
            var formChangesetId = Request.Form["changesetid"] ?? String.Empty;
            
            var formFileId = Request.Form["fileid"] ?? String.Empty;
            
            var formFileName = Request.Form["filename"] ?? String.Empty;
            
            var formProvider = Request.Form["provider"] ?? String.Empty;
            
            var formRepositoryUrl = Request.Form["repositoryurl"] ?? String.Empty;

            bool isDeleted = false;

            if (!formFileName.IsEmpty() && !formLineNumber.IsEmpty() && !formRepositoryUrl.IsEmpty())
            {
                Comment comment = new Comment();

                comment.ChangesetId = formChangesetId;
                
                comment.Date = DateTime.Now;
                
                comment.Fullname = UserContext.User.Fullname;
                
                comment.Message = formComment;
                
                comment.LineNumber = formLineNumber;
                
                comment.FileName = formFileName;
                
                comment.FileId = formFileId;
                
                comment.RepositoryUrl = formRepositoryUrl;

                SourceControlProvider Provider;

                try
                {
                    Provider = (SourceControlProvider)Enum.Parse(typeof(SourceControlProvider), formProvider,true);
                }
                catch(ArgumentException ex)
                {
                    Provider = SourceControlProvider.GitHub; //TODO maybe change to zero for default ? Check with saar
                }

                comment.Provider = Provider;

                // If it's the first comment, setup a new comment list
                if (data == null)
                {
                    data = new IssueWidgetData<List<Comment>>();
                    
                    data.Value = new List<Comment>();

                    data.Value.Add(comment);
                    
                    data.IssueId = issueId;
                    
                    GeminiContext.IssueWidgetStore.Save(data.IssueId, Constants.AppId, Constants.ControlId, data.Value); 
                }
                else
                {
                    var tmpComment = data.Value.Find(f => f.FileName == formFileName && f.Provider == Provider && f.LineNumber == formLineNumber && f.RepositoryUrl == formRepositoryUrl && f.ChangesetId == formChangesetId);
                    // IF current code line was already commented on, get comment and update message
                    if (tmpComment != null)
                    {
                        var index = data.Value.FindIndex(f => f.FileName == formFileName && f.Provider == Provider && f.LineNumber == formLineNumber && f.RepositoryUrl == formRepositoryUrl && f.ChangesetId == formChangesetId);

                        // If new message is empty, remove comment from DB
                        if (formComment.IsEmpty())
                        {
                            data.Value.RemoveAt(index);     
                            
                            data.IssueId = issueId;                            
                            
                            isDeleted = true;
                        }
                        else
                        {
                            data.Value[index].Message = formComment;
                            
                            data.IssueId = issueId;                            
                        } 
                    }
                    else
                    {  
                        // Add a new comment
                        data.Value.Add(comment);
                        
                        data.IssueId = issueId;                       
                    }

                    GeminiContext.IssueWidgetStore.Save(data.IssueId, Constants.AppId, Constants.ControlId, data.Value); 
                }

                return JsonSuccess(new { isdeleted = isDeleted });
            }
            else
            {
                return JsonError();
            }        
        }

        public ActionResult GetComment(int issueId)
        {
            IssueWidgetData<List<Comment>> data = GeminiContext.IssueWidgetStore.Get<List<Comment>>(issueId, Constants.AppId, Constants.ControlId);
           
            var formLinenumber = Request.Form["linenr"] ?? String.Empty;
            
            var formFileName = Request.Form["filename"] ?? String.Empty;
            
            var formChangesetId = Request.Form["changesetid"] ?? String.Empty;
            
            var formFileId = Request.Form["fileid"] ?? String.Empty;
            
            var formProvider = Request.Form["provider"] ?? String.Empty;
            
            var formRepositoryUrl = Request.Form["repositoryurl"] ?? String.Empty;

            SourceControlProvider Provider;

            try
            {
                Provider = (SourceControlProvider)Enum.Parse(typeof(SourceControlProvider), formProvider,true);
            }
            catch (ArgumentException)
            {
                Provider = SourceControlProvider.GitHub; //TODO maybe change to zero for default ? Check with saar
            }

            var comment = new Comment();            

            if (data != null)
            {
                comment = data.Value.Find((f => f.FileName == formFileName && f.Provider == Provider && f.LineNumber == formLinenumber && f.RepositoryUrl == formRepositoryUrl && f.ChangesetId == formChangesetId));
            }     
            
            return JsonSuccess( new { comment = comment });
        }

        public static void InitiateSSLTrust()
        {
            try
            {
                if (!_sslInitialised)
                {
                    _sslInitialised = true;
                    //Change SSL checks so that all checks pass
                    ServicePointManager.ServerCertificateValidationCallback =
                        new RemoteCertificateValidationCallback(
                            delegate
                            { return true; }
                        );
                }
            }
            catch (Exception ex)
            {
                GeminiApp.LogException(ex, false);
            }
        }
    }
}
