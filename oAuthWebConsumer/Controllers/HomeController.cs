using System;
using System.Net;
using System.Web.Mvc;

using DotNetOpenAuth.Messaging;
using DotNetOpenAuth.OAuth2;

using OAuthShared;

namespace oAuthWebConsumer.Controllers
{
    public class HomeController : Controller
    {
        private const string ClientId = "samplewebapiconsumer";
        private const string ClientSecret = "samplesecret";
        private const string ApiEndpoint = "http://localhost:30777/api/values";
        private const string AuthorizationEndpoint = "http://localhost:30777/OAuth/Authorise";
        private const string TokenEndpoint = "http://localhost:30777/OAuth/Token";
        private const string AuthorizationCallback = "http://localhost:40551/";

        public IAuthorizationState Authorization { get; private set; }

        public UserAgentClient Client { get; set; }

        public HomeController()
        {
            var authServer = new AuthorizationServerDescription
                {
                    AuthorizationEndpoint = new Uri(AuthorizationEndpoint),
                    TokenEndpoint = new Uri(TokenEndpoint),
                };

            Client = new UserAgentClient(authServer, ClientId, ClientSecret);
            Authorization = new AuthorizationState
                {
                    Callback = new Uri(AuthorizationCallback)
                };
        }

        /// <summary>
        /// Check if we have a code that means it is a return from an oAuth redirect where we want to 
        /// pass the code to the server and make the oAuth call. In this case the code is used for a
        /// one time only call and will change upon every refresh.
        /// </summary>
        /// <returns></returns>
        public ActionResult Index()
        {
            if (!string.IsNullOrEmpty(Request.QueryString["code"]))
            {
                try
                {
                    Client.ProcessUserAuthorization(Request.Url, Authorization);
                    var valueString = string.Empty;
                    if (!string.IsNullOrEmpty(Authorization.AccessToken))
                    {
                        valueString = CallApi(Authorization);
                    }

                    ViewBag.Values = valueString;
                }
                catch (ProtocolException)
                {
                }
            }

            return View();
        }

        /// <summary>
        /// A method that calls onto the API from the server using the code that has been retrieved using
        /// a previous oAuth call.
        /// </summary>
        /// <param name="authorization"></param>
        /// <returns></returns>
        private string CallApi(IAuthorizationState authorization)
        {
            string valueString;
            using (var webClient = new WebClient())
            {
                webClient.Headers["Content-Type"] = "application/json";
                webClient.Headers["X-JavaScript-User-Agent"] = "API Explorer";
                Client.AuthorizeRequest(webClient, Authorization);
                valueString = webClient.DownloadString(ApiEndpoint);
            }

            return valueString;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public JsonResult GetValues()
        {
            var isOK = false;
            var requiresAuth = false;
            var redirectUrl = string.Empty;
            if (Session["AccessToken"] == null)
            {
                Authorization.Scope.AddRange(OAuthUtilities.SplitScopes(ApiEndpoint));
                Uri authorizationUrl = Client.RequestUserAuthorization(Authorization);
                requiresAuth = true;
                redirectUrl = authorizationUrl.AbsoluteUri;
                isOK = true;
            }

            return new JsonResult
                {
                    Data = new
                    {
                        OK = isOK,
                        RequiresAuth = requiresAuth,
                        RedirectURL = redirectUrl
                    }
                };
        }
    }
}
