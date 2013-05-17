using System;
using System.Net;

using DotNetOpenAuth.OAuth2;

namespace OAuthConsoleConsumer
{
    public static class ResourceOwnerCredentials
    {
        private const string ClientId = "samplewebapiconsumer";
        private const string ClientSecret = "samplesecret";
        private const string TestUsername = "steven";
        private const string TestPassword = "pwd";
        private const string ApiEndpoint = "http://localhost:30777/api/values";
        private const string TokenEndpoint = "http://localhost:30777/OAuth/Token";

        public static void Run()
        {
            Console.WriteLine("Enter to run Resource Owner Credentials demo.");

            #region initial request

            // get an access token for the username and password
            var authorizationState = GetAccessToken();

            var tokenExpiration = authorizationState.AccessTokenExpirationUtc;
            var token = authorizationState.AccessToken;
            var refresh = authorizationState.RefreshToken;

            Console.WriteLine("Expires = {0}", tokenExpiration);
            Console.WriteLine();
            Console.WriteLine("Token = {0}", token);
            Console.WriteLine();
            Console.WriteLine("Refresh Token = {0}", refresh);
            Console.WriteLine();

            #region sych request

            Console.WriteLine("");
            Console.WriteLine("Hit a key to make a sychronous request.");
            Console.WriteLine("");
            Console.ReadKey();

            var webRequest = (HttpWebRequest)WebRequest.Create(ApiEndpoint);
            webRequest.Headers.Add("Authorization", "Bearer " + token);
            WebResponse webResponse = webRequest.GetResponse();
            var myReqRespStream = new System.IO.StreamReader(webResponse.GetResponseStream());

            Console.WriteLine(myReqRespStream.ReadToEnd());
            Console.WriteLine("");
            Console.WriteLine("Request Complete.");
            Console.ReadKey();
            Console.WriteLine("");

            #endregion

            // get a reference to the access token
            var httpClient = new OAuthHttpClient(token)
            {
                BaseAddress = new Uri(ApiEndpoint)
            };

            Console.WriteLine("Calling web api...");
            Console.WriteLine("...");

            // make the request
            var response = httpClient.GetAsync("").Result;
            Console.WriteLine("Got Response");

            // if ok write the result
            Console.WriteLine(response.StatusCode == HttpStatusCode.OK
                                  ? response.Content.ReadAsStringAsync().Result
                                  : "Error");

            Console.WriteLine();
            /*  */
            #endregion

            #region refreshing

            Console.WriteLine("Refreshing token ...");

            // first update the state to get a new token
            authorizationState = GetAccessToken(authorizationState.RefreshToken);

            tokenExpiration = authorizationState.AccessTokenExpirationUtc;
            token = authorizationState.AccessToken;
            refresh = authorizationState.RefreshToken;

            Console.WriteLine("Refresh Expires = {0}", tokenExpiration);
            Console.WriteLine();
            Console.WriteLine("Token = {0}", token);
            Console.WriteLine();

            httpClient = new OAuthHttpClient(token)
            {
                BaseAddress = new Uri(ApiEndpoint)
            };

            Console.WriteLine("Enter to call web api...");
            Console.WriteLine("...");

            // make the request
            response = httpClient.GetAsync("").Result;
            Console.WriteLine("Got Response");

            // if ok write the result
            if (response.StatusCode == HttpStatusCode.OK)
            {
                Console.WriteLine(response.Content.ReadAsStringAsync().Result);
            }
            else
            {
                Console.WriteLine("Error");
            }

            Console.WriteLine();
            Console.WriteLine("Finished calling API with refresh token");
            Console.WriteLine();

            #endregion

            Console.WriteLine();
            Console.WriteLine("Done");
            Console.ReadLine();
        }

        private static IAuthorizationState GetAccessToken()
        {
            return GetAccessToken(null);
        }

        private static IAuthorizationState GetAccessToken(string refresh)
        {
            var authorizationServer = new AuthorizationServerDescription
            {
                TokenEndpoint = new Uri(TokenEndpoint),
                ProtocolVersion = ProtocolVersion.V20,
            };

            // get a reference to the auth server
            var client = new UserAgentClient(authorizationServer, ClientId, ClientSecret);

            // now get a token
            IAuthorizationState authorizationState;
            if (refresh == null)
            {
                authorizationState = 
                    client.ExchangeUserCredentialForToken(TestUsername, TestPassword, new[] { ApiEndpoint });
            }
            else
            {
                // we had previously authenticated so we can use the token rather than the credentials to get a new access token
                authorizationState = new AuthorizationState(new[] { ApiEndpoint })
                    {
                        RefreshToken = refresh
                    };
                client.RefreshAuthorization(authorizationState);
            }

            // return result
            return authorizationState;
        }
    }
}
