using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;

namespace OAuthConsoleConsumer
{
    public class OAuthHttpClient : HttpClient
    {
        public OAuthHttpClient(string accessToken)
            : base(new OAuthTokenHandler(accessToken))
        {
        }

        class OAuthTokenHandler : MessageProcessingHandler
        {
            readonly string _accessToken;
            public OAuthTokenHandler(string accessToken)
                : base(new HttpClientHandler())
            {
                _accessToken = accessToken;
            }

            protected override HttpRequestMessage ProcessRequest(
                HttpRequestMessage request, 
                CancellationToken cancellationToken)
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);
                return request;
            }

            protected override HttpResponseMessage ProcessResponse(
                HttpResponseMessage response, 
                CancellationToken cancellationToken)
            {
                return response;
            }
        }
    }
}
