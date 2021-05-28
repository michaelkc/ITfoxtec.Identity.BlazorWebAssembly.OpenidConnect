using System;

namespace ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect
{
    public class ResourceAccessToken
    {
        // For serialization
        public ResourceAccessToken()
        {

        }
        public ResourceAccessToken(DateTimeOffset expires, string resource, string accessToken)
        {
            this.Expires = expires;
            this.Resource = resource;
            this.AccessToken = accessToken;
        }

        public DateTimeOffset Expires { get; set; }
        public string Resource { get;  set; }
        public string AccessToken { get; set; }
    }
}