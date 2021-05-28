using Blazored.SessionStorage;
using ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect.Models;
using ITfoxtec.Identity.Messages;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace ITfoxtec.Identity.BlazorWebAssembly.OpenidConnect
{
    public class OidcAuthenticationStateProvider : AuthenticationStateProvider
    {
        private const string userSessionKey = "user_session";
        private readonly IServiceProvider serviceProvider;
        private readonly OpenidConnectPkceSettings openidClientPkceSettings;
        private readonly ISessionStorageService sessionStorage;

        public OidcAuthenticationStateProvider(IServiceProvider serviceProvider, OpenidConnectPkceSettings openidClientPkceSettings, ISessionStorageService sessionStorage)
        {
            this.serviceProvider = serviceProvider;
            this.openidClientPkceSettings = openidClientPkceSettings;
            this.sessionStorage = sessionStorage;
        }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            var user = await GetClaimsPrincipalAsync();
            return await Task.FromResult(new AuthenticationState(user));
        }

        protected async Task<ClaimsPrincipal> GetClaimsPrincipalAsync()
        {
            try
            {
                var userSession = await GetUserSessionAsync();
                if (userSession != null)
                {
                    return new ClaimsPrincipal(new ClaimsIdentity(userSession.Claims.Select(c => new Claim(c.Type, c.Value)), userSession.AuthenticationType, openidClientPkceSettings.NameClaimType, openidClientPkceSettings.RoleClaimType));
                }
                else
                {
                    return new ClaimsPrincipal(new ClaimsIdentity());
                }
            }
            catch (TokenUnavailableException)
            {
                return new ClaimsPrincipal(new ClaimsIdentity());
            }
        }

        public async Task<string> GetIdToken(bool readInvalidSession = false)
        {
            var userSession = await GetUserSessionAsync(readInvalidSession);
            return userSession?.IdToken;
        }
        public async Task<string> GetAccessToken(bool readInvalidSession = false)
        {
            var userSession = await GetUserSessionAsync(readInvalidSession);
            return userSession?.AccessToken;
        }

        public async Task<Dictionary<string, ResourceAccessToken>> GetAccessTokens(bool readInvalidSession = false)
        {
            var userSession = await GetUserSessionAsync(readInvalidSession);
            return userSession?.AccessTokens;
        }

        protected async Task<OidcUserSession> GetUserSessionAsync(bool readInvalidSession = false)
        {
            var userSession = await sessionStorage.GetItemAsync<OidcUserSession>(userSessionKey);
            if (userSession != null)
            {
                try
                {
                    userSession = await serviceProvider.GetService<OpenidConnectPkce>().HandleRefreshTokenAsync(userSession);

                    if (userSession.ValidUntil >= DateTimeOffset.UtcNow)
                    {
                        return userSession;
                    }
                    else
                    {
                        await DeleteSessionAsync();

                        if (readInvalidSession)
                        {
                            return userSession;
                        }
                    }
                }
                catch (TokenUnavailableException)
                {
                    await DeleteSessionAsync(false);
                    if (readInvalidSession)
                    {
                        return null;
                    }
                    else
                    {
                        throw;
                    }
                }
            }

            return null;
        }

        public Task<OidcUserSession> CreateSessionAsync(
            ClaimsPrincipal claimsPrincipal,
            string sessionState, 
            OpenidConnectPkceState openidClientPkceState,
            Dictionary<string, TokenResponse> tokenResponses,
            string unusedRefreshToken)
        {
            return CreateUpdateSessionAsync(claimsPrincipal, sessionState, openidClientPkceState.OidcDiscoveryUri, openidClientPkceState.ClientId, tokenResponses, unusedRefreshToken);
        }

        public Task<OidcUserSession> UpdateSessionAsync(DateTimeOffset validUntil, ClaimsPrincipal claimsPrincipal, TokenResponse tokenResponse, string sessionState, OidcUserSession userSession)
        {
            Console.WriteLine("UpdateSessionAsync - tokens will drop");
            //TODO: Session updates when access tokens expire not currently handled, but would replicate what happens after code exchange gets the first refresh token
            // Currently, we silently drops all the secondary tokens :-/
            var singleResourceResponses = new[] {tokenResponse}
                .ToDictionary(r => "", r => r);
            return CreateUpdateSessionAsync(claimsPrincipal, sessionState, userSession.OidcDiscoveryUri, userSession.ClientId, singleResourceResponses, tokenResponse.RefreshToken );
        }

        private async Task<OidcUserSession> CreateUpdateSessionAsync(
            ClaimsPrincipal claimsPrincipal, 
            string sessionState, 
            string oidcDiscoveryUri,
            string clientId,
            Dictionary<string, TokenResponse> tokenResponses,
            string unusedRefreshToken)
        {
            var claimsIdentity = claimsPrincipal.Identities.First();
            var claimsList = claimsIdentity.Claims.Select(c => new ClaimValue { Type = c.Type, Value = c.Value }).ToList();


            var tmpAccessTokens = tokenResponses
                .Select(tr => new
                {
                    //TODO: Transplant expires logic
                    Expires = DateTimeOffset.UtcNow.AddSeconds(tr.Value.ExpiresIn ?? 0),
                    AccessToken = tr.Value.AccessToken,
                    Resource = tr.Key,
                    IdToken = tr.Value.IdToken
                })
                .ToArray();
            var accessTokens = tmpAccessTokens
                .Select(tr => 
                    new ResourceAccessToken(
                        tr.Expires, 
                        tr.Resource, 
                        tr.AccessToken))
                .ToDictionary(rat => rat.Resource, rat => rat);

            var userSession = new OidcUserSession
            {
                ValidUntil = tmpAccessTokens.Select(at => at.Expires).Min(),
                Claims = claimsList,
                AuthenticationType = claimsIdentity.AuthenticationType,
                IdToken = tmpAccessTokens.First().IdToken,
                AccessToken = tmpAccessTokens.First().AccessToken,
                AccessTokens = accessTokens,
                RefreshToken = unusedRefreshToken,
                SessionState = sessionState,
                OidcDiscoveryUri = oidcDiscoveryUri,
                ClientId = clientId
            };
            await sessionStorage.SetItemAsync(userSessionKey, userSession);

            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
            return userSession;
        }

        public async Task DeleteSessionAsync(bool notify = true)
        {
            await sessionStorage.RemoveItemAsync(userSessionKey);

            if(notify)
            {
                NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
            }
        }
    }
}
