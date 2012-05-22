using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Web;
using System.Web.Mvc;
using OpenAuth.Consumers;
using OpenAuth.Models;
using System.Web.SessionState;

namespace OpenAuth
{
	public static class OpenAuthHelper
	{
		public static RedirectResult Auth(OpenAuthProvider provider, Action<OpenAuthUser, OpenAuthAccessToken, IPrincipal, HttpSessionState, HttpResponse> callback)
		{
			return Auth(provider, 0, callback);
		}
		public static RedirectResult Auth(OpenAuthProvider provider, int scope, Action<OpenAuthUser, OpenAuthAccessToken, IPrincipal, HttpSessionState, HttpResponse> callback)
		{
			return new RedirectResult(Auth(provider, scope, false, callback));
		}
		public static RedirectResult AuthClosePopup(OpenAuthProvider provider, Action<OpenAuthUser, OpenAuthAccessToken, IPrincipal, HttpSessionState, HttpResponse> callback)
		{
			return AuthClosePopup(provider, 0, callback);
		}
		public static RedirectResult AuthClosePopup(OpenAuthProvider provider, int scope, Action<OpenAuthUser, OpenAuthAccessToken, IPrincipal, HttpSessionState, HttpResponse> callback)
		{
			return new RedirectResult(Auth(provider, scope, true, callback));
		}
		private static string Auth(OpenAuthProvider provider, int scope, bool closePopup, Action<OpenAuthUser, OpenAuthAccessToken, IPrincipal, HttpSessionState, HttpResponse> callback)
		{
			string guid = Guid.NewGuid().ToString();
			string callbackUrl = OpenAuthConfiguration.CallbackProtocol + Uri.SchemeDelimiter + OpenAuthConfiguration.CallbackDomain + "/" + OpenAuthConfiguration.CallbackPath + "?guid=" + guid;
			OpenAuthSessionRepository.Sessions[guid] = new OpenAuthSession {
				ClosePopup = closePopup,
				Callback = callback,
				Provider = provider
			};

			switch (provider) {
				case OpenAuthProvider.Facebook:
					return FacebookClient.Auth(callbackUrl, (FacebookClient.Scope)scope);
				case OpenAuthProvider.Twitter:
					return TwitterClient.Auth(callbackUrl);
				default:
					throw new NotImplementedException(provider.ToString());
			}
		}

		public static IEnumerable<OpenAuthFriend> GetFriends(OpenAuthProvider provider, OpenAuthAccessToken token)
		{
			switch (provider) {
				case OpenAuthProvider.Facebook:
					return FacebookClient.GetFriends(token.Token);
				case OpenAuthProvider.Twitter:
					return TwitterClient.GetFriends(token.Token, token.TokenSecret);
				default:
					throw new NotImplementedException();
			}
		}
	}
}