﻿using System;
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
			return new RedirectResult(Auth(provider, scope, callback, null));
		}
		public static RedirectResult AuthClosePopup(OpenAuthProvider provider, Func<OpenAuthUser, OpenAuthAccessToken, IPrincipal, HttpSessionState, HttpResponse, object> callback)
		{
			return AuthClosePopup(provider, 0, callback);
		}
		public static RedirectResult AuthClosePopup(OpenAuthProvider provider, int scope, Func<OpenAuthUser, OpenAuthAccessToken, IPrincipal, HttpSessionState, HttpResponse, object> callback)
		{
			return new RedirectResult(Auth(provider, scope, null, callback));
		}
		private static string Auth(OpenAuthProvider provider, int scope, Action<OpenAuthUser, OpenAuthAccessToken, IPrincipal, HttpSessionState, HttpResponse> callback, Func<OpenAuthUser, OpenAuthAccessToken, IPrincipal, HttpSessionState, HttpResponse, object> closePopupCallback)
		{
			string state = Guid.NewGuid().ToString();
			OpenAuthSessionRepository.Sessions[state] = new OpenAuthSession {
				Callback = callback,
				ClosePopupCallback = closePopupCallback,
				Provider = provider
			};

			switch (provider) {
				case OpenAuthProvider.Facebook:
					return FacebookClient.Auth(OpenAuthConfiguration.CallbackUrl, state, (FacebookClient.Scope)scope, closePopupCallback != null ? FacebookClient.Display.Popup : FacebookClient.Display.Page);
				case OpenAuthProvider.Google:
					return GoogleClient.Auth(OpenAuthConfiguration.CallbackUrl, state, (GoogleClient.Scope)scope);
				case OpenAuthProvider.Twitter:
					return TwitterClient.Auth(OpenAuthConfiguration.CallbackUrl, state);
				default:
					throw new NotImplementedException(provider.ToString());
			}
		}

		public static IEnumerable<OpenAuthFriend> GetFriends(OpenAuthProvider provider, OpenAuthAccessToken token)
		{
			switch (provider) {
				case OpenAuthProvider.Facebook:
					return FacebookClient.GetFriends(token.Token);
				case OpenAuthProvider.Google:
					return GoogleClient.GetFriends(token.Token);
				case OpenAuthProvider.Twitter:
					return TwitterClient.GetFriends(token.Token, token.TokenSecret);
				default:
					throw new NotImplementedException();
			}
		}
	}
}