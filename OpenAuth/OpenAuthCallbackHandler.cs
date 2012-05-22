using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Mvc;
using System.Web.SessionState;
using OpenAuth.Consumers;
using OpenAuth.Models;

namespace OpenAuth
{
	public class OpenAuthCallbackHandler : IHttpHandler, IRequiresSessionState
	{
		void IHttpHandler.ProcessRequest(HttpContext context)
		{
			if (context.Request.QueryString.AllKeys.Contains("guid") == false)
				throw new OpenAuthException { Error = OpenAuthErrorType.CrossSiteRequestForgery };

			string guid = context.Request.QueryString["guid"];

			OpenAuthSession session;
			OpenAuthSessionRepository.Sessions.TryRemove(guid, out session);

			if (session == null)
				throw new OpenAuthException { Error = OpenAuthErrorType.CrossSiteRequestForgery };

			OpenAuthAccessToken accessToken;
			OpenAuthUser userInfo;
			switch (session.Provider) {
				case OpenAuthProvider.Facebook:
					accessToken = FacebookClient.ProcessCallback();
					userInfo = FacebookClient.GetUserInfo(accessToken.Token);
					break;
				case OpenAuthProvider.Twitter:
					accessToken = TwitterClient.ProcessCallback();
					userInfo = TwitterClient.GetUserInfo(accessToken.Token, accessToken.TokenSecret);
					break;
				default:
					throw new NotImplementedException(session.Provider.ToString());
			}

			session.Callback(userInfo, accessToken, context.User, context.Session, context.Response);
			if (session.ClosePopup)
				context.Response.Write("<html><head><script type=\"text/javascript\">window.close();</script></head><body></body></html>");
		}

		bool IHttpHandler.IsReusable
		{
			get { return true; }
		}
	}
}