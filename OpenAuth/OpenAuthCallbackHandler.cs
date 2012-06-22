using System;
using System.Linq;
using System.Web;
using System.Web.SessionState;
using Newtonsoft.Json;
using OpenAuth.Consumers;
using OpenAuth.Infrastructure;
using OpenAuth.Models;

namespace OpenAuth
{
	public class OpenAuthCallbackHandler : IHttpHandler, IRequiresSessionState
	{
		private const string closePopupHtml = "<html><head><script type=\"text/javascript\">window.close();</script></head><body></body></html>";
		private const string closePopupHtmlWithResult = "<html><head><script type=\"text/javascript\">opener.result = {0};window.close();</script></head><body></body></html>";

		void IHttpHandler.ProcessRequest(HttpContext context)
		{
			if (context.Request.QueryString.AllKeys.Contains(OAuth2Parameter.State.Value()) == false)
				throw new OpenAuthException { Error = OpenAuthErrorType.CrossSiteRequestForgery };

			string state = context.Request.QueryString["state"];

			OpenAuthSession session;
			OpenAuthSessionRepository.Sessions.TryRemove(state, out session);

			if (session == null)
				throw new OpenAuthException { Error = OpenAuthErrorType.CrossSiteRequestForgery };

			try {
				OpenAuthAccessToken accessToken;
				OpenAuthUser userInfo;
				switch (session.Provider) {
					case OpenAuthProvider.Facebook:
						accessToken = FacebookClient.ProcessCallback();
						userInfo = FacebookClient.GetUserInfo(accessToken.Token);
						break;
					case OpenAuthProvider.Google:
						accessToken = GoogleClient.ProcessCallback();
						userInfo = GoogleClient.GetUserInfo(accessToken.Token);
						break;
					case OpenAuthProvider.Live:
						accessToken = LiveClient.ProcessCallback();
						userInfo = LiveClient.GetUserInfo(accessToken.Token);
						break;
					case OpenAuthProvider.Twitter:
						accessToken = TwitterClient.ProcessCallback();
						userInfo = TwitterClient.GetUserInfo(accessToken.Token, accessToken.TokenSecret);
						break;
					case OpenAuthProvider.LinkedIn:
						accessToken = LinkedInClient.ProcessCallback();
						userInfo = LinkedInClient.GetUserInfo(accessToken.Token, accessToken.TokenSecret);
						break;
					default:
						throw new NotImplementedException(session.Provider.ToString());
				}

				if (session.Callback != null) {
					session.Callback(userInfo, accessToken, context.User, context.Session, context.Response);
				}
				else if (session.ClosePopupCallback != null) {
					object result = session.ClosePopupCallback(userInfo, accessToken, context.User, context.Session, context.Response);

					if (result != null)
						context.Response.Write(string.Format(closePopupHtmlWithResult, JsonConvert.SerializeObject(result)));
					else
						context.Response.Write(closePopupHtml);
				}
			}
			catch (Exception ex) {
				if (session.ClosePopupCallback != null) {
					context.Response.Write(string.Format(closePopupHtmlWithResult, JsonConvert.SerializeObject(new {
						Success = false,
						Error = ex is OpenAuthException ? (ex as OpenAuthException).Error.ToString() : ex.Message
					})));
				}
				else {
					throw ex;
				}
			}
		}

		bool IHttpHandler.IsReusable
		{
			get { return true; }
		}
	}
}