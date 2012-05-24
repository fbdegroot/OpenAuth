using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using OpenAuth.Infrastructure;
using OpenAuth.Models;
using System.Net;
using System.Configuration;

namespace OpenAuth.Consumers
{
	public class FacebookClient
	{
		public enum Scope
		{
			None = 0,
			[Value("email")]
			Email = 1,
			[Value("user_birthday")]
			Birthday = 2,
			[Value("publish_stream")]
			Publish = 4
		}

		public enum Display
		{
			[Value("page")]
			Page,
			[Value("popup")]
			Popup,
			[Value("touch")]
			Touch
		}

		private static Uri AuthorizeEndpoint = new Uri("https://www.facebook.com/dialog/oauth");
		private static Uri AccessTokenEndpoint = new Uri("https://graph.facebook.com/oauth/access_token");
		private static Uri UserInfoEndpoint = new Uri("https://graph.facebook.com/me");

		private static Uri FriendsEndpoint = new Uri("https://graph.facebook.com/me/friends");
		private static Uri FeedEndpoint = new Uri("https://graph.facebook.com/me/feed");

		private static JsonSerializer jsonSerializer;

		private static string clientId = ConfigurationManager.AppSettings["FacebookClientID"];
		private static string clientSecret = ConfigurationManager.AppSettings["FacebookClientSecret"];
		private static string scopeDelimiter = ",";

		static FacebookClient()
		{
			jsonSerializer = JsonSerializer.Create(new JsonSerializerSettings { });
		}

		public static string Auth(string callbackUrl, string state, Scope scope = Scope.None, Display display = Display.Page)
		{
			var parameters = new List<Parameter> {
				new Parameter { Name = OAuth2Parameter.ConsumerID.Value(), Value = clientId },
				new Parameter { Name = OAuth2Parameter.CallbackUrl.Value(), Value = callbackUrl },
				new Parameter { Name = OAuth2Parameter.State.Value(), Value = state }
			};

			if (display != Display.Page)
				parameters.Add(new Parameter { Name = OAuth2Parameter.Display.Value(), Value = display.Value() });

			if (scope != Scope.None) {
				var permissionNames = new List<string>();
				if ((scope & Scope.Email) == Scope.Email)
					permissionNames.Add(Scope.Email.Value());
				if ((scope & Scope.Birthday) == Scope.Birthday)
					permissionNames.Add(Scope.Birthday.Value());
				if ((scope & Scope.Publish) == Scope.Publish)
					permissionNames.Add(Scope.Publish.Value());

				if (permissionNames.Count > 0)
					parameters.Insert(0, new Parameter { Name = OAuth2Parameter.Scope.Value(), Value = string.Join(scopeDelimiter, permissionNames) });
			}

			return Utils.CreateUri(AuthorizeEndpoint, parameters).AbsoluteUri;
		}
		public static OpenAuthAccessToken ProcessCallback()
		{
			if (HttpContext.Current.Request.QueryString.AllKeys.Contains("error_reason") &&
				HttpContext.Current.Request.QueryString["error_reason"] == "user_denied")
				throw new OpenAuthException { Error = OpenAuthErrorType.UserDenied };

			if (!HttpContext.Current.Request.QueryString.AllKeys.Contains(OAuth2Parameter.Code.Value()))
				throw new OpenAuthException { Error = OpenAuthErrorType.MissingKeys };

			string code = HttpContext.Current.Request.QueryString[OAuth2Parameter.Code.Value()];
			string guid = HttpContext.Current.Request.QueryString[OAuth2Parameter.Guid.Value()];

			string response = Request(HttpMethod.Get, AccessTokenEndpoint, new List<Parameter> {
				 new Parameter { Name = OAuth2Parameter.ConsumerID.Value(), Value = clientId },
				 new Parameter { Name = OAuth2Parameter.ConsumerSecret.Value(), Value = clientSecret },
				 new Parameter { Name = OAuth2Parameter.Code.Value(), Value = code },
				 new Parameter { Name = OAuth2Parameter.CallbackUrl.Value(), Value = OpenAuthConfiguration.CallbackUrl }
			});

			NameValueCollection data = HttpUtility.ParseQueryString(response);
			return new OpenAuthAccessToken {
				Token = data[OAuth2Parameter.AccessToken.Value()]
			};
		}

		public static OpenAuthUser GetUserInfo(string accessToken)
		{
			string response = Request(HttpMethod.Get, UserInfoEndpoint, new List<Parameter> {
				 new Parameter { Name = OAuth2Parameter.AccessToken.Value(), Value = accessToken }
			});

			JObject data = JObject.Parse(response);
			var user = new OpenAuthUser {
				ID = data["id"].Value<string>(),
				FullName = data["name"].Value<string>(),
				FirstName = data["first_name"].Value<string>(),
				LastName = data["last_name"].Value<string>(),
				DisplayName = data["name"].Value<string>(),
				Email = data["email"] != null ? data["email"].Value<string>() : null,
				Link = data["link"].Value<string>(),
				Gender = data["gender"] != null ? data["gender"].Value<string>() == "male" ? OpenAuthGender.Male : OpenAuthGender.Female : (OpenAuthGender?)null,
				PictureUrl = string.Format("http://graph.facebook.com/{0}/picture?type=large", data["id"].Value<string>())
			};

			if (data["hometown"] != null)
				user.Location = data["hometown"]["name"].Value<string>();
			else if (data["location"] != null)
				user.Location = data["location"]["name"].Value<string>();

			return user;
		}
		public static IEnumerable<OpenAuthFriend> GetFriends(string accessToken)
		{
			string response = Request(HttpMethod.Get, FriendsEndpoint, new List<Parameter> {
				 new Parameter { Name = OAuth2Parameter.AccessToken.Value(), Value = accessToken }
			});

			JObject data = JObject.Parse(response);
			return (data["data"] as JArray).Select(friend => new OpenAuthFriend {
				ID = friend["id"].Value<string>(),
				Name = friend["name"].Value<string>()
			});
		}
		public static void Post(string accessToken, string message)
		{
			string response = Request(HttpMethod.Post, FeedEndpoint, new List<Parameter> {
				new Parameter { Name = OAuth2Parameter.AccessToken.Value(), Value = accessToken },
				new Parameter { Name = OAuth2Parameter.Message.Value(), Value = message, Type = ParameterType.Post }
			});

			var data = JObject.Parse(response);
			if (data.Count != 1 || data["id"] == null)
				throw new OpenAuthException { Error = OpenAuthErrorType.Unknown };
		}

		private static string Request(HttpMethod httpMethod, Uri uri, List<Parameter> parameters)
		{
			try {
				return Utils.Request(httpMethod, uri, parameters);
			}
			catch (OpenAuthException ex) {
				if (ex.HttpStatusCode == HttpStatusCode.BadRequest || ex.HttpStatusCode == HttpStatusCode.Forbidden) {
					if (string.IsNullOrWhiteSpace(ex.Response) == false) {
						var data = JObject.Parse(ex.Response);

						if (data["error"] != null && data["error"]["code"] != null) {
							switch (data["error"]["code"].Value<int>()) {
								case 190:	// invalid OAuth access token
								case 2500:	// an active access token must be used to query information about the current user
									ex.Error = OpenAuthErrorType.InvalidOrExpiredAccessToken;
									break;
								case 200:	// the user hasn't authorized the application to perform this action
									ex.Error = OpenAuthErrorType.ScopeUnauthorized;
									break;
								case 506:	// posted the same message twice
									ex.Error = OpenAuthErrorType.DuplicateMessage;
									break;
							}
						}
					}
				}

				throw ex;
			}
		}
	}
}