using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using OpenAuth.Infrastructure;
using OpenAuth.Models;

namespace OpenAuth.Consumers
{
	public class LiveClient
	{
		public enum Scope
		{
			None,
			[Value("wl.basic")]
			Basic = 1,
			[Value("wl.emails")]
			Emails = 2,
			[Value("wl.birthday")]
			Birthday = 4
		}

		private static Uri AuthorizeEndpoint = new Uri("https://oauth.live.com/authorize");
		private static Uri AccessTokenEndpoint = new Uri("https://oauth.live.com/token");
		private static Uri UserInfoEndpoint = new Uri("https://apis.live.net/v5.0/me");

		// private static Uri ContactsEndpoint = new Uri("");

		private static JsonSerializer jsonSerializer;

		private static string clientId = ConfigurationManager.AppSettings["LiveClientID"];
		private static string clientSecret = ConfigurationManager.AppSettings["LiveClientSecret"];
		private static string scopeDelimiter = "+";

		static LiveClient()
		{
			jsonSerializer = JsonSerializer.Create(new JsonSerializerSettings { });
		}

		public static string Auth(string callbackUrl, string state, Scope scope = Scope.None)
		{
			var parameters = new List<Parameter> {
				new Parameter { Name = OAuth2Parameter.ConsumerID.Value(), Value = clientId },
				new Parameter { Name = OAuth2Parameter.CallbackUrl.Value(), Value = callbackUrl },
				new Parameter { Name = OAuth2Parameter.State.Value(), Value = state },
				new Parameter { Name = OAuth2Parameter.ResponseType.Value(), Value = "code" }
			};

			if (scope != Scope.None) {
				var permissionNames = new List<string>();
				if ((scope & Scope.Basic) == Scope.Basic)
					permissionNames.Add(Scope.Basic.Value());
				if ((scope & Scope.Emails) == Scope.Emails)
					permissionNames.Add(Scope.Emails.Value());
				if ((scope & Scope.Birthday) == Scope.Birthday)
					permissionNames.Add(Scope.Birthday.Value());

				if (permissionNames.Count > 0)
					parameters.Insert(0, new Parameter { Name = OAuth2Parameter.Scope.Value(), Value = string.Join(scopeDelimiter, permissionNames.Select(p => Utils.UrlEncode(p))), Encode = false });
			}

			return Utils.CreateUri(AuthorizeEndpoint, parameters).AbsoluteUri;
		}
		public static OpenAuthAccessToken ProcessCallback()
		{
			//if (HttpContext.Current.Request.QueryString.AllKeys.Contains("error_reason") &&
			//    HttpContext.Current.Request.QueryString["error_reason"] == "user_denied")
			//    throw new OpenAuthException { Error = OpenAuthErrorType.UserDenied };

			if (!HttpContext.Current.Request.QueryString.AllKeys.Contains(OAuth2Parameter.Code.Value()))
				throw new OpenAuthException { Error = OpenAuthErrorType.MissingKeys };

			string code = HttpContext.Current.Request.QueryString[OAuth2Parameter.Code.Value()];

			string response = Request(HttpMethod.Post, AccessTokenEndpoint, new List<Parameter> {
				 new Parameter { Name = OAuth2Parameter.ConsumerID.Value(), Value = clientId, Type = ParameterType.Post },
				 new Parameter { Name = OAuth2Parameter.ConsumerSecret.Value(), Value = clientSecret, Type = ParameterType.Post },
				 new Parameter { Name = OAuth2Parameter.Code.Value(), Value = code, Type = ParameterType.Post },
				 new Parameter { Name = OAuth2Parameter.CallbackUrl.Value(), Value = OpenAuthConfiguration.CallbackUrl, Type = ParameterType.Post },
				 new Parameter { Name = OAuth2Parameter.GrantType.Value(), Value = "authorization_code", Type = ParameterType.Post }
			});

			JObject data = JObject.Parse(response);
			return new OpenAuthAccessToken {
				Token = data[OAuth2Parameter.AccessToken.Value()].Value<string>()
			};
		}

		public static OpenAuthUser GetUserInfo(string accessToken)
		{
			string response = Request(HttpMethod.Get, UserInfoEndpoint, new List<Parameter> {
				 new Parameter { Name = OAuth2Parameter.AccessToken.Value(), Value = accessToken }
			});

			var data = JObject.Parse(response);
			var user = new OpenAuthUser {
				ID = data["id"].Value<string>(),
				FullName = data["name"].Value<string>(),
				FirstName = data["first_name"].Value<string>(),
				LastName = data["last_name"].Value<string>(),
				Link = data["link"].Value<string>(),
				Email = data["emails"]["preferred"].Value<string>()
			};

			switch (data["gender"].Value<string>()) {
				case "male": user.Gender = OpenAuthGender.Male; break;
				case "female": user.Gender = OpenAuthGender.Female; break;
			}

			return user;
		}
		public static IEnumerable<OpenAuthFriend> GetContacts(string accessToken)
		{
			throw new NotImplementedException();

			//string response = Request(HttpMethod.Get, ContactsEndpoint, new List<Parameter> {
			//    new Parameter { Name = OAuth2Parameter.AccessToken.Value(), Value = accessToken }
			//});

			//JObject data = JObject.Parse(response);
			//return (data["data"] as JArray).Select(friend => new OpenAuthFriend {
			//    ID = friend["id"].Value<string>(),
			//    Name = friend["name"].Value<string>()
			//});
		}

		private static string Request(HttpMethod httpMethod, Uri uri, List<Parameter> parameters)
		{
			try {
				return Utils.Request(httpMethod, uri, parameters);
			}
			catch (OpenAuthException ex) {
				throw ex;
			}
		}
	}
}