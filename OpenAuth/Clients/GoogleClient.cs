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
	public class GoogleClient
	{
		public enum Scope
		{
			None = 0,
			[Value("https://www.googleapis.com/auth/userinfo.profile")]
			Profile = 1,
			[Value("https://www.googleapis.com/auth/userinfo.email")]
			Email = 2,
			[Value("https://www.google.com/m8/feeds")]
			Contacts = 4
		}

		public enum GoogleOAuth2Parameter
		{
			[Value("v")]
			Version
		}

		private static Uri AuthorizeEndpoint = new Uri("https://accounts.google.com/o/oauth2/auth");
		private static Uri AccessTokenEndpoint = new Uri("https://accounts.google.com/o/oauth2/token");
		private static Uri UserInfoEndpoint = new Uri("https://www.googleapis.com/oauth2/v1/userinfo");

		private static Uri ContactsEndpoint = new Uri("https://www.google.com/m8/feeds/contacts/default/full");
		
		private static JsonSerializer jsonSerializer;

		private static string clientId = ConfigurationManager.AppSettings["GoogleClientID"];
		private static string clientSecret = ConfigurationManager.AppSettings["GoogleClientSecret"];
		private static string scopeDelimiter = "+";

		static GoogleClient()
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
				if ((scope & Scope.Profile) == Scope.Profile)
					permissionNames.Add(Scope.Profile.Value());
				if ((scope & Scope.Email) == Scope.Email)
					permissionNames.Add(Scope.Email.Value());
				if ((scope & Scope.Contacts) == Scope.Contacts)
					permissionNames.Add(Scope.Contacts.Value());

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

			JObject data = JObject.Parse(response);
			var user = new OpenAuthUser {
				ID = data["id"].Value<string>(),
				FullName = data["name"].Value<string>(),
				FirstName = data["given_name"].Value<string>(),
				LastName = data["family_name"].Value<string>(),
				DisplayName = data["name"].Value<string>(),
				Link = data["link"] != null ? data["link"].Value<string>() : null,
				Email = data["email"] != null ? data["email"].Value<string>() : null,
				// PictureUrl = string.Format("https://profiles.google.com/s2/photos/profile/{0}", data["id"].Value<string>())
			};

			if (data["gender"] != null) {
				switch (data["gender"].Value<string>()) {
					case "male": user.Gender = OpenAuthGender.Male; break;
					case "female": user.Gender = OpenAuthGender.Female; break;
				}
			}

			return user;
		}
		public static IEnumerable<OpenAuthFriend> GetContacts(string accessToken)
		{
			throw new NotImplementedException();

			//string response = Request(HttpMethod.Get, ContactsEndpoint, new List<Parameter> {
			//    new Parameter { Name = OAuth2Parameter.AccessToken.Value(), Value = accessToken },
			//    new Parameter { Name = GoogleOAuth2Parameter.Version.Value(), Value = "3.0" }
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