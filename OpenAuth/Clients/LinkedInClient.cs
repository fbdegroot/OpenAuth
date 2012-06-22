using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;
using Newtonsoft.Json.Linq;
using OpenAuth.Infrastructure;
using OpenAuth.Models;

namespace OpenAuth.Consumers
{
	public static class LinkedInClient
	{
		// 401: Invalid/expired token

		private static Uri RequestTokenEndpoint = new Uri("https://api.linkedin.com/uas/oauth/requestToken");
		private static Uri AuthorizeEndpoint = new Uri("https://api.linkedin.com/uas/oauth/authorize");
		private static Uri AccessTokenEndpoint = new Uri("https://api.linkedin.com/uas/oauth/accessToken");

		private static Uri UserInfoEndpoint = new Uri("http://api.linkedin.com/v1/people/~:(id,first-name,last-name,location:(name),picture-url)");

		private static ConcurrentDictionary<string, string> requestTokens;

		public static string clientId = ConfigurationManager.AppSettings["LinkedInClientID"];
		public static string clientSecret = ConfigurationManager.AppSettings["LinkedInClientSecret"];

		static LinkedInClient()
		{
			requestTokens = new ConcurrentDictionary<string, string>();
		}

		public static string Auth(string callbackUrl, string state)
		{
			callbackUrl += "?state=" + state;
			var requestToken = OAuth.GetRequestToken(RequestTokenEndpoint, clientId, clientSecret, callbackUrl);

			requestTokens[requestToken.Token] = requestToken.TokenSecret;

			Uri redirectUrl = Utils.CreateUri(AuthorizeEndpoint, new List<Parameter> {
				new Parameter { Name = OAuthParameter.Token.Value(), Value = requestToken.Token }
			});

			return redirectUrl.AbsoluteUri;
		}
		public static OpenAuthAccessToken ProcessCallback()
		{
			if (!HttpContext.Current.Request.QueryString.AllKeys.Contains(OAuthParameter.Token.Value()) ||
				!HttpContext.Current.Request.QueryString.AllKeys.Contains(OAuthParameter.Verifier.Value()))
				throw new OpenAuthException { Error = OpenAuthErrorType.MissingKeys };

			string token = HttpContext.Current.Request.QueryString[OAuthParameter.Token.Value()];
			string verifier = HttpContext.Current.Request.QueryString[OAuthParameter.Verifier.Value()];

			return OAuth.GetAccessToken(AccessTokenEndpoint, clientId, clientSecret, token, requestTokens[token], verifier);
		}

		public static OpenAuthUser GetUserInfo(string accessToken, string accessTokenSecret)
		{
			var parameters = new List<Parameter> {
				new Parameter { Name = OAuthParameter.Format.Value(), Value = "json" }
			};

			string response = Request(HttpMethod.Get, UserInfoEndpoint, parameters, clientId, clientSecret, accessToken, accessTokenSecret);

			JObject data = JObject.Parse(response);
			return new OpenAuthUser {
				ID = data["id"].Value<string>(),
				DisplayName = data["firstName"].Value<string>() + " " + data["lastName"].Value<string>(),
				FullName = data["firstName"].Value<string>() + " " + data["lastName"].Value<string>(),
				FirstName = data["firstName"].Value<string>(),
				LastName = data["lastName"].Value<string>(),
				Location = data["location"] != null && data["location"]["name"] != null ? data["location"]["name"].Value<string>() : null,
				PictureUrl = data["pictureUrl"] != null ? data["pictureUrl"].Value<string>() : null
			};
		}
		public static IEnumerable<OpenAuthFriend> GetFriends(string accessToken, string accessTokenSecret)
		{
			throw new NotImplementedException();

			//string response = Request(HttpMethod.Get, FriendsEndpoint, null, clientId, clientSecret, accessToken, accessTokenSecret);

			//JObject data = JObject.Parse(response);
			//return (data["ids"] as JArray).Select(id => new OpenAuthFriend {
			//    ID = id.Value<string>()
			//});
		}

		public static string Request(HttpMethod httpMethod, Uri uri, List<Parameter> parameters, string consumerKey, string consumerSecret, string token, string tokenSecret, SignatureMethod signatureMethod = SignatureMethod.HMACSHA1)
		{
			try {
				return OAuth.Request(httpMethod, uri, parameters, consumerKey, consumerSecret, token, tokenSecret, signatureMethod);
			}
			catch (OpenAuthException ex) {
				throw ex;
			}
		}
	}
}