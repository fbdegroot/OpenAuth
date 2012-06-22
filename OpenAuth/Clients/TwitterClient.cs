using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web.Mvc;
using System.Collections.Concurrent;
using System.Web;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using OpenAuth.Models;
using OpenAuth.Infrastructure;
using System.Net;
using System.Configuration;

namespace OpenAuth.Consumers
{
	public static class TwitterClient
	{
		// 401: Invalid/expired token

		private static Uri RequestTokenEndpoint = new Uri("http://twitter.com/oauth/request_token");
		private static Uri AuthorizeEndpoint = new Uri("http://twitter.com/oauth/authenticate");
		private static Uri AccessTokenEndpoint = new Uri("http://twitter.com/oauth/access_token");

		private static Uri UserInfoEndpoint = new Uri("http://api.twitter.com/1/account/verify_credentials.json");
		private static Uri FriendsEndpoint = new Uri("http://api.twitter.com/1/friends/ids.json");
		private static Uri FollowersEndpoint = new Uri("http://api.twitter.com/1/followers/ids.json");
		private static Uri UpdateEndpoint = new Uri("http://api.twitter.com/1/statuses/update.json");

		private static ConcurrentDictionary<string, string> requestTokens;
		private static JsonSerializer jsonSerializer;

		public static string clientId = ConfigurationManager.AppSettings["TwitterClientID"];
		public static string clientSecret = ConfigurationManager.AppSettings["TwitterClientSecret"];

		static TwitterClient()
		{
			requestTokens = new ConcurrentDictionary<string, string>();
			jsonSerializer = JsonSerializer.Create(new JsonSerializerSettings { });
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
				new Parameter { Name = OAuthParameter.IncludeEntities.Value(), Value = false.ToString().ToLower() },
				new Parameter { Name = OAuthParameter.SkipStatus.Value(), Value = true.ToString().ToLower() }
			};

			string response = Request(HttpMethod.Get, UserInfoEndpoint, parameters, clientId, clientSecret, accessToken, accessTokenSecret);

			JObject data = JObject.Parse(response);
			return new OpenAuthUser {
				ID = data["id"].Value<string>(),
				FullName = data["name"].Value<string>(),
				DisplayName = data["screen_name"].Value<string>(),
				PictureUrl = string.Format("https://api.twitter.com/1/users/profile_image?size=original&screen_name={0}", data["screen_name"].Value<string>())
			};
		}
		public static IEnumerable<OpenAuthFriend> GetFriends(string accessToken, string accessTokenSecret)
		{
			string response = Request(HttpMethod.Get, FriendsEndpoint, null, clientId, clientSecret, accessToken, accessTokenSecret);

			JObject data = JObject.Parse(response);
			return (data["ids"] as JArray).Select(id => new OpenAuthFriend {
				ID = id.Value<string>()
			});
		}
		public static IEnumerable<OpenAuthFriend> GetFollowers(string accessToken, string accessTokenSecret)
		{
			string response = Request(HttpMethod.Get, FollowersEndpoint, null, clientId, clientSecret, accessToken, accessTokenSecret);

			JObject data = JObject.Parse(response);
			return (data["ids"] as JArray).Select(id => new OpenAuthFriend {
				ID = id.Value<string>()
			});
		}

		public static void Tweet(string accessToken, string accessTokenSecret, string message)
		{
			var parameters = new List<Parameter> {
				new Parameter { Name = OAuthParameter.Status.Value(), Value = message, Type = ParameterType.Post }
			};

			string response = Request(HttpMethod.Post, UpdateEndpoint, parameters, clientId, clientSecret, accessToken, accessTokenSecret);
		}

		public static string Request(HttpMethod httpMethod, Uri uri, List<Parameter> parameters, string consumerKey, string consumerSecret, string token, string tokenSecret, SignatureMethod signatureMethod = SignatureMethod.HMACSHA1)
		{
			try {
				return OAuth.Request(httpMethod, uri, parameters, consumerKey, consumerSecret, token, tokenSecret, signatureMethod);
			}
			catch (OpenAuthException ex) {
				switch (ex.HttpStatusCode) {
					case HttpStatusCode.BadRequest:
						ex.Error = OpenAuthErrorType.InvalidOrExpiredAccessToken;
						break;
				}

				throw ex;
			}
		}
	}
}