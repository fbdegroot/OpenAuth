using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using OpenAuth.Infrastructure;
using System.Web;
using System.Collections.Specialized;

namespace OpenAuth
{
	public enum HttpMethod
	{
		[Value("GET")]
		Get,
		[Value("POST")]
		Post
	}
	public enum SignatureMethod
	{
		[Value("HMAC-SHA1")]
		HMACSHA1,
		[Value("RSA-SHA1")]
		RSASHA1,
		[Value("PLAINTEXT")]
		Plaintext
	}
	internal enum OAuthParameter
	{
		[Value("oauth_consumer_key")]
		ConsumerKey,
		[Value("oauth_signature_method")]
		SignatureMethod,
		[Value("oauth_signature")]
		Signature,
		[Value("oauth_timestamp")]
		Timestamp,
		[Value("oauth_nonce")]
		Nonce,
		[Value("oauth_version")]
		Version,
		[Value("oauth_callback")]
		Callback,
		[Value("oauth_verifier")]
		Verifier,
		[Value("oauth_token")]
		Token,
		[Value("oauth_token_secret")]
		TokenSecret,
		[Value("oauth_callback_confirmed")]
		CallbackConfirmed,
		[Value("include_entities")]
		IncludeEntities,
		[Value("skip_status")]
		SkipStatus,
		[Value("status")]
		Status
	}

	internal static class OAuth
	{
		private const string OAuthVersion = "1.0";
		private const string OAuthProtocolParameterPrefix = "oauth_";

		private static string GenerateTimeStamp()
		{
			TimeSpan ts = DateTime.UtcNow - new DateTime(1970, 1, 1);
			return Math.Truncate(ts.TotalSeconds).ToString();
		}
		private static string GenerateNonce(string timestamp)
		{
			var buffer = new byte[256];
			Random random = new Random();
			random.NextBytes(buffer);
			var hmacsha1 = new HMACSHA1();
			hmacsha1.Key = Encoding.ASCII.GetBytes(Encoding.ASCII.GetString(buffer));
			return ComputeHash(hmacsha1, timestamp);
		}
		private static string ComputeHash(HashAlgorithm hashAlgorithm, string data)
		{
			if (hashAlgorithm == null)
				throw new ArgumentNullException("hashAlgorithm");
			if (string.IsNullOrEmpty(data))
				throw new ArgumentNullException("data");

			byte[] buffer = System.Text.Encoding.ASCII.GetBytes(data);
			byte[] bytes = hashAlgorithm.ComputeHash(buffer);

			return Convert.ToBase64String(bytes);
		}
		private static List<Parameter> ExtractQueryString(string url)
		{
			int questionIndex = url.IndexOf('?');
			if (questionIndex == -1)
				return new List<Parameter>();

			var parameters = url.Substring(questionIndex + 1);
			var result = new List<Parameter>();

			if (!String.IsNullOrEmpty(parameters)) {
				string[] parts = parameters.Split('&');
				foreach (var part in parts) {
					if (!string.IsNullOrEmpty(part) && !part.StartsWith(OAuthProtocolParameterPrefix)) {
						if (part.IndexOf('=') != -1) {
							string[] nameValue = part.Split('=');
							result.Add(new Parameter(nameValue[0], nameValue[1]));
						}
						else
							result.Add(new Parameter(part, String.Empty));
					}
				}
			}

			return result;
		}
		private static string GenerateSignatureBaseString(HttpMethod httpMethod, Uri uri, List<Parameter> parameters)
		{
			parameters.Sort(new LexicographicComparer());

			var normalizedUrl = string.Format("{0}://{1}", uri.Scheme, uri.Host);

			if (!((uri.Scheme == "http" && uri.Port == 80) || (uri.Scheme == "https" && uri.Port == 443)))
				normalizedUrl += ":" + uri.Port;
			normalizedUrl += uri.AbsolutePath;

			var normalizedRequestParameters = string.Join("&", parameters.Select(p => p.Name + "=" + Uri.EscapeDataString(p.Value)));

			StringBuilder signatureBaseSb = new StringBuilder();
			signatureBaseSb.AppendFormat("{0}&", httpMethod.Value());
			signatureBaseSb.AppendFormat("{0}&", Uri.EscapeDataString(normalizedUrl));
			signatureBaseSb.AppendFormat("{0}", Uri.EscapeDataString(normalizedRequestParameters));
			return signatureBaseSb.ToString();
		}
		private static string GenerateSignature(string consumerSecret, SignatureMethod signatureMethod, string signatureBaseString, string tokenSecret = null)
		{
			switch (signatureMethod) {
				case SignatureMethod.HMACSHA1:
					var hmacsha1 = new HMACSHA1();
					hmacsha1.Key = Encoding.ASCII.GetBytes(string.Format("{0}&{1}", Utils.UrlEncode(consumerSecret), string.IsNullOrEmpty(tokenSecret) ? "" : Utils.UrlEncode(tokenSecret)));
					return ComputeHash(hmacsha1, signatureBaseString);
				case SignatureMethod.Plaintext:
					throw new NotImplementedException("PLAINTEXT Signature Method type is not yet implemented");
				case SignatureMethod.RSASHA1:
					throw new NotImplementedException("RSA-SHA1 Signature Method type is not yet implemented");
				default:
					throw new ArgumentException("Unknown Signature Method", "signatureMethod");
			}
		}

		private static string GenerateHeader(string consumerKey, string signatureMethod, string signature, string timestamp, string nonce, string version, string callback = null, string token = null, string verifier = null)
		{
			var sb = new StringBuilder();
			sb.Append("OAuth ");
			sb.AppendFormat("realm=\"{0}\", ", "OpenAuth");
			sb.AppendFormat("{0}=\"{1}\", ", OAuthParameter.ConsumerKey.Value(), Utils.UrlEncode(consumerKey));
			sb.AppendFormat("{0}=\"{1}\", ", OAuthParameter.SignatureMethod.Value(), signatureMethod);
			sb.AppendFormat("{0}=\"{1}\", ", OAuthParameter.Signature.Value(), Utils.UrlEncode(signature));
			sb.AppendFormat("{0}=\"{1}\", ", OAuthParameter.Timestamp.Value(), timestamp);
			sb.AppendFormat("{0}=\"{1}\", ", OAuthParameter.Nonce.Value(), Utils.UrlEncode(nonce));
			sb.AppendFormat("{0}=\"{1}\", ", OAuthParameter.Version.Value(), version);
			if (!string.IsNullOrEmpty(callback))
				sb.AppendFormat("{0}=\"{1}\", ", OAuthParameter.Callback.Value(), Utils.UrlEncode(callback));
			if (!string.IsNullOrEmpty(token))
				sb.AppendFormat("{0}=\"{1}\", ", OAuthParameter.Token.Value(), Utils.UrlEncode(token));
			if (!string.IsNullOrEmpty(verifier))
				sb.AppendFormat("{0}=\"{1}\", ", OAuthParameter.Verifier.Value(), Utils.UrlEncode(verifier));

			sb = sb.Remove(sb.Length - 2, 2);
			return sb.ToString();
		}

		public static OpenAuthRequestToken GetRequestToken(Uri uri, string consumerKey, string consumerSecret, string callbackUrl, SignatureMethod signatureMethod = SignatureMethod.HMACSHA1)
		{
			var urlEncodedCallback = Utils.UrlEncode(callbackUrl);
			var timestamp = GenerateTimeStamp();
			var nonce = GenerateNonce(timestamp);

			var parameters = new List<Parameter>();
			parameters.Add(new Parameter(OAuthParameter.ConsumerKey.Value(), consumerKey));
			parameters.Add(new Parameter(OAuthParameter.SignatureMethod.Value(), signatureMethod.Value()));
			parameters.Add(new Parameter(OAuthParameter.Timestamp.Value(), timestamp));
			parameters.Add(new Parameter(OAuthParameter.Nonce.Value(), nonce));
			parameters.Add(new Parameter(OAuthParameter.Version.Value(), OAuthVersion));
			parameters.Add(new Parameter(OAuthParameter.Callback.Value(), callbackUrl));

			string signatureBaseString = GenerateSignatureBaseString(HttpMethod.Post, uri, parameters);
			string signature = GenerateSignature(consumerSecret, signatureMethod, signatureBaseString);
			string header = GenerateHeader(consumerKey, signatureMethod.Value(), signature, timestamp, nonce, OAuthVersion, callbackUrl);

			string response = Utils.Request(HttpMethod.Post, uri, header);
			NameValueCollection data = HttpUtility.ParseQueryString(response);
			if (!data.AllKeys.Contains(OAuthParameter.Token.Value()) ||
				!data.AllKeys.Contains(OAuthParameter.TokenSecret.Value()) ||
				!data.AllKeys.Contains(OAuthParameter.CallbackConfirmed.Value()))
				throw new OpenAuthException { Error = OpenAuthErrorType.MissingKeys };

			return new OpenAuthRequestToken {
				Token = data[OAuthParameter.Token.Value()],
				TokenSecret = data[OAuthParameter.TokenSecret.Value()]
			};
		}
		public static OpenAuthAccessToken GetAccessToken(Uri uri, string consumerKey, string consumerSecret, string token, string tokenSecret, string verifier, SignatureMethod signatureMethod = SignatureMethod.HMACSHA1)
		{
			var timestamp = GenerateTimeStamp();
			var nonce = GenerateNonce(timestamp);

			var parameters = ExtractQueryString(uri.Query);
			parameters.Add(new Parameter(OAuthParameter.ConsumerKey.Value(), consumerKey));
			parameters.Add(new Parameter(OAuthParameter.SignatureMethod.Value(), signatureMethod.Value()));
			parameters.Add(new Parameter(OAuthParameter.Timestamp.Value(), timestamp));
			parameters.Add(new Parameter(OAuthParameter.Nonce.Value(), nonce));
			parameters.Add(new Parameter(OAuthParameter.Version.Value(), OAuthVersion));
			parameters.Add(new Parameter(OAuthParameter.Token.Value(), token));
			parameters.Add(new Parameter(OAuthParameter.Verifier.Value(), verifier));

			string signatureBaseString = GenerateSignatureBaseString(HttpMethod.Post, uri, parameters);
			string signature = GenerateSignature(consumerSecret, signatureMethod, signatureBaseString, tokenSecret);
			string header = GenerateHeader(consumerKey, signatureMethod.Value(), signature, timestamp, nonce, OAuthVersion, null, token, verifier);

			string response = Utils.Request(HttpMethod.Post, uri, header);
			NameValueCollection data = HttpUtility.ParseQueryString(response);
			if (!data.AllKeys.Contains(OAuthParameter.Token.Value()) || !data.AllKeys.Contains(OAuthParameter.TokenSecret.Value()))
				throw new OpenAuthException { Error = OpenAuthErrorType.MissingKeys };

			return new OpenAuthAccessToken {
				Token = data[OAuthParameter.Token.Value()],
				TokenSecret = data[OAuthParameter.TokenSecret.Value()]
			};
		}
		public static string Request(HttpMethod httpMethod, Uri uri, List<Parameter> parameters, string consumerKey, string consumerSecret, string token, string tokenSecret, SignatureMethod signatureMethod = SignatureMethod.HMACSHA1)
		{
			var timestamp = GenerateTimeStamp();
			var nonce = GenerateNonce(timestamp);

			var headerParameters = parameters != null ? new List<Parameter>(parameters) : new List<Parameter>();
			headerParameters.Add(new Parameter(OAuthParameter.ConsumerKey.Value(), consumerKey));
			headerParameters.Add(new Parameter(OAuthParameter.SignatureMethod.Value(), signatureMethod.Value()));
			headerParameters.Add(new Parameter(OAuthParameter.Timestamp.Value(), timestamp));
			headerParameters.Add(new Parameter(OAuthParameter.Nonce.Value(), nonce));
			headerParameters.Add(new Parameter(OAuthParameter.Version.Value(), OAuthVersion));
			headerParameters.Add(new Parameter(OAuthParameter.Token.Value(), token));

			string signatureBaseString = GenerateSignatureBaseString(httpMethod, uri, headerParameters);
			string signature = GenerateSignature(consumerSecret, signatureMethod, signatureBaseString, tokenSecret);
			string header = GenerateHeader(consumerKey, signatureMethod.Value(), signature, timestamp, nonce, OAuthVersion, null, token);

			return Utils.Request(httpMethod, uri, parameters, header);
		}
	}
}