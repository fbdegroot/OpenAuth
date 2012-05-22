using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using OpenAuth.Infrastructure;
using System.Web;

namespace OpenAuth
{
	internal enum OAuth2Parameter
	{
		[Value("client_id")]
		ConsumerID,
		[Value("client_secret")]
		ConsumerSecret,
		[Value("code")]
		Code,
		[Value("redirect_uri")]
		CallbackUrl,
		[Value("access_token")]
		AccessToken,
		[Value("scope")]
		Scope,
		[Value("message")]
		Message
	}

	internal static class OAuth2
	{
		internal static Uri StripQuery(Uri uri, params string[] names)
		{
			UriBuilder uriBuilder = new UriBuilder(uri);
			var query = HttpUtility.ParseQueryString(uriBuilder.Query);

			foreach (var name in query.AllKeys.ToList()) {
				if (names.Contains(name))
					query.Remove(name);
			}

			if (query.AllKeys.Count() > 0)
				uriBuilder.Query = string.Join("&", query.AllKeys.Select(name => name + "=" + query[name]));
			else
				uriBuilder.Query = null;

			return uriBuilder.Uri;
		}
	}
}