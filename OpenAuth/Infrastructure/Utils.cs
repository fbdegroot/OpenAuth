using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Web;
using OpenAuth.Consumers;

namespace OpenAuth.Infrastructure
{
	internal static class Utils
	{
		static Utils()
		{
			ServicePointManager.Expect100Continue = false;
		}

		private readonly static string reservedCharacters = "!*'();:@&=+$,/?%#[]";

		internal static string UrlEncode(string value)
		{
			if (String.IsNullOrEmpty(value))
				return String.Empty;

			var sb = new StringBuilder();

			foreach (char @char in value)
			{
				if (reservedCharacters.IndexOf(@char) == -1)
					sb.Append(@char);
				else
					sb.AppendFormat("%{0:X2}", (int)@char);
			}

			return sb.ToString();
		}
		internal static string NormalizeUrl(string url)
		{
			int questionIndex = url.IndexOf('?');
			if (questionIndex == -1)
				return url;

			var parameters = url.Substring(questionIndex + 1);
			var result = new StringBuilder();
			result.Append(url.Substring(0, questionIndex + 1));

			bool hasQueryParameters = false;
			if (!String.IsNullOrEmpty(parameters))
			{
				string[] parts = parameters.Split('&');
				hasQueryParameters = parts.Length > 0;

				foreach (var part in parts)
				{
					var nameValue = part.Split('=');
					result.Append(nameValue[0] + "=");
					if (nameValue.Length == 2)
						result.Append(UrlEncode(nameValue[1]));

					result.Append("&");
				}

				if (hasQueryParameters)
					result = result.Remove(result.Length - 1, 1);
			}

			return result.ToString();
		}
		internal static Uri CreateUri(Uri baseUri, List<Parameter> parameters)
		{
			UriBuilder uriBuilder = new UriBuilder(baseUri);

			if (parameters != null)
			{
				if (string.IsNullOrWhiteSpace(uriBuilder.Query) == false)
				{
					var query = HttpUtility.ParseQueryString(uriBuilder.Query);
					foreach (string key in query)
						parameters.Insert(0, new Parameter { Name = key, Value = query[key] });
				}

				if (parameters.Any(p => p.Type == ParameterType.Query))
					uriBuilder.Query = string.Join("&", parameters.Where(p => p.Type == ParameterType.Query).Select(q => q.Name + "=" + (q.Encode ? UrlEncode(q.Value) : q.Value)));
			}

			return uriBuilder.Uri;
		}

		internal static string Request(HttpMethod httpMethod, Uri endpoint)
		{
			return Request(httpMethod, endpoint, null, null);
		}
		internal static string Request(HttpMethod httpMethod, Uri endpoint, string header)
		{
			return Request(httpMethod, endpoint, null, header);
		}
		internal static string Request(HttpMethod httpMethod, Uri endpoint, List<Parameter> parameters)
		{
			return Request(httpMethod, endpoint, parameters, null);
		}
		internal static string Request(HttpMethod httpMethod, Uri endpoint, List<Parameter> parameters, string header)
		{
			Uri uri = CreateUri(endpoint, parameters);
			HttpWebRequest request = (HttpWebRequest)WebRequest.Create(uri);
			request.Method = httpMethod.Value();
			request.ContentType = "application/x-www-form-urlencoded";

			// oauth 1.0a authorization header
			if (header != null)
				request.Headers.Add("Authorization", header);

			// post parameters
			if (parameters != null && parameters.Any(p => p.Type == ParameterType.Post))
			{
				string parameterString = string.Join("&", parameters.Where(p => p.Type == ParameterType.Post).Select(p => p.Name + "=" + (p.Encode ? UrlEncode(p.Value) : p.Value)));
				byte[] bytes = System.Text.Encoding.ASCII.GetBytes(parameterString);
				using (var requestStream = request.GetRequestStream())
				{
					requestStream.Write(bytes, 0, bytes.Length);
					requestStream.Flush();
				}
			}

			try
			{
				using (var response = request.GetResponse())
				using (var responseStream = response.GetResponseStream())
				using (var reader = new StreamReader(responseStream))
					return reader.ReadToEnd();
			}
			catch (WebException ex)
			{
				using (var response = ex.Response)
				using (var reader = new StreamReader(response.GetResponseStream()))
				{
					throw new OpenAuthException(ex)
					{
						Uri = uri,
						Endpoint = endpoint,
						Parameters = parameters,
						HttpMethod = httpMethod,
						Response = reader.ReadToEnd(),
						HttpStatusCode = (response as HttpWebResponse).StatusCode
					};
				}
			}
			catch (Exception ex)
			{
				throw new OpenAuthException(ex)
				{
					Uri = uri,
					Endpoint = endpoint,					
					Parameters = parameters,
					HttpMethod = httpMethod
				};
			}
		}
	}
}