using System;
using System.Collections.Generic;
using System.Net;
using OpenAuth.Infrastructure;

namespace OpenAuth
{
	public class OpenAuthException : Exception
	{
		public HttpStatusCode HttpStatusCode { get; set; }
		public string Response { get; set; }
		public HttpMethod HttpMethod { get; set; }
		public Uri Endpoint { get; set; }
		public Uri Uri { get; set; }
		public List<Parameter> Parameters { get; set; }
		public OpenAuthErrorType Error { get; set; }

		public OpenAuthException(Exception innerException)
			: base(null, innerException)
		{
			Error = OpenAuthErrorType.None;
		}
		public OpenAuthException()
		{
			Error = OpenAuthErrorType.None;
		}
	}
}