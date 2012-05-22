using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Runtime.Serialization;

namespace OpenAuth
{
	public enum OpenAuthErrorType
	{
		None,
		Unknown,
		DuplicateMessage,		
		CrossSiteRequestForgery,
		MissingKeys,
		UserDenied,
		ScopeUnauthorized,
		InvalidOrExpiredAccessToken
	}
}