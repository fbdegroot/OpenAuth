﻿using System;
using System.Security.Principal;
using System.Web;
using System.Web.SessionState;
using OpenAuth.Models;

namespace OpenAuth
{
	public class OpenAuthSession
	{
		public OpenAuthProvider Provider { get; set; }
		public Action<OpenAuthUser, OpenAuthAccessToken, IPrincipal, HttpSessionState, HttpResponse> Callback { get; set; }
		public Func<OpenAuthUser, OpenAuthAccessToken, IPrincipal, HttpSessionState, HttpResponse, object> ClosePopupCallback { get; set; }
	}
}