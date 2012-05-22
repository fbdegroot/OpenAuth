using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace OpenAuth
{
	internal class OpenAuthSessionRepository
	{
		internal static ConcurrentDictionary<string, OpenAuthSession> Sessions = new ConcurrentDictionary<string, OpenAuthSession>();
	}
}