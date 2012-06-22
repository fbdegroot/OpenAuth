using System.Collections.Concurrent;

namespace OpenAuth
{
	internal class OpenAuthSessionRepository
	{
		internal static ConcurrentDictionary<string, OpenAuthSession> Sessions = new ConcurrentDictionary<string, OpenAuthSession>();
	}
}