
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