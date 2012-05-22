namespace OpenAuth
{
	public abstract class TokenBase
	{
		public string Token { get; set; }
		public string TokenSecret { get; set; }
	}

	public class OpenAuthRequestToken : TokenBase
	{
		public bool CallbackConfirmed { get; set; }
	}

	public class OpenAuthAccessToken : TokenBase
	{
	}
}