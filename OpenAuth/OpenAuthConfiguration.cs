using System;
using System.Configuration;
using System.IO;
using System.Web.Configuration;

namespace OpenAuth
{
	public static class OpenAuthConfiguration
	{
		public static string CallbackProtocol { get; set; }
		public static string CallbackDomain { get; set; }
		public static string CallbackPath { get; set; }

		static OpenAuthConfiguration()
		{
			OpenAuthConfigurationSection config = WebConfigurationManager.GetSection("openAuth") as OpenAuthConfigurationSection;

			if (config == null)
				throw new Exception("OpenAuthConfiguration missing");

			CallbackProtocol = string.IsNullOrWhiteSpace(config.CallbackProtocol) ? "http" : config.CallbackProtocol;
			CallbackDomain = config.CallbackDomain;
			CallbackPath = string.IsNullOrWhiteSpace(config.CallbackPath) ? "openauth.axd" : config.CallbackPath;
		}
	}

	public sealed class OpenAuthConfigurationSection : ConfigurationSection
	{
		[ConfigurationProperty("callbackProtocol", IsRequired = false)]
		public string CallbackProtocol
		{
			get { return (string)base["callbackProtocol"]; }
		}

		[ConfigurationProperty("callbackDomain", IsRequired = true)]
		public string CallbackDomain
		{
			get { return (string)base["callbackDomain"]; }
		}

		[ConfigurationProperty("callbackPath", IsRequired = false)]
		public string CallbackPath
		{
			get { return (string)base["callbackPath"]; }
		}
	}
}