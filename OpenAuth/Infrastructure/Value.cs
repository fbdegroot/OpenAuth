using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;

namespace OpenAuth.Infrastructure
{
	[AttributeUsage(AttributeTargets.Field)]
	internal class ValueAttribute : Attribute
	{
		public string Value { get; private set; }

		public ValueAttribute(string value)
		{
			Value = value;
		}
	}

	internal static class ValueExtension
	{
		public static string Value(this Enum value)
		{
			string output = null;
			Type type = value.GetType();
			FieldInfo fieldInfo = type.GetField(value.ToString());
			ValueAttribute[] attributes = fieldInfo.GetCustomAttributes(typeof(ValueAttribute), false) as ValueAttribute[];
			if (attributes.Length > 0)
				output = attributes[0].Value;
			return output;
		}
	}
}