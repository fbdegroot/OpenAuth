﻿using System.Collections.Generic;

namespace OpenAuth.Infrastructure
{
	public class Parameter
	{
		public string Name { get; set; }
		public string Value { get; set; }
		public ParameterType Type { get; set; }
		public bool Encode { get; set; }

		public Parameter()
		{
			Type = ParameterType.Query;
			Encode = true;
		}
		public Parameter(string name, string value)
		{
			Name = name;
			Value = value;
			Type = ParameterType.Query;
			Encode = true;
		}
	}
	internal class LexicographicComparer : IComparer<Parameter>
	{
		public int Compare(Parameter x, Parameter y)
		{
			if (x.Name == y.Name)
				return string.Compare(x.Value, y.Value);
			else
				return string.Compare(x.Name, y.Name);
		}
	}

	public enum ParameterType
	{
		Query,
		Post
	}
}