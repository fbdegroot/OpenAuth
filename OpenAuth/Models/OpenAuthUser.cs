using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace OpenAuth.Models
{
	public class OpenAuthUser
	{
		public string ID { get; set; }
		public string FirstName { get; set; }
		public string LastName { get; set; }
		public string FullName { get; set; }
		public string DisplayName { get; set; }
		public string Location { get; set; }
		public string Email { get; set; }
		public string Link { get; set; }
		public string PictureUrl { get; set; }

		public OpenAuthGender? Gender { get; set; }
	}
}