using System;

namespace SecureQueryString
{
    public class Globals
    {
        public static byte[] SecureQueryStringKey = new byte[]
		{
			1,
			5,
			7,
			3,
			4,
			5,
			6,
			9,
			6,
			9,
			0,
			2,
			3,
			8,
			4,
			6
		};

        public static bool SignQueryString = true;
    }
}