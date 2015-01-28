using System;
namespace SecureQueryString
{
	public class InvalidQueryStringException : Exception
	{
		public InvalidQueryStringException()
		{
		}
		public InvalidQueryStringException(string message) : base(message)
		{
		}
	}
}
