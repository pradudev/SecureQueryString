using System;
namespace SecureQueryString
{
	public sealed class CommonUtil
	{
		private CommonUtil()
		{
		}
		public static bool CompareBytes(byte[] array1, byte[] array2)
		{
			if (array1.Length != array2.Length)
			{
				return false;
			}
			for (int i = 0; i < array1.Length; i++)
			{
				if (array1[i] != array2[i])
				{
					return false;
				}
			}
			return true;
		}
	}
}
