using System;
using System.IO;
using System.Security.Cryptography;
namespace SecureQueryString
{
	public class SymmetricAlgorithmProvider : ISymmetricCryptoProvider
	{
		private int IVSize;
		private SymmetricAlgorithm algorithm;
		public SymmetricAlgorithmProvider(byte[] key) : this(Rijndael.Create(), key)
		{
		}
		public SymmetricAlgorithmProvider(SymmetricAlgorithm algorithm, byte[] key)
		{
			this.algorithm = algorithm;
			algorithm.Key = key;
			algorithm.GenerateIV();
			this.IVSize = algorithm.IV.Length;
		}
		public byte[] Encrypt(byte[] plaintext)
		{
			this.ValidateByteArrayParam("plaintext", plaintext);
			this.algorithm.GenerateIV();
			byte[] ciphertext = null;
			using (ICryptoTransform cryptoTransform = this.algorithm.CreateEncryptor())
			{
				ciphertext = this.Transform(cryptoTransform, plaintext);
			}
			return this.PrependIVToCipher(ciphertext);
		}
		public byte[] Decrypt(byte[] ciphertext)
		{
			this.ValidateByteArrayParam("ciphertext", ciphertext);
			this.algorithm.IV = this.GetIVFromCipher(ciphertext);
			byte[] result = null;
			using (ICryptoTransform cryptoTransform = this.algorithm.CreateDecryptor())
			{
				result = this.Transform(cryptoTransform, this.StripIVFromCipher(ciphertext));
			}
			return result;
		}
		private byte[] Transform(ICryptoTransform transform, byte[] buffer)
		{
			byte[] result = null;
			using (MemoryStream memoryStream = new MemoryStream())
			{
				CryptoStream cryptoStream = null;
				try
				{
					cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write);
					cryptoStream.Write(buffer, 0, buffer.Length);
					cryptoStream.FlushFinalBlock();
					result = memoryStream.ToArray();
				}
				finally
				{
					if (cryptoStream != null)
					{
						cryptoStream.Close();
					}
				}
			}
			return result;
		}
		private void ValidateByteArrayParam(string paramName, byte[] value)
		{
			if (value == null || value.Length == 0)
			{
				throw new ArgumentNullException(paramName);
			}
		}
		private byte[] PrependIVToCipher(byte[] ciphertext)
		{
			byte[] array = new byte[ciphertext.Length + this.algorithm.IV.Length];
			Buffer.BlockCopy(this.algorithm.IV, 0, array, 0, this.algorithm.IV.Length);
			Buffer.BlockCopy(ciphertext, 0, array, this.algorithm.IV.Length, ciphertext.Length);
			return array;
		}
		private byte[] GetIVFromCipher(byte[] ciphertext)
		{
			byte[] array = new byte[this.IVSize];
			Buffer.BlockCopy(ciphertext, 0, array, 0, this.IVSize);
			return array;
		}
		private byte[] StripIVFromCipher(byte[] ciphertext)
		{
			byte[] array = new byte[ciphertext.Length - this.IVSize];
			Buffer.BlockCopy(ciphertext, this.IVSize, array, 0, array.Length);
			return array;
		}
	}
}
