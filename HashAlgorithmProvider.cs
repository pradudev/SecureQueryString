using System;
using System.Security.Cryptography;

namespace SecureQueryString
{
    public class HashAlgorithmProvider : IHashProvider
    {
        private HashAlgorithm algorithm;

        public HashAlgorithmProvider()
            : this(MD5.Create())
        {
        }

        public HashAlgorithmProvider(HashAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        public byte[] Hash(byte[] buffer)
        {
            return this.algorithm.ComputeHash(buffer);
        }
    }
}