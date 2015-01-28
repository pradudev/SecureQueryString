using System;

namespace SecureQueryString
{
    public interface ISymmetricCryptoProvider
    {
        byte[] Encrypt(byte[] plaintext);

        byte[] Decrypt(byte[] ciphertext);
    }
}