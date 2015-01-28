using System;

namespace SecureQueryString
{
    public interface IHashProvider
    {
        byte[] Hash(byte[] buffer);
    }
}