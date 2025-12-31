using System.Text;

namespace MetaFrm.Security
{
    /// <summary>
    /// SHA512 해시 알고리즘
    /// </summary>
    public class SHA512 : IHashAlgorithm
    {
        string IHashAlgorithm.ComputeHash(string value)
        {
            return ((IHashAlgorithm)this).ComputeHash(value);
        }

        string IHashAlgorithm.ComputeHash(string value, Encoding? encoding)
        {
            encoding ??= Encoding.UTF8;

            return Convert.ToBase64String(((IHashAlgorithm)this).ComputeHash(encoding.GetBytes(value)));
        }

        byte[] IHashAlgorithm.ComputeHash(byte[] value)
        {
            return System.Security.Cryptography.SHA512.HashData(value);
        }
    }
}