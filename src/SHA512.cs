using System.Security.Cryptography;
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
            return Convert.ToBase64String(((IHashAlgorithm)this).ComputeHash(Encoding.UTF8.GetBytes(value)));
        }

        string IHashAlgorithm.ComputeHash(string value, Encoding? encoding)
        {
            if (encoding == null)
                encoding = Encoding.UTF8;

            return Convert.ToBase64String(((IHashAlgorithm)this).ComputeHash(encoding.GetBytes(value)));
        }

        byte[] IHashAlgorithm.ComputeHash(byte[] value)
        {
            byte[] bytes;

            using HashAlgorithm sHAManaged = System.Security.Cryptography.SHA512.Create();
            bytes = sHAManaged.ComputeHash(value);
            sHAManaged.Clear();

            return bytes;
        }
    }
}