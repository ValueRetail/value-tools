using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Value.Tools.Security
{
    public class AES256Cipher
    {
        private readonly byte[] _key;

        public AES256Cipher(string key)
        {
            if (string.IsNullOrWhiteSpace(key)) throw new NullReferenceException("The encryption key is empty. Please provide a valid key. Must be 128, 192, or 256 bits.");
            _key = Convert.FromBase64String(key);
            if (_key.Length != 16 && _key.Length != 24 && _key.Length != 32)
                throw new ArgumentException("Key size is not valid. Must be 128, 192, or 256 bits.");
        }

        public string Decrypt(string value)
        {
            var ivAndCipherText = Convert.FromBase64String(value);
            using (var aes = Aes.Create())
            {
                var ivLength = aes.BlockSize / 8;
                aes.IV = ivAndCipherText.Take(ivLength).ToArray();
                aes.Key = _key;
                using (var cipher = aes.CreateDecryptor())
                {
                    var cipherText = ivAndCipherText.Skip(ivLength).ToArray();
                    var text = cipher.TransformFinalBlock(cipherText, 0, cipherText.Length);
                    return Encoding.UTF8.GetString(text);
                }
            }
        }

        public string Encrypt(string value)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = _key;
                aes.GenerateIV();
                using (var cipher = aes.CreateEncryptor())
                {
                    var text = Encoding.UTF8.GetBytes(value);
                    var cipherText = cipher.TransformFinalBlock(text, 0, text.Length);
                    return Convert.ToBase64String(aes.IV.Concat(cipherText).ToArray());
                }
            }
        }

        public static string GenerateNewKey()
        {
            using (var aes = Aes.Create())
            {
                aes.GenerateKey();
                return Convert.ToBase64String(aes.Key);
            }
        }

        public static bool IsBase64String(string base64)
        {
            try
            {
                Convert.FromBase64String(base64);
                return true;
            }
            catch (FormatException)
            {
                return false;
            }
        }
    }
}