using System;
using SecurityLibrary.Shared;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            var res = "";
            for (var i = 0; i < cipherText.Length; i++)
            {
                res += (char)(Helper.Mod((cipherText[i] - 'A') - (plainText[i] - 'a'), 26) + 'a');
            }
            for (var i = 1; i < cipherText.Length; i++)
            {
                var s = res.Substring(0, i);
                var len = i;
                while (len + i < cipherText.Length && res.Substring(len, i) == s) len += i;
                if (len + i >= cipherText.Length) return s;
            }
            return res;
        }

        public string Decrypt(string cipherText, string key)
        {
            var res = "";
            for (var i = 0; i < cipherText.Length; i++)
            {
                res += (char) (Helper.Mod((cipherText[i] - 'A') - (key[i%key.Length] - 'a'), 26) + 'a');
            }
            return res;
        }

        public string Encrypt(string plainText, string key)
        {
            var res = "";
            for(var i = 0; i < plainText.Length; i ++)
            {
                res += (char) (((plainText[i] - 'a') + (key[i%key.Length] - 'a'))%26 + 'A');
            }
            return res;
        }
    }
}