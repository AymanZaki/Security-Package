using System;
using SecurityLibrary.Shared;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
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
                var s = res.Substring(i);
                if (plainText.StartsWith(s))
                    return res.Substring(0, i);
            }
            return res;
        }

        public string Decrypt(string cipherText, string key)
        {
            var res = "";
            int ind = 0;
            for (var i = 0; i < cipherText.Length; i++)
            {
                if (key.Length == i) key += res[ind++];
                res += (char)(Helper.Mod((cipherText[i] - 'A') - (key[i] - 'a'), 26) + 'a');
            }
            return res;
        }

        public string Encrypt(string plainText, string key)
        {
            key += plainText;
            var res = "";
            for (var i = 0; i < plainText.Length; i++)
            {
                res += (char) (((plainText[i] - 'a') + (key[i] - 'a'))%26 + 'A');
            }
            return res;
        }
    }
}
