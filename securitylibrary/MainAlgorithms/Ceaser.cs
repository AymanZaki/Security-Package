using System;
using SecurityLibrary.Shared;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            string cipherText = null;
            foreach (var alph in plainText)
            {
                cipherText += (char)((alph - 'a' + key)%26 + 'a');
            }
            return cipherText;
        }

        public string Decrypt(string cipherText, int key)
        {
            string plainText = null;
            foreach (var alph in cipherText)
            {
                plainText += (char)(Helper.Mod((alph - 'A' - key), 26) + 'A');
            }
            return plainText;
        }

        public int Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            for (var i = 0; i < 25; i++)
            {
                var ind = 0;
                for (; ind < cipherText.Length; ind++)
                {
                    if (cipherText[ind] != (char)((plainText[ind] - 'a' + i) % 26 + 'a')) break;
                }
                if (ind == cipherText.Length) return i;
            }
            return -1;
        }
    }
}
