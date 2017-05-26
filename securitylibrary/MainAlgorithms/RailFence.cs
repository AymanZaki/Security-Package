using System;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            for (var i = 2; i < cipherText.Length-2; i++)
            {
                if (cipherText == Encrypt(plainText, i).ToUpper()) return i;
            }
            return 0;
        }

        public string Decrypt(string cipherText, int key)
        {
            var res = "";
            var len = (double)cipherText.Length/(double)key;
            int c = (int) Math.Ceiling(len);
            for (var i = 0; i < c; i++)
            {
                for (var j = 0; j < key && i + (c * j) < cipherText.Length ; j++)
                {
                    res += cipherText[i+(c*j)];
                }
            }
            return res;
        }

        public string Encrypt(string plainText, int key)
        {
            var res = "";
            for (var i = 0; i < key; i++)
            {
                for (var j = i; j < plainText.Length; j+=key)
                {
                    res += plainText[j];
                }
            }
            return res;
        }
    }
}
