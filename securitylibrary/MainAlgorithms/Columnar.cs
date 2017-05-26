using System;
using System.Collections.Generic;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            throw new NotImplementedException();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            var res = "";
            var len = plainText.Length;
            var col = key.Count;
            var row = (int)Math.Ceiling((double)len/col);
            var mat = new char[row, col];
            var ind = 0;
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    if (ind < len)
                        mat[i, j] = plainText[ind++];
                    else mat[i, j] = 'x';
                }
            }
            foreach (var i in key)
            {
                for (int j = 0; j < row; j++)
                {
                    res += mat[j, i-1];
                }
               
            }
            return res;
        }
    }
}
