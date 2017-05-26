using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using MathNet.Numerics.LinearAlgebra;
using MathNet.Numerics.LinearAlgebra.Double;
using SecurityLibrary.Shared;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        private int FindMultiplicativeInverse(double det, List<int> key)
        {
            if (!key.All(i => i >= 0)) return 0;
            var gcd = Helper.Gcd(26, (int)det);
            if (gcd != 1) return 0;
            for (var i = 1; i <= 26; i++) if ((i * (int)det) % 26 == 1) return i;
            return 0;
        }

        //Done -Mohsen
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            var len = 1;
            while (len * len < key.Count) len++;
            Matrix<double> mat = DenseMatrix.OfArray(new double[len, len]);
            var ind = 0;
            for (var f = 0; f < len; f++)
                for (var f1 = 0; f1 < len; f1++)
                {
                    mat[f, f1] = key[ind];
                    ind++;
                }
            var det = Math.Ceiling(mat.Determinant());
            det = Helper.Mod((int)det, 26);
            var multInverse = FindMultiplicativeInverse(det, key);
            if (multInverse == 0) return new List<int>();
            Matrix<double> invMatrix = DenseMatrix.OfArray(new double[len, len]);
            for (var f = 0; f < len; f++)
                for (var f1 = 0; f1 < len; f1++)
                {
                    var temMatrix = DenseMatrix.OfArray(new double[len - 1, len - 1]);
                    var ind1 = 0;
                    var ind2 = 0;
                    for (var g = 0; g < len; g++)
                        for (var g1 = 0; g1 < len; g1++)
                        {
                            if (g == f || g1 == f1) continue;
                            temMatrix[ind1, ind2] = mat[g, g1];
                            ind2++;
                            if (ind2 != len - 1) continue;
                            ind2 = 0;
                            ind1++;
                        }
                    var temDet = temMatrix.Determinant();
                    invMatrix[f, f1] = Helper.Mod((int)(multInverse * Math.Pow(-1, f + f1) * temDet), 26);
                }
            invMatrix = invMatrix.Transpose();
            var res = new List<int>();
            for (var i = 0; i < cipherText.Count; i += len)
            {
                Vector<double> vec = DenseVector.OfArray(new double[len]);
                for (var j = 0; j < len; j++)
                    vec[j] = cipherText[i + j];
                var list = invMatrix * vec;
                for (var j = 0; j < len; j++) res.Add((int)list[j] % 26);
            }
            return res;
        }

        //Done -Mohsen
        public string Decrypt(string cipherText, string key)
        {
            var key_ = key.Select(i => i - 'a').ToList();
            var cipherText_ = cipherText.Select(i => i - 'A').ToList();
            var list = Decrypt(cipherText_, key_);
            return list.Aggregate("", (current, i) => current + (char)(i + 'a'));
        }

        //Done -Mohsen
        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            var len = 1;
            while (len * len < key.Count) len++;
            Matrix<double> mat = DenseMatrix.OfArray(new double[len, len]);
            var ind = 0;
            for (var f = 0; f < len; f++)
                for (var f1 = 0; f1 < len; f1++)
                {
                    mat[f, f1] = key[ind];
                    ind++;
                }
            var res = new List<int>();
            for (var i = 0; i < plainText.Count; i += len)
            {
                Vector<double> vec = DenseVector.OfArray(new double[len]);
                for (var j = 0; j < len; j++)
                    vec[j] = plainText[i + j];
                var list = mat * vec;
                for (var j = 0; j < len; j++) res.Add((int)list[j] % 26);
            }
            return res;
        }

        //Done - Mohsen
        public string Encrypt(string plainText, string key)
        {
            var key_ = key.Select(i => i - 'a').ToList();
            var plainText_ = plainText.Select(i => i - 'a').ToList();
            var list = Encrypt(plainText_, key_);
            return list.Aggregate("", (current, i) => current + (char)(i + 'A'));
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            throw new NotImplementedException();
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }
    }
}
