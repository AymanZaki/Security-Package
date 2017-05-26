using System;
using System.Collections.Generic;
using SecurityLibrary.Shared;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        private readonly Dictionary<char, Tuple<int, int> > _mat;
        private readonly char[,] _mat1;

        public PlayFair()
        {
            _mat1 = new char[5,5];
            _mat = new Dictionary<char, Tuple<int, int>>();
        }

        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        /// 
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            var plainText = "";
            cipherText = cipherText.ToLower();
            BuiledMatrix(key);
            cipherText = _mat.ContainsKey('i') ? cipherText.Replace("j", "i") : cipherText.Replace("i", "j");
            for (var i = 0; i < cipherText.Length; i += 2)
            {
                var c1 = cipherText[i];
                var c2 = 'x';
                if (i + 1 < cipherText.Length) c2 = cipherText[i + 1];
                if (_mat[c1].Item1 != _mat[c2].Item1 &&
                    _mat[c1].Item2 != _mat[c2].Item2)
                {
                    plainText += _mat1[_mat[c1].Item1, _mat[c2].Item2];
                    plainText += _mat1[_mat[c2].Item1, _mat[c1].Item2];
                }
                else if (_mat[c1].Item1 != _mat[c2].Item1)
                {
                    plainText += _mat1[Helper.Mod(_mat[c1].Item1 - 1, 5), _mat[c1].Item2];
                    plainText += _mat1[Helper.Mod(_mat[c2].Item1 - 1, 5), _mat[c2].Item2];
                }
                else if (_mat[c1].Item2 != _mat[c2].Item2)
                {
                    plainText += _mat1[_mat[c1].Item1, Helper.Mod(_mat[c1].Item2 - 1, 5)];
                    plainText += _mat1[_mat[c2].Item1, Helper.Mod(_mat[c2].Item2 - 1, 5)];
                }
            }
            double count = 0;
            foreach (var pl in plainText)
            {
                if (pl == 'x') count++;
            }
            for (int i = 0; i < plainText.Length - 2; i++)
            {
                const string chars = "setflmor";
                foreach (var c in chars)
                {
                    if (plainText[i] != c) continue;
                    if (plainText[i] != plainText[i + 2] || plainText[i + 1] != 'x') continue;
                    plainText = plainText.Remove(i + 1, 1);
                    count--;
                }
            }
            if (plainText.EndsWith("x")) plainText = plainText.Remove(plainText.Length - 1);
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            var cipherText = "";
            BuiledMatrix(key);
            plainText = _mat.ContainsKey('i') ? plainText.Replace("j", "i") : plainText.Replace("i", "j");
            for (var i = 0; i < plainText.Length; i+=2)
            {
                var c1 = plainText[i];
                var c2 = 'x';
                if (i + 1 < plainText.Length) c2 = plainText[i + 1];
                if (c1 == c2)
                {
                    c2 = 'x';
                    i --;
                }
                if (_mat[c1].Item1 != _mat[c2].Item1 && 
                    _mat[c1].Item2 != _mat[c2].Item2)
                {
                    cipherText += _mat1[_mat[c1].Item1,_mat[c2].Item2];
                    cipherText += _mat1[_mat[c2].Item1, _mat[c1].Item2];
                }
                else if (_mat[c1].Item1 != _mat[c2].Item1)
                {
                    cipherText += _mat1[(_mat[c1].Item1 + 1)%5, _mat[c1].Item2];
                    cipherText += _mat1[(_mat[c2].Item1 + 1)%5, _mat[c2].Item2];
                }
                else if (_mat[c1].Item2 != _mat[c2].Item2)
                {
                    cipherText += _mat1[_mat[c1].Item1, (_mat[c1].Item2 + 1)%5];
                    cipherText += _mat1[_mat[c2].Item1, (_mat[c2].Item2 + 1)%5];
                }
                else
                {
                    cipherText += c1;
                    cipherText += c2;
                }
            }

            return cipherText;
        }

        private void BuiledMatrix(string text)
        {
            text = text.ToLower();
            var visit = new bool[26];
            int indi = 0, indj = 0;
            foreach (var ch in text)
            {
                var c = ch;
                if ((c == 'i' || c == 'j') && (visit[8]|| visit[9])) continue;
                if (visit[c - 'a']) continue;
               
                visit[c - 'a'] = true;
                _mat[c] = new Tuple<int, int>(indi, indj);
                _mat1[indi, indj++] = c;
                if (indj != 5) continue;
                indj = 0;
                indi++;
            }
            for (var i = 0; i <= 25; i++)
            {
                if ((i == 8 || i == 9) && (visit[8] || visit[9])) continue;

                if (!visit[i])
                {
                    _mat[(char) ('a' + i)] = new Tuple<int, int>(indi, indj);
                    _mat1[indi, indj++] = (char) ('a' + i);
                    visit[i] = true;
                }
                if (indj != 5) continue;
                indj = 0;
                indi++;
            }
        }
    }
}
