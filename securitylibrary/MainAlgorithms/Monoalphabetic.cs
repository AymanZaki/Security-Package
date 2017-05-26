using System;
using System.Collections.Generic;
using System.Data;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            var map = new Dictionary<char, char>();
            var key = "";
            cipherText = cipherText.ToLower();
            for (var i = 0; i < cipherText.Length; i++)
                map[plainText[i]] = cipherText[i];
            for (var ind = 'a'; ind <= 'z'; ind++)
                if (map.ContainsKey(ind))
                    key += map[ind];
            for (var ind = 'a'; ind <= 'z'; ind++)
                if (!map.ContainsKey(ind))
                    for (var ind1 = 'a'; ind1 <= 'z'; ind1++)
                        if (!key.Contains(ind1.ToString()))
                        {
                            key = key.Insert(ind - 'a', ind1.ToString());
                            break;
                        }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            var map = new Dictionary<char, char>();
            var ind = 'a';
            string plainText = null;
            cipherText = cipherText.ToLower();
            foreach (var alph in key)
            {
                map[alph] = ind;
                ind++;
            }
            foreach (var t in cipherText)
            {
                plainText += map[t];
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            var map = new Dictionary<char, char>();
            var ind = 'a';
            string cipherText = null;
            foreach (var alph in key)
            {
                map[ind] = alph;
                ind++;
            }
            foreach (var t in plainText)
            {
                cipherText += map[t];
            }
            return cipherText;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            var key = new char[26];
            var map = new Dictionary<char, char>();
            var countFreq = new double[26];
            var freq = new Dictionary<char, double>
            {
                ['E'] = 12.51,
                ['T'] = 9.25,
                ['A'] = 8.04,
                ['O'] = 7.60,
                ['I'] = 7.26,
                ['N'] = 7.09,
                ['S'] = 6.54,
                ['R'] = 6.12,
                ['H'] = 5.49,
                ['L'] = 4.14,
                ['D'] = 3.99,
                ['C'] = 3.06,
                ['U'] = 2.71,
                ['M'] = 2.53,
                ['F'] = 2.30,
                ['P'] = 2.00,
                ['G'] = 1.96,
                ['W'] = 1.92,
                ['Y'] = 1.73,
                ['B'] = 1.54,
                ['V'] = 0.99,
                ['K'] = 0.67,
                ['X'] = 0.19,
                ['J'] = 0.16,
                ['Q'] = 0.11,
                ['Z'] = 0.09
            };
            foreach (var alph in cipher)
            {
                countFreq[alph - 'A']++;
            }
            for (var i = 0; i <26; i++)
            {
                countFreq[i] /= (cipher.Length/100.00);
                var minDef = 1000.00;
                char x = '?';
                foreach (var k in freq)
                {
                    if (Math.Abs(countFreq[i] - k.Value) < minDef)
                    {
                        minDef = Math.Abs(countFreq[i] - k.Value);
                        x = k.Key;
                    }
                }
                freq[x] = 1000000.000;
                key[x-'A'] = (char)('a' + i);
               
            }
           
            return Decrypt(cipher, new string(key));
        }

       
    }
}
