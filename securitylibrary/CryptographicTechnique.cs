﻿using System;

namespace SecurityLibrary
{
    public abstract class CryptographicTechnique : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public abstract string Decrypt(string cipherText, string key);

        public abstract string Encrypt(string plainText, string key);
    }
}
