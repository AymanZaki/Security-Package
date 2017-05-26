using System;
using System.Collections.Generic;

namespace SecurityLibrary.Shared
{
    public class Dectionaries
    {
        private static readonly Lazy<Dectionaries> Lazy =
            new Lazy<Dectionaries>(() => new Dectionaries());
        public static Dectionaries Instance => Lazy.Value;

        public Dectionaries()
        {
            for (var i = 0; i < 26; i++)
            {
                AlphNum[(char)('a' + i)] = i;
                AlphNum[(char)('A' + i)] = i;
                NumAlph[i] = (char)('a' + i);
            }
        }
        public Dictionary<char, int> AlphNum = new Dictionary<char, int>();
        public Dictionary<int, char> NumAlph = new Dictionary<int, char>();
    }
}
