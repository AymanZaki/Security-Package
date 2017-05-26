using System;
using System.Reflection.Emit;
using System.Text;

namespace SecurityLibrary.MD5
{
    public class MD5
    {
        private uint a0 = 0x67452301;//A
        private uint b0 = 0xefcdab89;//B
        private uint c0 = 0x98badcfe;//C
        private uint d0 = 0x10325476;//D
        private readonly uint[] T = new uint[64]
        {
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,

            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,

            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,

            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
        };
        int[,] S = new int[4, 4]{
            {7,12, 17, 22},
            {5,  9, 14, 20},
            {4, 11, 16, 23},
            {6, 10, 15, 21}};
        public string GetHash(string text)
        {
           // text = "a";
            int Textlength = text.Length;
            int chunk = ((Textlength * 8) + 1 + 64) / 512;//1 bit for 1, 64 bits for text length
            chunk++;
            int arrayLength = chunk * 64;
            byte[] Text = new byte[arrayLength];
            int x = (chunk * 512) - 64;
            for (int i = 0; i < Textlength; i++)
            {
                Text[i] = (byte)text[i];
            }

            //add 1 bit and other bits 0
            Text[Textlength] = 128;
            
            //add length of text
            byte[] tmpArr = BitConverter.GetBytes((ulong)Textlength * 8);
            for (int i = 0; i < 8; ++i)
            {
                Text[arrayLength - 8 + i] = tmpArr[i];
            }
            

            for (int i = 0; i < chunk; ++i)
            {
                uint A = a0, B = b0, C = c0, D = d0;
                uint F;
                int g;
                for (int round = 0; round < 4; round++)
                {
                    for (int step = 0; step < 16; step++)
                    { 
                        if (round == 0)
                        {
                            //F(b, c, d) = (b AND c) OR(NOT b AND d)
                            F = (B & C) | ((~B) & D);
                            g = step + (round*16);
                        }
                        else if (round == 1)
                        {
                            //G(b,c,d) =(b AND d) OR (c AND NOT d)
                            F = (B & D) | (C & (~D));
                            g = ((5 * step + (round * 16)) + 1) % 16;
                        }
                        else if (round == 2)
                        {
                            //H(b,c,d) = b XOR c XOR d
                            F = B ^ C ^ D;
                            g = ((3 * step + (round * 16)) + 5) % 16;
                        }
                        else
                        {
                            //I(b, c, d) = c XOR(b OR NOT d)
                            F = C ^ (B | (~D));
                            g = (7 * step + (round * 16)) % 16;
                        }

                        uint dword = 0;
                        for (int j = (g * 4) + 3 ; j >= (g * 4); --j)
                        {
                            dword <<= 8;
                            dword |= Text[(i*64) + j];

                        }
                        uint tmpB = A + F + T[(round*16) + step] + dword;
                        uint tmp = D;
                        D = C;
                        C = B;
                        B = B + RotateLeft(tmpB, S[round, step%4]);
                        A = tmp;
                    }
                }
                a0 = a0 + A;
                b0 = b0 + B;
                c0 = c0 + C;
                d0 = d0 + D;
            }
            return IntToString(a0) + IntToString(b0) + IntToString(c0) + IntToString(d0);
        }

        private string IntToString(uint x)
        {
            byte[] arr = BitConverter.GetBytes(x);
            string res = BitConverter.ToString(arr).Replace("-", string.Empty);
            return res;
        }

        private uint RotateLeft(uint x, int n)
        {
            return ((x) << (n)) | ((x) >> (32 - (n)));
        }
    }
}