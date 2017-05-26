using System;
using System.Reflection.Emit;
using SecurityLibrary.Shared;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        private byte[,] TextMatrix;
        private byte[,] KeyMatrix;
        private byte[,] SBox;
        private byte[,] InvSbox;
        private byte[,] MixColumn;
        private byte[,] InvMixColumn;
        private byte[] Rcon;
        private byte[,,] Keys;

        public override string Decrypt(string cipherText, string key)
        {
            Initialize(cipherText, key);
            AddRoundKey(TextMatrix, 10);
            for (int i = 0; i < 9; i++)
            {
                ShiftRows(TextMatrix, false);
                SubBytes(TextMatrix, InvSbox);
                AddRoundKey(TextMatrix, 9 - i);
                MixColumns(TextMatrix, InvMixColumn);

            }
            ShiftRows(TextMatrix, false);
            SubBytes(TextMatrix, InvSbox);
            AddRoundKey(TextMatrix, 0);

            string Text = "0x";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Text += TextMatrix[j, i].ToString("X2");
                }
            }
            return Text;
        }

        public override string Encrypt(string plainText, string key)
        {
            Initialize(plainText, key);

            AddRoundKey(TextMatrix, 0);

            //9 Rounds
            for (int i = 0; i < 9; i++)
            {
                SubBytes(TextMatrix, SBox);
                ShiftRows(TextMatrix, true);
                MixColumns(TextMatrix, MixColumn);
                AddRoundKey(TextMatrix, i + 1);

            }
            SubBytes(TextMatrix, SBox);
            ShiftRows(TextMatrix, true);
            AddRoundKey(TextMatrix, 10);

            string Encrypted = "0x";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Encrypted += TextMatrix[j, i].ToString("X2");
                }
            }
            return Encrypted;
        }

        private void Initialize(string Text, string Key)
        {
            TextMatrix = new byte[4, 4];
            KeyMatrix = new byte[4, 4];
            SBox = new byte[16, 16] {
            {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
            {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
            {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
            {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
            {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
            {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
            {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
            {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
            {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
            {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
            {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
            {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
            {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
            {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
            {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16} };

            InvSbox = new byte[16, 16]{
            { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
            { 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
            { 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
            { 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
            { 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
            { 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
            { 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
            { 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
            { 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
            { 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
            { 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
            { 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
            { 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
            { 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
            { 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
            { 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}};

            MixColumn = new byte[4, 4]{
                {2, 3, 1, 1},
                {1, 2, 3, 1},
                {1, 1, 2, 3},
                {3, 1, 1, 2}};
            InvMixColumn = new byte[4, 4]{
                {0xE, 0xB, 0xD, 0x9},
                {0x9, 0xE, 0xB, 0xD},
                {0xD, 0x9, 0xE, 0xB},
                {0xB, 0xD, 0x9, 0xE}};

            Rcon = new byte[11]{0x0, 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

            BuildMatrix(Text, TextMatrix);
            BuildMatrix(Key, KeyMatrix);

            Keys = new byte[11, 4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Keys[0, i, j] = KeyMatrix[i, j];
                }
            }
            GenerateKeys();
        }

        private void BuildMatrix(string text, byte[,] mat)
        {
            int x = 0, y = 0;
            for (int i = 2; i < text.Length; i += 2)
            {
                string hex = text[i].ToString() + text[i + 1].ToString();
                mat[y++, x] = byte.Parse(hex, System.Globalization.NumberStyles.HexNumber);
                if (y == 4)
                {
                    y = 0;
                    x++;
                }
            }
        }

        private void AddRoundKey(byte[,] mat, int round)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    mat[i, j] ^= Keys[round, i, j];
                }
            }
        }

        private void SubBytes(byte[,] mat, byte[,] Box)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int x, y;
                    y = mat[i, j] & 0xF;
                    x = mat[i, j] >> 4;
                    mat[i, j] = Box[x, y];
                }
            }
        }

        private void ShiftRows(byte[,] mat, bool flag)
        {
            byte[] temp = new byte[4];
            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    if(flag == true)//Encryption
                    temp[j] = mat[i, (i + j) % 4];
                    else //Decryption
                        temp[j] = mat[i, (4 - i + j) % 4];
                }
                for (int j = 0; j < 4; j++)
                    mat[i, j] = temp[j];
            }
        }

        private void MixColumns(byte[,] mat, byte[,] MixColumnsMat)
        {
            //MixColumn * mat
            byte[,] tmp = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    tmp[i, j] = Mul(i, j, MixColumnsMat);
                }
            }
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    mat[i, j] = tmp[i, j];
        }

        private byte Mul(int i, int j, byte[,] MixColumnsMat)
        {
            byte res = 0;
            for (int k = 0; k < 4; k++)
            {
                if (MixColumnsMat[i, k] == 1)
                {
                    res ^= TextMatrix[k, j];
                }
                else if (MixColumnsMat[i, k] == 2)
                {
                    res ^= GaloisField2(TextMatrix[k, j]);
                }
                else if (MixColumnsMat[i, k] == 3)
                {
                    res ^= GaloisField2(TextMatrix[k, j]);
                    res ^= TextMatrix[k, j];
                }
                //X × 9 = (((X × 2) × 2) × 2) + X
                //X × 11 = ((((X × 2) × 2) + X) × 2) + X
                //X × 13 = ((((X × 2) + X) × 2) × 2) + X
                //X × 14 = ((((X × 2) + X) × 2) + X) × 2
                else if (MixColumnsMat[i, k] == 0xE)//1110
                {
                    byte tmp;
                    //X × 14 = ((((X × 2) + X) × 2) + X) × 2
                    tmp = GaloisField2(TextMatrix[k, j]);
                    tmp ^= TextMatrix[k, j];
                    tmp = GaloisField2(tmp);
                    tmp ^= TextMatrix[k, j];
                    tmp = GaloisField2(tmp);
                    res ^= tmp;
                }
                else if (MixColumnsMat[i, k] == 0xB)//1011
                {
                    //X × 11 = ((((X × 2) × 2) + X) × 2) + X
                    byte tmp;
                    tmp = GaloisField2(TextMatrix[k, j]);
                    tmp = GaloisField2(tmp);
                    tmp ^= TextMatrix[k, j];
                    tmp = GaloisField2(tmp);
                    tmp ^= TextMatrix[k, j];
                    res ^= tmp;
                }
                else if (MixColumnsMat[i, k] == 0xD)//1101
                {
                    //X × 13 = ((((X × 2) +X) × 2) × 2) +X
                    byte tmp;
                    tmp = GaloisField2(TextMatrix[k, j]);
                    tmp ^= TextMatrix[k, j];
                    tmp = GaloisField2(tmp);
                    tmp = GaloisField2(tmp);
                    tmp ^= TextMatrix[k, j];
                    res ^= tmp;
                }
                else if (MixColumnsMat[i, k] == 0x9)//1001
                {
                    //X × 9 = (((X × 2) × 2) × 2) + X
                    byte tmp;
                    tmp = GaloisField2(TextMatrix[k, j]);
                    tmp = GaloisField2(tmp);
                    tmp = GaloisField2(tmp);
                    tmp ^= TextMatrix[k, j];
                    res ^= tmp;
                }
            }
            return res;
        }

        private byte GaloisField2(byte val)
        {
            byte C = 128;
            byte tmp = val;
            tmp = (byte)(tmp << 1);
            if ((C & val) == C)
                return (byte)(tmp ^ 0x1B);
            return tmp;
        }

        private void GenerateKeys()
        {
            for (int k = 1; k < 11; ++k)
            {
                //1 - Rotate
                byte[] tmp = new byte[4] {Keys[k - 1, 1, 3], Keys[k- 1, 2, 3], Keys[k - 1, 3, 3], Keys[k - 1, 0, 3]};
                //2 - Sub Bytes
                for (int i = 0; i < 4; i++)
                {
                    int y = tmp[i] & 0xF;
                    int x = tmp[i] >> 4;
                    tmp[i] = SBox[x, y];
                }
                //3 - Xor
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        if (i == 0)
                        {
                            if (j == 0)
                                Keys[k, j, i] = (byte) (Keys[k - 1, j, i] ^ Rcon[k] ^ tmp[j]);
                            else
                                Keys[k, j, i] = (byte) (Keys[k - 1, j, i] ^ tmp[j]);
                        }
                        else
                        {
                            Keys[k, j, i] = (byte) (Keys[k - 1, j, i] ^ Keys[k, j, i - 1]);
                        }
                    }
                }
            }
        }
    }
}
