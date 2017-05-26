using System;

namespace SecurityLibrary.AES
{
	public class ExtendedEuclid
	{
		/// <summary>
		/// 
		/// </summary>
		/// <param name="number"></param>
		/// <param name="baseN"></param>
		/// <returns>Mul inverse, -1 if no inv</returns>
		public int GetMultiplicativeInverse(int number, int baseN)
		{
			int[] A = new int[3];
			int[] B = new int[3];
			A[0] = B[1] = 1;
			A[1] = B[0] = 0;
			A[2] = baseN;
			B[2] = number;
			while (true)
			{
				if (B[2] == 0)
				{
					return ~0;
				}
				else if (B[2] == 1)
				{
					while (B[1] < 0)
					{
						B[1] += baseN;
					}
					while (B[1] > baseN)
					{
						B[1] -= baseN;
					}
					return B[1];
				}
				int Q = A[2] / B[2];
				for (int i = 0; i < 3; ++i)
				{
					int Temp = A[i] - Q * B[i];
					A[i] = B[i];
					B[i] = Temp;
				}
			}
		}
	}
}
