namespace SecurityLibrary.Shared
{
   public static class Helper
    {
       public static int Mod(int a, int b)
        {
            var r = a % b;
            return r < 0 ? r + b : r;
        }

       public static int Gcd(int a, int b)
       {
           while (true)
           {
               if (b == 0) return a;
               var a1 = a;
               a = b;
               b = a1%b;
           }
       }
    }
}
