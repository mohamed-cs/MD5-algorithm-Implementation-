using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecurityLibrary.DES;
using System;
using System.Collections.Generic;
using System.Data.SqlTypes;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace SecurityLibrary.MD5
{
    public class MD5
    {


        int[] shift ={7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
             5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
             4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
             6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

   

        public byte access_bit(byte[]data,int num)
        {
            int base_b = (int)(num / 8);
            int shift = (int)(num % 8);

            return ((byte)(data[base_b] >> shift));
        }
    


        public string GetHash(string text)
        {


            byte[] bytes = Encoding.ASCII.GetBytes(text);

            String m = "";
            for (int i=0;i<bytes.Length*8;i++)
            {
                byte temp = access_bit(bytes, i);
                temp = (byte)(temp & 0x1);
                m += temp;
            }



           

            String message = m;

     
          
            int original_message_len = message.Length;

            int multiple = get_multiple(message.Length);

           

            int zero_padding_size = 512 * multiple - 64 - message.Length - 8;
       

            message += "00000001";

            for (int i = 0; i < zero_padding_size; i++)
            {
                message += '0';
            }


          
           



            string binary_message_length = "";

            binary_message_length = Convert.ToString(original_message_len% (int)Math.Pow(2, 64), 2);


         

            int zero_padding = 64 - binary_message_length.Length;


            char[] stringArray = binary_message_length.ToCharArray();
            Array.Reverse(stringArray);
            binary_message_length = new string(stringArray);
            message += binary_message_length;

            for (int i = 0; i < zero_padding; i++)
            {
                message += "0";
            }





           




            String[] message_blocks = new String[message.Length / 512];


            int loop_count = 0;

            for (int i = 0; i < message.Length / 512; i++)
            {
                message_blocks[i] = message.Substring(loop_count, 512);
                loop_count += 512;
            }

         

            UInt64 a = 0x67452301;
            UInt64 b = 0xefcdab89;
            UInt64 c = 0x98badcfe;
            UInt64 d = 0x10325476;

            BigInteger outp = md5_512(a, b, c, d, message_blocks);

           

            var bb = outp.ToByteArray();


           



            return ByteArrayToString(bb);
        }


        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);


            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);


            String outp= hex.ToString();
            if (outp[outp.Length - 1].Equals('0') && outp[outp.Length - 2].Equals('0'))
            {
                outp = outp.Remove(outp.Length-1);
                outp = outp.Remove(outp.Length - 1);

            }


            return outp;
        }

    

       
        public UInt64 F(UInt64 b, UInt64 c, UInt64 d)
        {
            return (b&c) | ((~b) &d) ;
        }

        public UInt64 G(UInt64 b, UInt64 c, UInt64 d)
        {
           
            return (b&d) | (c&(~d));
        }

        public UInt64 H(UInt64 b, UInt64 c, UInt64 d)
        {

            return (b^c^d);
        }

        public UInt64 I(UInt64 b, UInt64 c, UInt64 d)
        {
            return c^(b|(~d));
        }


        


        public UInt64 circular_left_shift(UInt64 hex, int d)
        {

            hex &= 0xFFFFFFFF;

            UInt64 res = hex << d | hex >> (32 - d) & 0xFFFFFFFF;


            return res;

        }


        public BigInteger md5_512(UInt64 a, UInt64 b, UInt64 c, UInt64 d, String []Message_512blocks)
        {
            


            UInt64[] t = new UInt64[64];

            for (int i = 0; i < 64; i++)
            {
                t[i] = (UInt64)(UInt64)(Math.Abs(Math.Sin(i + 1)) * 4294967296) & 0xFFFFFFFF;
            }


            for (int l = 0; l < Message_512blocks.Length; l++)
            {
                UInt64 A = a;
                UInt64 B = b;
                UInt64 C = c;
                UInt64 D = d;

                String[] message_blocks_512 = new String[16];


                int loop_count = 0;


                for (int i = 0; i < 16; i++)
                {
                    message_blocks_512[i] = Message_512blocks[l].Substring(loop_count, 32);
                    loop_count += 32;
                }


                int t_count = 0;


                for (int i = 0; i < 64; i++)
                {

                    int g = 0;
                    UInt64 func = 0;

                    if (i >= 0 && i < 16)
                    {
                        func = F(B, C, D);

                        g = i;
                    }
                    else if (i >= 16 && i < 32)
                    {

                        func = G(B, C, D);
                        g = ((5 * i) + 1) % 16;
                    }
                    else if (i >= 32 && i < 48)
                    {
                        func = H(B, C, D);
                        g = ((3 * i) + 5) % 16;
                    }
                    else if (i >= 48 && i < 64)
                    {
                        func = I(B, C, D);
                        g = (7 * i) % 16;
                    }




                    char[] stringArray = message_blocks_512[g].ToCharArray();
                    Array.Reverse(stringArray);
                    String message_blocks = new string(stringArray);

                    UInt32 message_sub = Convert.ToUInt32(message_blocks, 2);

                  

                    UInt64 res = A + func + t[i] + message_sub;

                    res = circular_left_shift(res, shift[i]);

                 

                    res += B;

                    res = res & 0xFFFFFFFF;





                    A = D;
                    D = C;
                    C = B;
                    B = res;



                    t_count += 1;
                }

                a += A;
                b += B;
                c += C;
                d += D;
            }

            

         


            a = a & 0xFFFFFFFF;
            b = b & 0xFFFFFFFF;
            c = c & 0xFFFFFFFF;
            d = d & 0xFFFFFFFF;


           
      

            BigInteger output = (BigInteger)a << (32 * 0);
            output += (BigInteger)b << (32 * 1);
            output += (BigInteger)c << (32 * 2);
            output += (BigInteger)d << (32 * 3);
           
            return output;
        }


        public int get_multiple(int message_length)
        {
            int i = 1;

            while (true)
            {
                if (message_length < (512 * i - 64))
                {
                    return i;
                }
                else
                {
                    i += 1;
                }
            }

        }


    }
}