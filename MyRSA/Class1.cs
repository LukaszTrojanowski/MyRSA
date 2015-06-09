using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics; // add a reference in Project -> Add Reference | for BigInteger
using System.Security.Cryptography;

namespace MyRSA
{
    public class RSA
    {

        private BigInteger pub_key;
        private BigInteger priv_key;
        private BigInteger RSAmodule;


        public BigInteger getPublicKey()
        {
            return pub_key;
        }

        public BigInteger getPrivateKey()
        {
            return priv_key;
        }

        public BigInteger getRSAModule()
        {
            return RSAmodule;
        }
       // private BigInteger composite; // often denoted as N
        
        
        // link to Miller-Rabin test:
        // http://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
        private bool is_prime(BigInteger n, int k = 30)
        {
            if (n <= 3)
            {
                return (n == 2 || n == 3);
            }
            else if (n % 2 == 0)
            {
                return false;
            }

            BigInteger neg_one = n - 1;

            // write n-1 as 2^s*d whre d is odd
            BigInteger d;
            int s = 0;
            d = neg_one;
            while (d % 2 == 0){
                s += 1;
                d >>= 1;
            }
            var rng = new RNGCryptoServiceProvider();
            byte[] bytes = new byte[n.ToByteArray().Length];
            
            for (int i = 0; i < k; i++) // WitnessLoop
            {
                BigInteger a;
                 { // gen a big int in range <3, n-2>
                    a = BigIntRand.RandInRange(neg_one-1);
                 } while (a < 3 || a >= neg_one - 1);
                BigInteger x = BigInteger.ModPow(a, d, n);
                if (x == 1 || x == neg_one)
                    continue;
                for (int r=1; r < s; r++)
                {
                    x = BigInteger.ModPow(x, 2, n);
                    if (x == 1)
                        return false;
                    if (x == neg_one)
                        break;
                }
                if (x != neg_one) // instead of for ... else (?? stackoverflow) 
                    return false;
            }
            return true;
        }

        // generate prime in range 1 to 2**(N+1)-1
        private BigInteger randPrime(int N = 128) // change after testing to higher exp 2048
        {
            BigInteger p = 1;
            while (!is_prime(p))
            {
                p = BigIntRand.RandOfSize(N);
            }
            return p;
        }

        public void keyGen(int N = 128, BigInteger? public_val = null) // set N to 128 for testing, after to 2048
        {
            BigInteger p = randPrime(N);
            BigInteger q = randPrime(N);
            RSAmodule = p*q;

            BigInteger phi_N=BigInteger.Multiply((p-1),(q-1));

            if (public_val == null)
            {
                do {
                    priv_key = BigIntRand.RandOfSize(N);
                } while(BigInteger.GreatestCommonDivisor(priv_key, phi_N)!=1);
                pub_key = Utils.modInverse(priv_key, phi_N);
            } else {
                pub_key = (BigInteger)public_val;
                priv_key = Utils.modInverse(pub_key, phi_N);
            }
        }

        //http://www.cs.utexas.edu/~eberlein/cs337/cryptography3.pdf some usefull resources
        public string encode(string msg, BigInteger publicKey, BigInteger modulus, bool verbose = false)
        {
            int blockSize = (int)BigInteger.Log(modulus, 2); // max block size in bits 
            int byteBlockSize = (blockSize + 7) / 8;
            byte[] bytes_msg = Utils.GetBytes(msg);
            byte[] chunk = new byte[byteBlockSize];
            byte[] encrypted_msg;
            List<byte> encrypted_list = new List<byte>();
            for (int start = 0; start*byteBlockSize < bytes_msg.Length; start++)
            {
                // preparation of chunk and eventuall fillup with zeros
                byte[] temp_chunk = bytes_msg.Skip(start * blockSize).Take(byteBlockSize).ToArray();
                for (int i = 0; i < temp_chunk.Length; i++)
                {
                    chunk[i] = temp_chunk[i];
                }
                for (int i = temp_chunk.Length; i < byteBlockSize; i++)
                {
                    chunk[i] = 0;
                }
                // conversion of chunk
                BigInteger chunkBI = new BigInteger(chunk);
                BigInteger encrypted_chunk = BigInteger.ModPow(chunkBI, publicKey, modulus);
                encrypted_list.AddRange(encrypted_chunk.ToByteArray());
            }
            encrypted_msg = encrypted_list.ToArray();
            if (verbose == true)
                Console.WriteLine(Utils.GetString(encrypted_msg));
            return Utils.GetString(encrypted_msg);
        }

        public string decode(string enc_msg, BigInteger privateKey, BigInteger modulus, bool verbose = false)
        {
            int blockSize = (int)BigInteger.Log(modulus, 2);
            int byteBlockSize = (blockSize + 7) / 8;
            byte[] bytes_msg = Utils.GetBytes(enc_msg);
            byte[] chunk = new byte[byteBlockSize];
            byte[] decrypted_msg;
            List<byte> decrypted_list = new List<byte>();
            for (int start = 0; start*byteBlockSize < bytes_msg.Length; start++)
            {
                byte[] temp_chunk = bytes_msg.Skip(start * blockSize).Take(byteBlockSize).ToArray();
                BigInteger chunkBI = new BigInteger(temp_chunk);
                BigInteger decoded_chunk = BigInteger.ModPow(chunkBI, privateKey, modulus);
                decrypted_list.AddRange(decoded_chunk.ToByteArray());
            }
            decrypted_msg = decrypted_list.ToArray();
            if (verbose == true)
                Console.WriteLine(Utils.GetString(decrypted_msg));
            return Utils.GetString(decrypted_msg);
        }

    }

    public static class Utils
    {
        public static BigInteger modInverse(BigInteger a, BigInteger n)
        {
            BigInteger i = n, v = 0, d = 1;
            while (a > 0)
            {
                BigInteger t = i / a, x = a;
                a = i % x;
                i = x;
                x = d;
                d = v - t * x;
                v = x;
            }
            v %= n;
            if (v < 0) v = (v + n) % n;
            return v;
        }
        public static byte[] GetBytes(string str)
        {
            byte[] bytes = new byte[str.Length * sizeof(char)];
            System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        public static string GetString(byte[] bytes)
        {
            char[] chars = new char[(int)Math.Ceiling((double)((double)bytes.Length / sizeof(char)))];
            System.Buffer.BlockCopy(bytes, 0, chars, 0, bytes.Length);
            return new string(chars);
        }
    }

    public static class BigIntRand {
        private static RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
        

        public static BigInteger RandOfSize(int N){ // returns a Random number taking up up to N bits
            if (N % 8 != 0)
                throw new Exception("The specified size is not equally devidable by 8");
            byte[] bytes =  new byte[N / 8];
            rng.GetBytes(bytes);
            bytes[bytes.Length -1] &= (byte)0x7F; // 01111111 assure positive sign
            BigInteger IntegerOfSize = new BigInteger(bytes);
            return IntegerOfSize;
        }

        public static BigInteger RandInRange(BigInteger MaxVal)
        {
            if (MaxVal < 1)
                throw new Exception("RandInRange input must be bigger then 1");
            byte[] bytes = MaxVal.ToByteArray();
            BigInteger IntegerOfRange;

            do
            {
                rng.GetBytes(bytes);
                bytes[bytes.Length - 1] &= (byte)0x7F; //force sign bit to positive
                IntegerOfRange = new BigInteger(bytes);
            } while (IntegerOfRange >= MaxVal);

            return IntegerOfRange;       
        }
    }
}
