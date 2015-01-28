using System;
using System.Collections.Specialized;
using System.Globalization;
using System.Text;
using System.Web;

namespace SecureQueryString
{
    public class SecureQueryString : NameValueCollection
    {
        private const string timeStampKey = "__TS__";
        private const string dateFormat = "G";
        private const string sessionIDKey = "sessionid";
        private ISymmetricCryptoProvider symmetricCryptoProvider;
        private IHashProvider hashProvider;
        private DateTime expireTime = DateTime.MaxValue;
        private string sessionid;
        private byte[] key;

        public DateTime ExpireTime
        {
            get
            {
                return this.expireTime;
            }
            set
            {
                this.expireTime = value;
            }
        }

        public string SessionID
        {
            get
            {
                return this.sessionid;
            }
            set
            {
                this.sessionid = value;
            }
        }

        public ISymmetricCryptoProvider SymmetricCryptoProvider
        {
            get
            {
                return this.symmetricCryptoProvider;
            }
            set
            {
                this.symmetricCryptoProvider = value;
            }
        }

        public IHashProvider HashProvider
        {
            get
            {
                return this.hashProvider;
            }
            set
            {
                this.hashProvider = value;
            }
        }

        public SecureQueryString(byte[] key)
        {
            this.symmetricCryptoProvider = new SymmetricAlgorithmProvider(key);
            this.hashProvider = new HashAlgorithmProvider();
            this.key = key;
        }

        public SecureQueryString()
            : this(Globals.SecureQueryStringKey)
        {
        }

        public SecureQueryString(byte[] key, string queryString)
            : this(key)
        {
            this.Deserialize(this.DecryptAndVerify(queryString.Replace(" ", "+")));
            this.CheckExpiration();
            //this.CheckValidSession();
        }

        public SecureQueryString(string queryString)
            : this(Globals.SecureQueryStringKey, queryString)
        {
        }

        public override string ToString()
        {
            return HttpUtility.HtmlEncode(this.EncryptAndSign(this.Serialize()));
        }

        private string Hex(string sData)
        {
            string a = string.Empty;
            string str = string.Empty;
            StringBuilder stringBuilder = new StringBuilder(sData.Length * 2);
            for (int i = 0; i < sData.Length; i++)
            {
                if (sData.Length - (i + 1) > 0)
                {
                    a = sData.Substring(i, 2);
                    if (a == "\\n")
                    {
                        str += "0A";
                    }
                    else
                    {
                        if (a == "\\b")
                        {
                            str += "20";
                        }
                        else
                        {
                            if (a == "\\r")
                            {
                                str += "0D";
                            }
                            else
                            {
                                if (a == "\\c")
                                {
                                    str += "2C";
                                }
                                else
                                {
                                    if (a == "\\\\")
                                    {
                                        str += "5C";
                                    }
                                    else
                                    {
                                        if (a == "\\0")
                                        {
                                            str += "00";
                                        }
                                        else
                                        {
                                            if (a == "\\t")
                                            {
                                                str += "07";
                                            }
                                            else
                                            {
                                                stringBuilder.Append(string.Format("{0:X2}", (int)sData.ToCharArray()[i]));
                                                i--;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    stringBuilder.Append(string.Format("{0:X2}", (int)sData.ToCharArray()[i]));
                }
                i++;
            }
            return stringBuilder.ToString();
        }

        private string DeHex(string hexstring)
        {
            string arg_05_0 = string.Empty;
            StringBuilder stringBuilder = new StringBuilder(hexstring.Length / 2);
            for (int i = 0; i <= hexstring.Length - 1; i += 2)
            {
                stringBuilder.Append((char)int.Parse(hexstring.Substring(i, 2), NumberStyles.HexNumber));
            }
            return stringBuilder.ToString();
        }

        private void Deserialize(string queryString)
        {
            string[] array = queryString.Split(new char[]
			{
				'&'
			});
            for (int i = 0; i < array.Length; i++)
            {
                string[] array2 = array[i].Split(new char[]
				{
					'='
				});
                if (array2.Length == 2)
                {
                    base.Add(array2[0], array2[1]);
                }
            }
            if (base["__TS__"] != null)
            {
                this.expireTime = DateTime.Parse(base["__TS__"], CultureInfo.InvariantCulture);
            }
            if (base["sessionid"] != null)
            {
                this.sessionid = base["sessionid"].ToString();
            }
        }

        private string Serialize()
        {
            StringBuilder stringBuilder = new StringBuilder();
            string[] allKeys = base.AllKeys;
            for (int i = 0; i < allKeys.Length; i++)
            {
                string text = allKeys[i];
                stringBuilder.Append(text);
                stringBuilder.Append('=');
                stringBuilder.Append(base[text]);
                stringBuilder.Append('&');
            }
            stringBuilder.Append("__TS__");
            stringBuilder.Append('=');
            stringBuilder.Append(this.expireTime.ToString("G", CultureInfo.InvariantCulture));
            stringBuilder.Append('&');
            stringBuilder.Append("sessionid");
            stringBuilder.Append('=');
            stringBuilder.Append(HttpContext.Current.Session.SessionID);
            return stringBuilder.ToString();
        }

        private string DecryptAndVerify(string input)
        {
            byte[] bytes = null;
            try
            {
                if (Globals.SignQueryString)
                {
                    byte[] array = Convert.FromBase64String(input);
                    byte b = array[0];
                    byte[] array2 = new byte[(int)b];
                    Buffer.BlockCopy(array, 1, array2, 0, (int)b);
                    byte[] array3 = new byte[array.Length - (int)b - 1];
                    Buffer.BlockCopy(array, (int)(b + 1), array3, 0, array3.Length);
                    byte[] array4 = this.hashProvider.Hash(this.CombineBytes(this.key, array3));
                    if (!CommonUtil.CompareBytes(array2, array4))
                    {
                        throw new InvalidQueryStringException("Query string was improperly signed or tampered with");
                    }
                    bytes = this.symmetricCryptoProvider.Decrypt(array3);
                }
                else
                {
                    byte[] ciphertext = Convert.FromBase64String(input);
                    bytes = this.symmetricCryptoProvider.Decrypt(ciphertext);
                }
            }
            catch (Exception)
            {
                throw new InvalidQueryStringException();
            }
            return Encoding.Unicode.GetString(bytes);
        }

        private string EncryptAndSign(string input)
        {
            if (Globals.SignQueryString)
            {
                byte[] buffer = this.symmetricCryptoProvider.Encrypt(Encoding.Unicode.GetBytes(input));
                byte[] array = this.hashProvider.Hash(this.CombineBytes(this.key, buffer));
                byte[] buffer2 = this.CombineBytes(array, buffer);
                byte[] buffer3 = new byte[]
				{
					(byte)array.Length
				};
                return Convert.ToBase64String(this.CombineBytes(buffer3, buffer2));
            }
            return Convert.ToBase64String(this.symmetricCryptoProvider.Encrypt(Encoding.Unicode.GetBytes(input)));
        }

        private void CheckExpiration()
        {
            if (DateTime.Compare(this.ExpireTime, DateTime.Now) < 0)
            {
                throw new ExpiredQueryStringException();
            }
        }

        private void CheckValidSession()
        {
            if (this.SessionID != HttpContext.Current.Session.SessionID)
            {
                throw new SessionNotMatchException();
            }
        }

        private byte[] CombineBytes(byte[] buffer1, byte[] buffer2)
        {
            byte[] array = new byte[buffer1.Length + buffer2.Length];
            Buffer.BlockCopy(buffer1, 0, array, 0, buffer1.Length);
            Buffer.BlockCopy(buffer2, 0, array, buffer1.Length, buffer2.Length);
            return array;
        }
    }
}