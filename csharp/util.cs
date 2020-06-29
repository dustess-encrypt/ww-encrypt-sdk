using System;
using Newtonsoft.Json;
namespace crypt
{
    /// <summary>
    /// 工具类
    /// </summary>
   static class Util
    {
        /// <summary>
        /// 反序列化Json数据为指定对象
        /// </summary>
        /// <typeparam name="T">类型</typeparam>
        /// <param name="str">入参</param>
        /// <returns></returns>
        public static T Deserialize<T>(string str)
        {
            if (string.IsNullOrEmpty(str))
            {
                throw new ArgumentNullException("Error", "str can't be empty or null.");
            }
            return JsonConvert.DeserializeObject<T>(str);
        }

        /// <summary>
        /// 序列化对象为Json数据
        /// </summary>
        /// <param name="obj">对象</param>
        /// <returns>序列化后的字符串</returns>
        public static string Serialize(object obj)
        {
            if (obj == null)
            {
                throw new ArgumentNullException("Error", "obj can't be null.");
            }
            return JsonConvert.SerializeObject(obj);
        }

        /// <summary>
        /// 生成随机字符串
        /// </summary>
        /// <returns>随机字符串</returns>
        public static string GetRandomString(int codeLen)
        {
            string codeSerial = "2,3,4,5,6,7,a,c,d,e,f,h,i,j,k,m,n,p,r,s,t,A,C,D,E,F,G,H,J,K,M,N,P,Q,R,S,U,V,W,X,Y,Z";
            if (codeLen == 0)
            {
                codeLen = 16;
            }
            string[] arr = codeSerial.Split(',');
            string code = "";
            int randValue = -1;
            Random rand = new Random(unchecked((int)DateTime.Now.Ticks));
            for (int i = 0; i < codeLen; i++)
            {
                randValue = rand.Next(0, arr.Length - 1);
                code += arr[randValue];
            }
            return code;
        }

        /// <summary> 
        /// 获取时间戳 
        /// </summary> 
        /// <returns></returns> 
        public static string GetTimeStamp()
        {
            TimeSpan ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0);
            return Convert.ToInt64(ts.TotalSeconds).ToString();
        }
    }
}
