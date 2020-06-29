using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace crypt
{
    class Program
    {
        static void Main(string[] args)
        {

            string sToken = "thisisatoken";
            string companyId = "P00000000023";
            string sEncodingAESKey = "jWmYm7qr5nMoAUwZRjGtBxmz3KA1tkAj3ykkR6q2B2C";
            var wxcpt = new WXBizMsgCrypt(sToken, companyId, sEncodingAESKey);

            /*
			------------使用示例1：消息解密---------------
			企业收到post请求之后解析出url上的参数，包括消息体签名(Signature)，时间戳(Timestamp)以及随机数字串(Nonce)，以及加密字符串（Encrypt）
			2.验证消息体签名的正确性。
			3.将post请求的数据进行json解析，并将<Encrypt>标签的内容进行解密，解密出来的明文即是用户回复消息的明文，明文格式请参考官方文档
			第2，3步可以用企业微信提供的库函数DecryptMsg来实现。
			*/

            string sReqMsgSig = "1c4bb9c4f152249c8c82c8bef37c764a5387ebcc";
            string sReqTimeStamp = "1593335246";
            string sReqNonce = "fKFadfQepSA7Y6cX";
            string sReqData = "{\"Signature\":\"1c4bb9c4f152249c8c82c8bef37c764a5387ebcc\",\"Encrypt\":\"8DXg6XnAihaz7+VMxRCTE53Y7tWQ4JCgQYBCugaHBMwls0FcmRaRiK1wbNRCpM3Cn3kTF+BOAn/uedl4fa6Okw==\",\"Timestamp\":\"1593335246\",\"Nonce\":\"fKFadfQepSA7Y6cX\"}";
            string sMsg = "";  // 解析之后的明文
            var ret = wxcpt.DecryptMsg(sReqMsgSig, sReqTimeStamp, sReqNonce, sReqData, ref sMsg);
            if (ret != 0)
            {
                System.Console.WriteLine("ERR: Decrypt Fail, ret: " + ret);
                return;
            }

            /*
             ------------使用示例2：回复用户消息的加密---------------
             企业被动回复用户的消息也需要进行加密，并且拼接成密文格式的json串。
             假设企业需要回复用户的明文如下：
             {\"Name\":\"张三\",\"Age\":180}
             为了将此段明文回复给用户，企业应：
             1.自己将数据序列化为json字符串。
             2.将明文加密得到密文。	
             3.用密文，步骤1生成的包括消息体签名(Signature)，时间戳(Timestamp)以及随机数字串(Nonce)生成消息体签名。			
             4.将密文，消息体签名，时间戳，随机数字串拼接成json格式的字符串，发送给企业。
             以上2，3，4步可以用尘封信息提供的库函数EncryptMsg来实现。
             */
            string sEncryptMsg = "{\"Name\":\"张三\",\"Age\":180}"; //原文
            string resp="";// 加密后的秘文，里面包含时间戳，随机串，签名等数据
            ret = wxcpt.EncryptMsg(sEncryptMsg,  ref resp);
            if (ret != 0)
            {
                System.Console.WriteLine("ERR: EncryptMsg Fail, ret: " + ret);
                return;
            }


            /*
			------------使用示例3：验证回调URL---------------
			*企业开启回调模式时，尘封信息会向验证url发送一个get请求 
			假设点击验证时，企业收到类似请求：
			* GET /dustess/push?Signature=1c4bb9c4f152249c8c82c8bef37c764a5387ebcc&Timestamp=1593335246&Nonce=fKFadfQepSA7Y6cX&Encrypt=8DXg6XnAihaz7+VMxRCTE53Y7tWQ4JCgQYBCugaHBMwls0FcmRaRiK1wbNRCpM3Cn3kTF+BOAn/uedl4fa6Okw== 
			* HTTP/1.1 Host: mk.dustess.com
			* 接收到该请求时，请求之后解析出url上的参数，包括消息体签名(Signature)，时间戳(Timestamp)以及随机数字串(Nonce)，以及加密字符串（Encrypt）
			这一步注意作URL解码。
			2.验证消息体签名的正确性 
			3.解密出Encrypt原文，将原文当作Get请求的response，返回给尘封信息
			第2，3步可以用尘封信息提供的库函数VerifyURL来实现。
			*/
            string sVerifyMsgSig = "1c4bb9c4f152249c8c82c8bef37c764a5387ebcc";
            string sVerifyTimeStamp = "1593335246";
            string sVerifyNonce = "fKFadfQepSA7Y6cX";
            string sVerifyEchoStr = "8DXg6XnAihaz7+VMxRCTE53Y7tWQ4JCgQYBCugaHBMwls0FcmRaRiK1wbNRCpM3Cn3kTF+BOAn/uedl4fa6Okw==";
            string sEchoStr = "";
            ret = wxcpt.VerifyURL(sVerifyMsgSig, sVerifyTimeStamp, sVerifyNonce, sVerifyEchoStr, ref sEchoStr);
            if (ret != 0)
            {
                System.Console.WriteLine("ERR: VerifyURL fail, ret: " + ret);
                return;
            }

            Console.ReadKey();
        }
    }
}
