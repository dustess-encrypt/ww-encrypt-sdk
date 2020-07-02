using System;
using System.Text;
using System.Collections;
using System.Security.Cryptography;
namespace crypt
{
    class BizMsgCrypt
    {
        string m_sToken;
        string m_sEncodingAESKey;
        string m_receiveId;

        enum BizMsgCryptErrorCode
        {
            BizMsgCrypt_OK = 0,
            BizMsgCrypt_ValidateSignature_Error = -40001,
            BizMsgCrypt_ParseXml_Error = -40002,
            BizMsgCrypt_ComputeSignature_Error = -40003,
            BizMsgCrypt_IllegalAesKey = -40004,
            BizMsgCrypt_ValidateReceiveId_Error = -40005,
            BizMsgCrypt_EncryptAES_Error = -40006,
            BizMsgCrypt_DecryptAES_Error = -40007,
            BizMsgCrypt_IllegalBuffer = -40008,
            BizMsgCrypt_EncodeBase64_Error = -40009,
            BizMsgCrypt_DecodeBase64_Error = -40010
        };

        /// <summary>
        /// 构造函数
        /// </summary>
        /// <param name="sToken">token</param>
        /// <param name="receiveId">公司ID</param>
        /// <param name="sEncodingAESKey">密钥</param>
        public BizMsgCrypt(string sToken, string receiveId, string sEncodingAESKey)
        {
            m_sToken = sToken;
            m_sEncodingAESKey = sEncodingAESKey;
            m_receiveId = receiveId;
        }

        /// <summary>
        /// 验证url
        /// </summary>
        /// <param name="sMsgSignature">签名串，对应URL的Signature参数</param>
        /// <param name="sTimeStamp">时间戳，对应URL的Timestamp</param>
        /// <param name="sNonce">随机串，对应URL的Nonce</param>
        /// <param name="sEchoStr">随机串，对应URL参数的echostr</param>
        /// <param name="sReplyEchoStr">解密之后的数据</param>
        /// <returns></returns>
        public int VerifyURL(string sMsgSignature, string sTimeStamp, string sNonce, string sEchoStr, ref string sReplyEchoStr)
        {
            int ret = 0;
            if (m_sEncodingAESKey.Length != 43)
            {
                return (int)BizMsgCryptErrorCode.BizMsgCrypt_IllegalAesKey;
            }
            ret = VerifySignature(m_sToken, sTimeStamp, sNonce, sEchoStr, sMsgSignature);
            if (0 != ret)
            {
                return ret;
            }
            sReplyEchoStr = "";
            string receiveId = "";
            try
            {
                sReplyEchoStr = Cryptography.AES_decrypt(sEchoStr, m_sEncodingAESKey, ref receiveId); //m_sReceiveId);
            }
            catch (Exception)
            {
                sReplyEchoStr = "";
                return (int)BizMsgCryptErrorCode.BizMsgCrypt_DecryptAES_Error;
            }
            if (receiveId != m_receiveId)
            {
                sReplyEchoStr = "";
                return (int)BizMsgCryptErrorCode.BizMsgCrypt_ValidateReceiveId_Error;
            }
            return 0;
        }

        /// <summary>
        /// 消息解密
        /// </summary>
        /// <param name="sMsgSignature">签名</param>
        /// <param name="sTimeStamp">时间戳</param>
        /// <param name="sNonce">随机字符</param>
        /// <param name="sPostData">密文</param>
        /// <param name="sMsg">解密后的原文，当return返回0时有效</param>
        /// <returns>成功0，失败返回对应的错误码</returns>
        public int DecryptMsg(string sMsgSignature, string sTimeStamp, string sNonce, string sPostData, ref string sMsg)
        {
            if (m_sEncodingAESKey.Length != 43)
            {
                return (int)BizMsgCryptErrorCode.BizMsgCrypt_IllegalAesKey;
            }

            // 反序列化数据
            var msg = Util.Deserialize<BizMsg4Recv>(sPostData);
            var ret = 0;
            ret = VerifySignature(m_sToken, sTimeStamp, sNonce, msg.Encrypt, sMsgSignature);
            if (ret != 0)
                return ret;

            string reviceId = "";
            try
            {
                sMsg = Cryptography.AES_decrypt(msg.Encrypt, m_sEncodingAESKey, ref reviceId);
            }
            catch (FormatException)
            {
                sMsg = "";
                return (int)BizMsgCryptErrorCode.BizMsgCrypt_DecodeBase64_Error;
            }
            catch (Exception)
            {
                sMsg = "";
                return (int)BizMsgCryptErrorCode.BizMsgCrypt_DecryptAES_Error;
            }
            if (reviceId != m_receiveId)
                return (int)BizMsgCryptErrorCode.BizMsgCrypt_ValidateReceiveId_Error;
            return 0;
        }

        /// <summary>
        /// 消息加密
        /// </summary>
        /// <param name="sReplyMsg">待加密的字符串</param>
        /// <param name="sEncryptMsg">加密后的密文</param>
        /// <returns>成功0，失败返回对应的错误码</returns>
        public int EncryptMsg(string sReplyMsg, ref string sEncryptMsg)
        {
            // 获取时间戳和随机字符串
            var sTimeStamp = Util.GetTimeStamp();
            var sNonce = Util.GetRandomString(16);
            if (m_sEncodingAESKey.Length != 43)
            {
                return (int)BizMsgCryptErrorCode.BizMsgCrypt_IllegalAesKey;
            }

            string raw = "";
            try
            {
                raw = Cryptography.AES_encrypt(sReplyMsg, m_sEncodingAESKey, m_receiveId);
            }
            catch (Exception)
            {
                return (int)BizMsgCryptErrorCode.BizMsgCrypt_EncryptAES_Error;
            }

            string MsgSigature = "";
            int ret = 0;
            ret = GenarateSinature(m_sToken, sTimeStamp, sNonce, raw, ref MsgSigature);
            if (0 != ret)
                return ret;
            var send = new BizMsg4Send(MsgSigature, raw, sTimeStamp, sNonce);
            sEncryptMsg = Util.Serialize(send);

            return 0;
        }

        public class DictionarySort : System.Collections.IComparer
        {
            public int Compare(object oLeft, object oRight)
            {
                string sLeft = oLeft as string;
                string sRight = oRight as string;
                int iLeftLength = sLeft.Length;
                int iRightLength = sRight.Length;
                int index = 0;
                while (index < iLeftLength && index < iRightLength)
                {
                    if (sLeft[index] < sRight[index])
                        return -1;
                    else if (sLeft[index] > sRight[index])
                        return 1;
                    else
                        index++;
                }
                return iLeftLength - iRightLength;

            }
        }

        /// <summary>
        /// 验证签名
        /// </summary>
        /// <param name="sToken">token</param>
        /// <param name="sTimeStamp">时间戳</param>
        /// <param name="sNonce">随机字符串</param>
        /// <param name="sMsgEncrypt"></param>
        /// <param name="sSigture">前面</param>
        /// <returns></returns>
        private static int VerifySignature(string sToken, string sTimeStamp, string sNonce, string sMsgEncrypt, string sSigture)
        {
            string hash = "";
            int ret = 0;
            ret = GenarateSinature(sToken, sTimeStamp, sNonce, sMsgEncrypt, ref hash);
            if (ret != 0)
                return ret;
            if (hash == sSigture)
                return 0;
            else
            {
                return (int)BizMsgCryptErrorCode.BizMsgCrypt_ValidateSignature_Error;
            }
        }

        public static int GenarateSinature(string sToken, string sTimeStamp, string sNonce, string sMsgEncrypt, ref string sMsgSignature)
        {
            ArrayList AL = new ArrayList();
            AL.Add(sToken);
            AL.Add(sTimeStamp);
            AL.Add(sNonce);
            AL.Add(sMsgEncrypt);
            AL.Sort(new DictionarySort());
            string raw = "";
            for (int i = 0; i < AL.Count; ++i)
            {
                raw += AL[i];
            }

            SHA1 sha;
            ASCIIEncoding enc;
            string hash = "";
            try
            {
                sha = new SHA1CryptoServiceProvider();
                enc = new ASCIIEncoding();
                byte[] dataToHash = enc.GetBytes(raw);
                byte[] dataHashed = sha.ComputeHash(dataToHash);
                hash = BitConverter.ToString(dataHashed).Replace("-", "");
                hash = hash.ToLower();
            }
            catch (Exception)
            {
                return (int)BizMsgCryptErrorCode.BizMsgCrypt_ComputeSignature_Error;
            }
            sMsgSignature = hash;
            return 0;
        }
    }
}


class BizMsg4Recv
{
    // 消息类型
    public String MsgType;

    // 密文
    public String Encrypt;
}

class BizMsg4Send
{
    // 签名串，对应URL的Signature参数
    public String Signature;

    // 密文
    public String Encrypt;

    // 时间戳
    public String Timestamp;

    // 随机串
    public String Nonce;

    /// <summary>
    /// 构造方法
    /// </summary>
    /// <param name="signature">签名串，对应URL的Signature参数</param>
    /// <param name="encrypt">密文</param>
    /// <param name="timeStamp">时间戳</param>
    /// <param name="nonce">随机字符串</param>
    public BizMsg4Send(string signature, string encrypt, string timeStamp, string nonce)
    {
        this.Encrypt = encrypt;
        this.Signature = signature;
        this.Timestamp = timeStamp;
        this.Nonce = nonce;
    }
}