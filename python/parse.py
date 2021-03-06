# -*- coding：utf-8 -*-

import logging
import base64
import random
import hashlib
import time
import struct
from Crypto.Cipher import AES
import xml.etree.cElementTree as ET
import socket

import ierror


class FormatException(Exception):
    """
    自定义异常
    """
    pass


def throw_exception(message, exception_class=FormatException):
    """my define raise exception function"""
    raise exception_class(message)


class SHA1:
    """计算企业微信的消息签名接口"""

    def getSHA1(self, token, timestamp, nonce, encrypt):
        """用SHA1算法生成安全签名
        @param token:  票据
        @param timestamp: 时间戳
        @param encrypt: 密文
        @param nonce: 随机字符串
        @return: 安全签名
        """
        try:
            sortlist = [token, timestamp, nonce, encrypt]
            sortlist.sort()
            sha = hashlib.sha1()
            sha.update("".join(sortlist).encode())
            return ierror.WXBizMsgCrypt_OK, sha.hexdigest()
        except Exception as e:
            logger = logging.getLogger()
            logger.error(e)
            return ierror.WXBizMsgCrypt_ComputeSignature_Error, None


class MsgData:
    """
    加解密 数据结构体
    """
    encrypt = ""
    signature = ""
    timestamp = ""
    nonce = ""

    def __init__(self, encrypt: str, signature: str, timestamp: str, nonce: str):
        self.encrypt = encrypt
        self.signature = signature
        self.timestamp = timestamp
        self.nonce = nonce

    def __str__(self):
        return f'encrypt:{self.encrypt}\nsignature:{self.signature}\ntimestamp:{self.timestamp}\nnonce:{self.nonce}\n'


class PKCS7Encoder:
    """提供基于PKCS7算法的加解密接口"""

    block_size = 32

    def encode(self, text):
        """ 对需要加密的明文进行填充补位
        @param text: 需要进行填充补位操作的明文
        @return: 补齐明文字符串
        """
        text_length = len(text)
        # 计算需要填充的位数
        amount_to_pad = self.block_size - (text_length % self.block_size)
        if amount_to_pad == 0:
            amount_to_pad = self.block_size
        # 获得补位所用的字符
        pad = chr(amount_to_pad)
        return text + (pad * amount_to_pad).encode()

    def decode(self, decrypted):
        """删除解密后明文的补位字符
        @param decrypted: 解密后的明文
        @return: 删除补位字符后的明文
        """
        pad = ord(decrypted[-1])
        if pad < 1 or pad > 32:
            pad = 0
        return decrypted[:-pad]


class Prpcrypt:
    """提供接收和推送给企业微信消息的加解密接口"""

    def __init__(self, key):

        # self.key = base64.b64decode(key+"=")
        self.key = key
        # 设置加解密模式为AES的CBC模式
        self.mode = AES.MODE_CBC

    def encrypt(self, text: str, receiveid: str):
        """对明文进行加密
        @param text: 需要加密的明文
        @return: 加密得到的字符串
        """
        # 16位随机字符串添加到明文开头
        text = text.encode()
        text = self.get_random_str() + struct.pack("I", socket.htonl(len(text))) + text + receiveid.encode()

        # 使用自定义的填充方式对明文进行补位填充
        pkcs7 = PKCS7Encoder()
        text = pkcs7.encode(text)
        # 加密
        cryptor = AES.new(self.key, self.mode, self.key[:16])
        try:
            ciphertext = cryptor.encrypt(text)
            # 使用BASE64对加密后的字符串进行编码
            return ierror.WXBizMsgCrypt_OK, base64.b64encode(ciphertext)
        except Exception as e:
            logger = logging.getLogger()
            logger.error(e)
            return ierror.WXBizMsgCrypt_EncryptAES_Error, None

    def decrypt(self, text, receiveid) -> (int, bytes):
        """对解密后的明文进行补位删除
        @param text: 密文
        @return: 删除填充补位后的明文
        """
        try:
            cryptor = AES.new(self.key, self.mode, self.key[:16])
            # 使用BASE64对密文进行解码，然后AES-CBC解密
            plain_text = cryptor.decrypt(base64.b64decode(text))
        except Exception as e:
            logger = logging.getLogger()
            logger.error(e)
            return ierror.WXBizMsgCrypt_DecryptAES_Error, None
        try:
            pad = plain_text[-1]
            # 去掉补位字符串
            # pkcs7 = PKCS7Encoder()
            # plain_text = pkcs7.encode(plain_text)
            # 去除16位随机字符串
            content = plain_text[16:-pad]
            xml_len = socket.ntohl(struct.unpack("I", content[: 4])[0])
            xml_content = content[4: xml_len + 4]
            from_receiveid = content[xml_len + 4:]
        except Exception as e:
            logger = logging.getLogger()
            logger.error(e)
            return ierror.WXBizMsgCrypt_IllegalBuffer, None

        if from_receiveid.decode('utf8') != receiveid:
            return ierror.WXBizMsgCrypt_ValidateCorpid_Error, None
        return 0, xml_content

    def get_random_str(self) -> bytes:
        """ 随机生成16位字符串
        @return: 16位字符串
        """
        return str(random.randint(1000000000000000, 9999999999999999)).encode()


class WXBizMsgCrypt:
    # 构造函数
    def __init__(self, token: str, aes_key: str, receive_id: str):
        """

        :param token:  token
        :param aes_key: aes 密匙
        :param receive_id:   公司
        """
        try:
            self.key = base64.b64decode(aes_key + "=")
            assert len(self.key) == 32
        except:
            throw_exception("[error]: aes_key unvalid !", FormatException)
            # return ierror.WXBizMsgCrypt_IllegalAesKey,None
        self.m_sToken = token
        self.receive_id = receive_id

    def VerifyURL(self, sMsgSignature: str, sTimeStamp: str, sNonce: str, sEchoStr: str) -> (int, str):
        """
        验证url
        :param sMsgSignature: : 签名串，对应URL参数的msg_signature
        :param sTimeStamp: 时间戳，对应URL参数的timestamp
        :param sNonce: 随机串，对应URL参数的nonce
        :param sEchoStr: 随机串，对应URL参数的echostr
        :returns:
            ret: 成功0，失败返回对应的错误码
            sReplyEchoStr: 解密之后的echostr，当return返回0时有效
        """
        sha1 = SHA1()
        ret, signature = sha1.getSHA1(self.m_sToken, sTimeStamp, sNonce, sEchoStr)
        if ret != 0:
            return ret, None
        if not signature == sMsgSignature:
            return ierror.WXBizMsgCrypt_ValidateSignature_Error, None
        pc = Prpcrypt(self.key)
        ret, sReplyEchoStr = pc.decrypt(sEchoStr, self.receive_id)
        return ret, sReplyEchoStr

    def EncryptMsg(self, data: str, sNonce: str = None, timestamp: str = None) -> (int, MsgData):
        """
        消息加密打包
        :param data: 数据
        :param sNonce: 随机串，防篡改验证
        :param timestamp: 时间戳(秒) 1593335961
        :return:
        """
        pc = Prpcrypt(self.key)
        ret, encrypt = pc.encrypt(data, self.receive_id)
        encrypt = encrypt.decode('utf8')
        if ret != 0:
            return ret, None
        if timestamp is None:
            timestamp = str(int(time.time()))
        if sNonce is None:
            sNonce = str(pc.get_random_str().decode())
        # 生成安全签名
        sha1 = SHA1()
        ret, signature = sha1.getSHA1(self.m_sToken, timestamp, sNonce, encrypt)
        if ret != 0:
            return ret, None
        return ret, MsgData(encrypt, signature, timestamp, sNonce)

    def DecryptMsg(self, msg_data: str, signature: str, timestamp: str, nonce: str) -> (int, bytes):
        """
        解密数据,封装的下面那个
        :param msg_data:
        :param signature:
        :param timestamp:
        :param nonce:
        :return:
        """
        post_data = MsgData(msg_data, signature, timestamp, nonce)
        return self.DecryptMsgData(post_data)

    def DecryptMsgData(self, sPostData: MsgData) -> (int, bytes):
        """
        检验消息的真实性，并且获取解密后的明文
        :param sPostData:
        :return:
        """
        # 验证安全签名
        encrypt = sPostData.encrypt
        sMsgSignature = sPostData.signature
        sTimeStamp = sPostData.timestamp
        sNonce = sPostData.nonce
        sha1 = SHA1()
        ret, signature = sha1.getSHA1(self.m_sToken, sTimeStamp, sNonce, encrypt)
        if ret != 0:
            return ret, None
        if not signature == sMsgSignature:
            return ierror.WXBizMsgCrypt_ValidateSignature_Error, None
        pc = Prpcrypt(self.key)
        ret, xml_content = pc.decrypt(encrypt, self.receive_id)
        return ret, xml_content
