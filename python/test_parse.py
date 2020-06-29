# -*- coding：utf-8 -*-

"""
加解密测试
"""

from unittest import TestCase
from parse import WXBizMsgCrypt, MsgData
from parameterized import parameterized, param
from ierror import WXBizMsgCrypt_OK


class TestAES(TestCase):
    """
    测试aes加解密
    """
    token = "thisisatoken"
    aes_key = "jWmYm7qr5nMoAUwZRjGtBxmz3KA1tkAj3ykkR6q2B2C"
    input = "hello world 哈喽 "
    company_id = "P00000000023"

    def crypt(self):
        return WXBizMsgCrypt(self.token, self.aes_key, self.company_id)

    def test_encode(self):
        """
        加密
        :return:
        """
        nonce = "EDH75AiKExevY8L3"
        timestamp = "1592916319"
        ret, msg_data = self.crypt().EncryptMsg(self.input, nonce, timestamp)
        assert ret == WXBizMsgCrypt_OK, "msg_data:" + msg_data
        print(msg_data)

    def test_encode_and_decode(self):
        """
        加解密
        :return:
        """
        nonce = "EDH75AiKExevY8L3"
        timestamp = "1592916319"
        ret, msg_data = self.crypt().EncryptMsg(self.input, nonce, timestamp)
        assert ret == WXBizMsgCrypt_OK, "ret:%d" % ret
        assert msg_data != None, "msg_data 不能是none"
        ret, msg_data = self.crypt().DecryptMsgData(msg_data)
        assert ret == WXBizMsgCrypt_OK, f"ret!={ret}"
        if isinstance(msg_data, (bytes,)):
            msg_data = msg_data.decode()  # 显示中文啊
        print(msg_data)

    @parameterized.expand([
        param("CZWs4CWRpI4VolQlvn4dlPb2f0uQxokbSIZGwiT1u44MCk4o6Iw6R/zVkcFkIdMCxD99C7nyOfERckg+HnjgMw==",
              "d8a328f4957174415ac09446f690be0f491c0895", "1593325356", "EDH75AiKExevY8L3"),
        param("RSZ3zTLyHduRfE+eJ07Mi5HFE/5TXGaXAumHoli36eFMpdblxY2dqR+Vhv7yfKCkTsZLSkIeecEGCVyMQ76u7A==",
              "ff310278354c75a4235c81d2f95862416f67dbee", "1593333518", "lvsomfeujrn6bhdg")

    ])
    def test_decode(self, encrypt, signature, timestamp, nonce):
        """
        解密指定数据
        {
            "Encrypt": "CZWs4CWRpI4VolQlvn4dlPb2f0uQxokbSIZGwiT1u44MCk4o6Iw6R/zVkcFkIdMCxD99C7nyOfERckg+HnjgMw==",
            "Signature": "d8a328f4957174415ac09446f690be0f491c0895",
             "TimeStamp": "1593325356",
             "Nonce": "EDH75AiKExevY8L3"
         }
        :return:
        """
        # encrypt = "CZWs4CWRpI4VolQlvn4dlPb2f0uQxokbSIZGwiT1u44MCk4o6Iw6R/zVkcFkIdMCxD99C7nyOfERckg+HnjgMw=="
        # signature = "d8a328f4957174415ac09446f690be0f491c0895"
        # timestamp = "1593325356"
        # nonce = "EDH75AiKExevY8L3"
        msg_data = MsgData(encrypt=encrypt, signature=signature, timestamp=timestamp, nonce=nonce)
        ret, msg = self.crypt().DecryptMsgData(msg_data)
        assert ret == WXBizMsgCrypt_OK, f"ret!={ret}"
        print(f"{encrypt}解析：\n", msg.decode())
