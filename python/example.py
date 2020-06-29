# -*- coding：utf-8 -*-

from parse import WXBizMsgCrypt
from ierror import WXBizMsgCrypt_OK

# 配置
token = "thisisatoken"
aes_key = "jWmYm7qr5nMoAUwZRjGtBxmz3KA1tkAj3ykkR6q2B2C"
company_id = "P00000000023"

if __name__ == '__main__':
    # 加密 然后解密
    send_msg = "hello你好，我是数据发送方 world!"
    # 初始化配置
    crypt = WXBizMsgCrypt(token, aes_key, company_id)
    # 加密
    ret, msg_data = crypt.EncryptMsg(send_msg)
    assert ret == WXBizMsgCrypt_OK, f"加密失败{ret}"
    assert msg_data is not None, "加密失败"
    # 解密
    ret, msg = crypt.DecryptMsgData(msg_data)
    assert ret == WXBizMsgCrypt_OK, f"解密失败{ret}"
    print(u'数据接收方解密数据:%s' % msg.decode())  # 坑，显示中文真难
    # encrypt_data = msg_data.encrypt
    # signature = msg_data.signature
    # timestamp = msg_data.timestamp
    # nonce = msg_data.nonce
    # ret, msg = crypt.DecryptMsg(encrypt_data, signature, timestamp, nonce)
    # assert ret == 0, f"解密失败{ret}"
    # print(u'%s' % msg.decode())  # 坑*编码转换
