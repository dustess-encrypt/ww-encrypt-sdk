### 目录说明
1. parse.py 加解密实现
2. example.py 简单的例子
3. ierror.py 错误码

### 为了避免不必要的意外 文件头还是加上吧
```python
#-*- coding：utf-8 -*- 
```

### 环境
```shell script
pip install pipenv
pipenv install
```
### 流程
```python
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
    print(u'数据接收方解密数据:%s' % msg.decode())  
```