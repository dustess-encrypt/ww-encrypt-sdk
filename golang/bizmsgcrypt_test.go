package crypt

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestBizMsgCrypt_EncryptMsg(t *testing.T) {
	token := "thisisatoken"
	encodingAesKey := "jWmYm7qr5nMoAUwZRjGtBxmz3KA1tkAj3ykkR6q2B2C"
	receiveId := "P00000000023"

	crypt := NewBizMsgCrypt(token, encodingAesKey, receiveId, JsonType)

	type Msg struct{
		Name string
	}

	msg := Msg{
		Name: "哈哈",
	}

	marshal, _ := json.Marshal(msg)
	//timeStamp := time.Now().Unix()
	//formatInt := strconv.FormatInt(timeStamp, 10)
	//fmt.Println(formatInt)
	encryptMsg, e := crypt.EncryptMsg(string(marshal))
	if e != nil {
		fmt.Println(e)
	}
	fmt.Printf("%v",encryptMsg)
}

func TestBizMsgCrypt_DecryptMsg(t *testing.T) {
	token := "thisisatoken"
	encodingAesKey := "jWmYm7qr5nMoAUwZRjGtBxmz3KA1tkAj3ykkR6q2B2C"
	receiveId := "P00000000023"

	crypt := NewBizMsgCrypt(token, encodingAesKey, receiveId, JsonType)
	recv := BizMsg4Recv{
		MsgType: "add_customer",
		Encrypt: "CZWs4CWRpI4VolQlvn4dlHCxcccOUldh2dM/HUHjz9lmXN+DbNparH5f3mPPDG0EBhuCYhE+vJ5SXkNCcAN7jg==",
	}
	marshal, _ := json.Marshal(recv)
	msg, e := crypt.DecryptMsg("fe2c1539b7d56e35bec5e302da15bad2f563b854", "1592552065", "EDH75AiKExevY8L3", marshal)
	if e != nil {
		fmt.Println(e)
	}

	type Msg struct{
		Name string
	}
	msg1 := Msg{}
	err := json.Unmarshal(msg, &msg1)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(msg1)

}

func TestBizMsgCrypt_VerifyURL(t *testing.T) {
	token := "thisisatoken"
	encodingAesKey := "jWmYm7qr5nMoAUwZRjGtBxmz3KA1tkAj3ykkR6q2B2C"
	receiveId := "P00000000023"
	crypt := NewBizMsgCrypt(token, encodingAesKey, receiveId, JsonType)
	/*

		先用加密获取到消息体签名（msgSignature）、时间戳(timestamp)、随机数字串(nonce)、数据加密字符串(echostr)
	   	------------使用示例一：验证回调URL---------------
	   	*企业开启回调模式时，企业微信会向验证url发送一个get请求
	   	假设点击验证时，企业收到类似请求：
	   	* GET /cgi-bin/push?msg_signature=5c45ff5e21c57e6ad56bac8758b79b1d9ac89fd3&timestamp=1409659589&nonce=263014780&echostr=P9nAzCzyDtyTWESHep1vC5X9xho%2FqYX3Zpb4yKa9SKld1DsH3Iyt3tP3zNdtp%2B4RPcs8TgAE7OaBO%2BFZXvnaqQ%3D%3D
	   	* HTTP/1.1 Host: mk.dustess.com

	   	接收到该请求时，企业应
	        1.解析出Get请求的参数，包括消息体签名(msg_signature)，时间戳(timestamp)，随机数字串(nonce)以及企业微信推送过来的随机加密字符串(echostr),
	        这一步注意作URL解码。
	        2.验证消息体签名的正确性
	        3. 解密出echostr原文，将原文当作Get请求的response，返回给企业微信
	        第2，3步可以用企业微信提供的库函数VerifyURL来实现。

	*/
	// 解析出url上的参数值如下：
	// verifyMsgSign := HttpUtils.ParseUrl("msg_signature")
	msgSignature := "02aba3eaf97b8c490876283804d0d76dc30b01d1"
	// verifyTimestamp := HttpUtils.ParseUrl("timestamp")
	timestamp := "1592916319"
	// verifyNonce := HttpUtils.ParseUrl("nonce")
	nonce := "EDH75AiKExevY8L3"
	// verifyEchoStr := HttpUtils.ParseUrl("echoStr")
	verifyEchoStr := "CZWs4CWRpI4VolQlvn4dlF6ZQ1mKb47xql2W2MgYO3kPzC29/TE8bowgSWDrJy8e3lcCJtxDjklMudvItLOEOw=="
	echoStr, cryptErr := crypt.VerifyURL(msgSignature, timestamp, nonce, verifyEchoStr)
	if nil != cryptErr {
		fmt.Println("verifyUrl fail", cryptErr)
	}
	fmt.Println("verifyUrl success echoStr", string(echoStr))
	// 验证URL成功，将sEchoStr返回
	// HttpUtils.SetResponse(sEchoStr)
}