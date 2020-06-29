<?php

include_once "index.php";

// 假设设置的参数如下
$encodingAesKey = "jWmYm7qr5nMoAUwZRjGtBxmz3KA1tkAj3ykkR6q2B2C";
$token = "thisisatoken";
$companyID = "P00000000023";
$bizMsgCrypt =new BizMsgCrypt($token,$encodingAesKey,$companyID);

/*
------------使用示例一：验证回调URL---------------
*企业开启回调模式时，企业号会向验证url发送一个get请求 
假设点击验证时

接收到该请求时，企业应
1.解析出Get请求的参数，包括消息体签名(msg_signature)，时间戳(timestamp)，随机数字串(nonce)以及公众平台推送过来的随机加密字符串(echostr),
这一步注意作URL解码。
2.验证消息体签名的正确性 
3. 解密出echostr原文，将原文当作Get请求的response，返回给公众平台
第2，3步可以用公众平台提供的库函数VerifyURL来实现。

*/

$sVerifyMsgSig = "02aba3eaf97b8c490876283804d0d76dc30b01d1";
$sVerifyTimeStamp = "1592916319";
$sVerifyNonce = "EDH75AiKExevY8L3";
$sVerifyEchoStr = "CZWs4CWRpI4VolQlvn4dlF6ZQ1mKb47xql2W2MgYO3kPzC29/TE8bowgSWDrJy8e3lcCJtxDjklMudvItLOEOw==";

// 需要返回的明文
$sEchoStr = "";

$errCode = $bizMsgCrypt->VerifyURL($sVerifyMsgSig, $sVerifyTimeStamp, $sVerifyNonce, $sVerifyEchoStr, $sEchoStr);
if ($errCode == 0) {
	print("done VerifyURL, sEchoStr : \n");
    var_dump($sEchoStr);
	//
	// 验证URL成功，将sEchoStr返回
	// HttpUtils.SetResponce($sEchoStr);
} else {
	print("ERR: " . $errCode . "\n\n");
}

print("<hr>");

/*
------------使用示例二：对用户回复的消息解密---------------
用户回复消息或者点击事件响应时，企业会收到回调消息，此消息是经过平台加密之后的密文以post形式发送给企业，密文格式请参考官方文档
假设企业收到平台的回调消息如下：
{
	"ToUserName": "wx5823bf96d3bd56c7",
	"Encrypt": "jYKl5gAKBiSvZ694aryRMNxKJhUJFtNCSDS9TgfV7rDtEe0x6FjiuCWenK3dCDOah+qOJ8yS6RERDoFhe4dYsHpyImaoZwiGjTp1RGXr7GEW5Tn21BdmYId4Pzvoi6ieOKWbrzag5v2TzcF9syQtry2Ujg5hLEgmMP1Y3GPKHLJ8Rg1kpASRriNKeoHWnokLHlpVt3Ai45y2Bfqn+GxT7qz+yODK3f9Ygxhkpkvp6EaIDIzvk77r26t6Q/sTGfzBYPsNYI8t811B9UFyr38gwslPQUHYuOUXalAUnqpiZW0=";
	"AgentID": 218
}

企业收到post请求之后应该
1.解析出url上的参数，包括消息体签名(msg_signature)，时间戳(timestamp)以及随机数字串(nonce)
2.验证消息体签名的正确性。
3.将post请求的数据进行json解析，并将<Encrypt>标签的内容进行解密，解密出来的明文即是用户回复消息的明文，明文格式请参考官方文档
第2，3步可以用公众平台提供的库函数DecryptMsg来实现。
*/

$sReqMsgSig = "d8a328f4957174415ac09446f690be0f491c0895";
$sReqTimeStamp = "1593325356";
$sReqNonce = "EDH75AiKExevY8L3";

// post请求的密文数据
$sReqData = '{"Encrypt":"CZWs4CWRpI4VolQlvn4dlPb2f0uQxokbSIZGwiT1u44MCk4o6Iw6R/zVkcFkIdMCxD99C7nyOfERckg+HnjgMw==", "Signature":"d8a328f4957174415ac09446f690be0f491c0895","Nonce":"EDH75AiKExevY8L3","Timestamp":"1593325356"}';
$sMsg = "";  // 解析之后的明文
$errCode = $bizMsgCrypt->DecryptMsg($sReqMsgSig, $sReqTimeStamp, $sReqNonce, $sReqData, $sMsg);
if ($errCode == 0) {
	// 解密成功，sMsg即为xml格式的明文
	print("done DecryptMsg, sMsg : \n");
    var_dump($sMsg);
	// TODO: 对明文的处理
} else {
	print("ERR: " . $errCode . "\n\n");
	//exit(-1);
}

print("<hr>");

/*
------------使用示例三：企业回复用户消息的加密---------------
企业被动回复用户的消息也需要进行加密，并且拼接成密文格式的json串。
假设企业需要回复用户的明文如下：

{ 
	"Name": "哈哈",
	"Age":"12"

为了将此段明文回复给用户，企业应：
1.自己生成时间时间戳(timestamp),随机数字串(nonce)以便生成消息体签名
2.将明文加密得到密文。
3.用密文，步骤1生成的timestamp,nonce和企业在平台设定的token生成消息体签名。
4.将密文，消息体签名，时间戳，随机数字串拼接成json格式的字符串，发送给企业号。
以上2，3，4步可以用平台提供的库函数EncryptMsg来实现。
*/

// 需要发送的明文
$sRespData = '{"Name":"哈哈","Age":"12"}';
$EncryptMsg = ""; //json格式的密文
var_dump($EncryptMsg);
$errCode = $bizMsgCrypt->EncryptMsg($sRespData, $EncryptMsg);
var_dump( $sReqNonce, $EncryptMsg);
if ($errCode == 0) {
	print("done EncryptMsg, sEncryptMsg : \n");
    echo ($EncryptMsg);
	// TODO:
	// 加密成功，企业需要将加密之后的sEncryptMsg返回
	// HttpUtils.SetResponce($sEncryptMsg);  //回复加密之后的密文
	print("done \n");
} else {
	print("ERR: " . $errCode . "\n\n");
	// exit(-1);
}

