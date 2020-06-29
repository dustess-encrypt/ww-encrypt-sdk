<?php

class BizMsgCrypt{
    private $m_sToken;
	private $m_sEncodingAesKey;
    private $m_sReceiveId;
    
	/**
	 * 构造函数
	 * @param $token string 开发者设置的token
	 * @param $encodingAesKey string 开发者设置的EncodingAESKey
	 * @param $receiveId string  公司id
	 */
	public function __construct($token, $encodingAesKey, $receiveId)
	{
		$this->m_sToken = $token;
		$this->m_sEncodingAesKey = $encodingAesKey;
		$this->m_sReceiveId = $receiveId;
	}
		
    /*
	*验证URL
    *@param sMsgSignature: 签名串，对应URL参数的msg_signature
    *@param sTimeStamp: 时间戳，对应URL参数的timestamp
    *@param sNonce: 随机串，对应URL参数的nonce
    *@param sEchoStr: 随机串，对应URL参数的echostr
    *@param sReplyEchoStr: 解密之后的echostr，当return返回0时有效
    *@return：成功0，失败返回对应的错误码
	*/
	public function VerifyURL($sMsgSignature, $sTimeStamp, $sNonce, $sEchoStr, &$sReplyEchoStr)
	{
		if (strlen($this->m_sEncodingAesKey) != 43) {
			return ErrorCode::$IllegalAesKey;
		}

		$pc = new Prpcrypt($this->m_sEncodingAesKey);
		//verify msg_signature
		$sha1 = new SHA1;
		$array = $sha1->getSHA1($this->m_sToken, $sTimeStamp, $sNonce, $sEchoStr);
		$ret = $array[0];

		if ($ret != 0) {
			return $ret;
		}

		$signature = $array[1];
		if ($signature != $sMsgSignature) {
			return ErrorCode::$ValidateSignatureError;
		}

		$result = $pc->decrypt($sEchoStr, $this->m_sReceiveId);
		if ($result[0] != 0) {
			return $result[0];
		}
		$sReplyEchoStr = $result[1];

		return ErrorCode::$OK;
	}
	/**
	 * 将用户的消息加密打包.
	 * <ol>
	 *    <li>对要发送的消息进行AES-CBC加密</li>
	 *    <li>生成安全签名</li>
	 *    <li>将消息密文和安全签名打包成json格式</li>
	 * </ol>
	 *
	 * @param $replyMsg string 待回复用户的消息，json格式的字符串
	 * @param &$encryptMsg string 加密后的可以直接回复用户的密文，包括msg_signature, timestamp, nonce, encrypt的json格式的字符串,
	 *                      当return返回0时有效
	 *
	 * @return int 成功0，失败返回对应的错误码
	 */
	public function EncryptMsg($sReplyMsg, &$sEncryptMsg)
	{
		$pc = new Prpcrypt($this->m_sEncodingAesKey);
        $sNonce =   $pc->getRandomStr();
        $sTimeStamp = time();
		//加密
		$array = $pc->encrypt($sReplyMsg, $this->m_sReceiveId);
		$ret = $array[0];
		if ($ret != 0) {
			return $ret;
		}

		if ($sTimeStamp == null) {
			$sTimeStamp = time();
		}
		$encrypt = $array[1];

		//生成安全签名
		$sha1 = new SHA1;
		$array = $sha1->getSHA1($this->m_sToken, $sTimeStamp, $sNonce, $encrypt);
		$ret = $array[0];
		if ($ret != 0) {
			return $ret;
		}
		$signature = $array[1];

		//生成发送的json
		$jsonParse = new JsonParse;
		$sEncryptMsg = $jsonParse->generate($encrypt, $signature, $sTimeStamp, $sNonce);
		return ErrorCode::$OK;
	}


	/**
	 * 检验消息的真实性，并且获取解密后的明文.
	 * <ol>
	 *    <li>利用收到的密文生成安全签名，进行签名验证</li>
	 *    <li>若验证通过，则提取json中的加密消息</li>
	 *    <li>对消息进行解密</li>
	 * </ol>
	 *
	 * @param $msgSignature string 签名串，对应URL参数的msg_signature
	 * @param $timestamp string 时间戳 对应URL参数的timestamp
	 * @param $nonce string 随机串，对应URL参数的nonce
	 * @param $postData string 密文，对应POST请求的数据
	 * @param &$msg string 解密后的原文，当return返回0时有效
	 *
	 * @return int 成功0，失败返回对应的错误码
	 */
	public function DecryptMsg($sMsgSignature, $sTimeStamp = null, $sNonce, $sPostData, &$sMsg)
	{
		if (strlen($this->m_sEncodingAesKey) != 43) {
			return ErrorCode::$IllegalAesKey;
		}

		$pc = new Prpcrypt($this->m_sEncodingAesKey);

		//提取密文
		$jsonParse = new JsonParse;
		$array = $jsonParse->extract($sPostData);
		$ret = $array[0];

		if ($ret != 0) {
			return $ret;
		}
		if ($sTimeStamp == null) {
			$sTimeStamp = time();
		}

		$encrypt = $array[1];

		//验证安全签名
		$sha1 = new SHA1;
		$array = $sha1->getSHA1($this->m_sToken, $sTimeStamp, $sNonce, $encrypt);
		$ret = $array[0];

		if ($ret != 0) {
			return $ret;
		}

		$signature = $array[1];
		if ($signature != $sMsgSignature) {
			print("signature not match, signature ".$signature.", sSignature ".$sMsgSignature."\n");
			return ErrorCode::$ValidateSignatureError;
		}

		$result = $pc->decrypt($encrypt, $this->m_sReceiveId);
		if ($result[0] != 0) {
			return $result[0];
		}
		$sMsg = $result[1];

		return ErrorCode::$OK;
	}
}

/**
 * error code 说明.
 * <ul>
 *    <li>-40001: 签名验证错误</li>
 *    <li>-40002: xml解析失败</li>
 *    <li>-40003: sha加密生成签名失败</li>
 *    <li>-40004: encodingAesKey 非法</li>
 *    <li>-40005: corpid 校验错误</li>
 *    <li>-40006: aes 加密失败</li>
 *    <li>-40007: aes 解密失败</li>
 *    <li>-40008: 解密后得到的buffer非法</li>
 *    <li>-40009: base64加密失败</li>
 *    <li>-40010: base64解密失败</li>
 *    <li>-40011: 生成xml失败</li>
 * </ul>
 */
class ErrorCode
{
	public static $OK = 0;
	public static $ValidateSignatureError = -40001;
	public static $ParseXmlError = -40002;
	public static $ComputeSignatureError = -40003;
	public static $IllegalAesKey = -40004;
	public static $ValidateCorpidError = -40005;
	public static $EncryptAESError = -40006;
	public static $DecryptAESError = -40007;
	public static $IllegalBuffer = -40008;
	public static $EncodeBase64Error = -40009;
	public static $DecodeBase64Error = -40010;
	public static $GenReturnXmlError = -40011;
}


/**
 * Prpcrypt class
 *
 * 提供接收和推送给公众平台消息的加解密接口.
 */
class Prpcrypt
{
    public $key = null;
    public $iv = null;

    /**
     * Prpcrypt constructor.
     * @param $k
     */
    public function __construct($k)
    {
        $this->key = base64_decode($k . '=');
        $this->iv  = substr($this->key, 0, 16);

    }

    /**
     * 加密
     *
     * @param $text
     * @param $receiveId
     * @return array
     */
    public function encrypt($text, $receiveId)
    {
        try {
            //拼接
            $text = $this->getRandomStr() . pack('N', strlen($text)) . $text . $receiveId;
            //添加PKCS#7填充
            $pkc_encoder = new PKCS7Encoder;
            $text        = $pkc_encoder->encode($text);
            //加密
            $encrypted = openssl_encrypt($text, 'AES-256-CBC', $this->key, OPENSSL_ZERO_PADDING, $this->iv);
            return [ErrorCode::$OK, $encrypted];
        } catch (Exception $e) {
            print $e;
            return [MyErrorCode::$EncryptAESError, null];
        }
    }

    /**
     * 解密
     *
     * @param $encrypted
     * @param $receiveId
     * @return array
     */
    public function decrypt($encrypted, $receiveId)
    {
        try {
            //解密
            $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $this->key, OPENSSL_ZERO_PADDING, $this->iv);
        } catch (Exception $e) {
            return [ErrorCode::$DecryptAESError, null];
        }
        try {
            //删除PKCS#7填充
            $pkc_encoder = new PKCS7Encoder;
            $result      = $pkc_encoder->decode($decrypted);
            if (strlen($result) < 16) {
                return [];
            }
            //拆分
            $content     = substr($result, 16, strlen($result));
            $len_list    = unpack('N', substr($content, 0, 4));
            $json_len     = $len_list[1];
            $json_content = substr($content, 4, $json_len);
            $from_receiveId = substr($content, $json_len + 4);
        } catch (Exception $e) {
            print $e;
            return [ErrorCode::$IllegalBuffer, null];
        }
        if ($from_receiveId != $receiveId) {
            return [ErrorCode::$ValidateCorpidError, null];
        }
        return [0, $json_content];
    }

    /**
     * 生成随机字符串
     *
     * @return string
     */
    public function getRandomStr()
    {
        $str     = '';
        $str_pol = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyl';
        $max     = strlen($str_pol) - 1;
        for ($i = 0; $i < 16; $i++) {
            $str .= $str_pol[mt_rand(0, $max)];
        }
        return $str;
    }
}

/**
 * PKCS7Encoder class
 *
 * 提供基于PKCS7算法的加解密接口.
 */
class PKCS7Encoder
{
	public static $block_size = 32;

	/**
	 * 对需要加密的明文进行填充补位
	 * @param $text 需要进行填充补位操作的明文
	 * @return 补齐明文字符串
	 */
	function encode($text)
	{
		$block_size = PKCS7Encoder::$block_size;
		$text_length = strlen($text);
		//计算需要填充的位数
		$amount_to_pad = PKCS7Encoder::$block_size - ($text_length % PKCS7Encoder::$block_size);
		if ($amount_to_pad == 0) {
			$amount_to_pad = PKCS7Encoder::block_size;
		}
		//获得补位所用的字符
		$pad_chr = chr($amount_to_pad);
		$tmp = "";
		for ($index = 0; $index < $amount_to_pad; $index++) {
			$tmp .= $pad_chr;
		}
		return $text . $tmp;
	}

	/**
	 * 对解密后的明文进行补位删除
	 * @param decrypted 解密后的明文
	 * @return 删除填充补位后的明文
	 */
	function decode($text)
	{

		$pad = ord(substr($text, -1));
		if ($pad < 1 || $pad > PKCS7Encoder::$block_size) {
			$pad = 0;
		}
		return substr($text, 0, (strlen($text) - $pad));
	}

}



/**
 * SHA1 class
 *
 * 计算公众平台的消息签名接口.
 */
class SHA1
{
	/**
	 * 用SHA1算法生成安全签名
	 * @param string $token 票据
	 * @param string $timestamp 时间戳
	 * @param string $nonce 随机字符串
	 * @param string $encrypt 密文消息
	 */
	public function getSHA1($token, $timestamp, $nonce, $encrypt_msg)
	{
		//排序
		try {
			$array = array($encrypt_msg, $token, $timestamp, $nonce);
			sort($array, SORT_STRING);
			$str = implode($array);
			return array(ErrorCode::$OK, sha1($str));
		} catch (Exception $e) {
			print $e . "\n";
			return array(ErrorCode::$ComputeSignatureError, null);
		}
	}

}


/**
 * JsonParse class
 *
 * 提供提取消息格式中的密文及生成回复消息格式的接口.
 */
class JsonParse
{

	/**
	 * 提取出json数据包中的加密消息
	 * @param string $jsontext 待提取的json字符串
	 * @return string 提取出的加密消息字符串
	 */
	public function extract($jsontext)
	{
		try {
			$encrypt = json_decode($jsontext, true)['Encrypt'];
			return array(0, $encrypt);
		} catch (Exception $e) {
			print $e . "\n";
			return array(ErrorCode::$ParseXmlError, null);
		}
	}

	/**
	 * 生成json消息
	 * @param string $encrypt 加密后的消息密文
	 * @param string $signature 安全签名
	 * @param string $timestamp 时间戳
	 * @param string $nonce 随机字符串
	 */
	public function generate($encrypt, $signature, $timestamp, $nonce)
	{
		$format = '{"Encrypt": "%s", "Signature": "%s", "TimeStamp": "%s", "Nonce": "%s"}';
		return sprintf($format, $encrypt, $signature, $timestamp, $nonce);
	}

}
