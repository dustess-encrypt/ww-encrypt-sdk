package com.dustess.crypt;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;

/**
 * 提供接收和推送消息的加解密接口(UTF8编码的字符串).
 * <ol>
 * 	<li>第三方回复加密消息给尘锋</li>
 * 	<li>第三方收到尘锋发送的消息，验证消息的安全性，并对消息进行解密。</li>
 * </ol>
 * 说明：异常java.security.InvalidKeyException:illegal Key Size的解决方案
 * <ol>
 * 	<li>在官方网站下载JCE无限制权限策略文件（JDK7的下载地址：
 *      https://www.oracle.com/java/technologies/javase-jce7-downloads.html</li>
 * 	<li>下载后解压，可以看到local_policy.jar和US_export_policy.jar以及readme.txt</li>
 * 	<li>如果安装了JRE，将两个jar文件放到%JRE_HOME%\lib\security目录下覆盖原来的文件</li>
 * 	<li>如果安装了JDK，将两个jar文件放到%JDK_HOME%\jre\lib\security目录下覆盖原来文件</li>
 * </ol>
 */
public class BizMsgCrypt {
	static Charset CHARSET = Charset.forName("utf-8");
	Base64 base64 = new Base64();
	byte[] aesKey;
	String token;
	String companyId;

	/**
	 * 构造函数
	 * @param token 服务商后台，开发者设置的token
	 * @param encodingAesKey 服务商后台，开发者设置的EncodingAESKey
	 * @param companyId, 服务商后台可见， 公司ID
	 * @throws BizException 执行失败，请查看该异常的错误码和具体的错误信息
	 */
	public BizMsgCrypt(String token, String encodingAesKey, String companyId) throws BizException {
		if (encodingAesKey.length() != 43) {
			throw new BizException(BizErrorCodeEnum.IllegalAesKey);
		}

		this.token = token;
		this.companyId = companyId;
		aesKey = Base64.decodeBase64(encodingAesKey + "=");
	}

	// 生成4个字节的网络字节序
	byte[] getNetworkBytesOrder(int sourceNumber) {
		byte[] orderBytes = new byte[4];
		orderBytes[3] = (byte) (sourceNumber & 0xFF);
		orderBytes[2] = (byte) (sourceNumber >> 8 & 0xFF);
		orderBytes[1] = (byte) (sourceNumber >> 16 & 0xFF);
		orderBytes[0] = (byte) (sourceNumber >> 24 & 0xFF);
		return orderBytes;
	}

	// 还原4个字节的网络字节序
	int recoverNetworkBytesOrder(byte[] orderBytes) {
		int sourceNumber = 0;
		for (int i = 0; i < 4; i++) {
			sourceNumber <<= 8;
			sourceNumber |= orderBytes[i] & 0xff;
		}
		return sourceNumber;
	}

	// 随机生成16位字符串
	String getRandomStr() {
		String base = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
		Random random = new Random();
		StringBuffer nonce = new StringBuffer();
		for (int i = 0; i < 16; i++) {
			int number = random.nextInt(base.length());
			nonce.append(base.charAt(number));
		}
		return nonce.toString();
	}

	/**
	 * 对明文进行加密.
	 * 
	 * @param text 需要加密的明文
	 * @return 加密后base64编码的字符串
	 * @throws BizException aes加密失败
	 */
	String encrypt(String randomStr, String text) throws BizException {
		ByteGroup byteCollector = new ByteGroup();
		byte[] randomStrBytes = randomStr.getBytes(CHARSET);
		byte[] textBytes = text.getBytes(CHARSET);
		byte[] networkBytesOrder = getNetworkBytesOrder(textBytes.length);
		byte[] companyIdBytes = companyId.getBytes(CHARSET);

		// randomStr + networkBytesOrder + text + companyId
		byteCollector.addBytes(randomStrBytes);
		byteCollector.addBytes(networkBytesOrder);
		byteCollector.addBytes(textBytes);
		byteCollector.addBytes(companyIdBytes);

		// ... + pad: 使用自定义的填充方式对明文进行补位填充
		byte[] padBytes = PKCS7Encoder.encode(byteCollector.size());
		byteCollector.addBytes(padBytes);

		// 获得最终的字节流, 未加密
		byte[] unencrypted = byteCollector.toBytes();

		try {
			// 设置加密模式为AES的CBC模式
			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
			IvParameterSpec iv = new IvParameterSpec(aesKey, 0, 16);
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);

			// 加密
			byte[] encrypted = cipher.doFinal(unencrypted);

			// 使用BASE64对加密后的字符串进行编码
			String base64Encrypted = base64.encodeToString(encrypted);

			return base64Encrypted;
		} catch (Exception e) {
			e.printStackTrace();
			throw new BizException(BizErrorCodeEnum.EncryptAESError);
		}
	}

	/**
	 * 对密文进行解密.
	 * 
	 * @param text 需要解密的密文
	 * @return 解密得到的明文
	 * @throws BizException aes解密失败
	 */
	String decrypt(String text) throws BizException {
		byte[] original;
		try {
			// 设置解密模式为AES的CBC模式
			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			SecretKeySpec key_spec = new SecretKeySpec(aesKey, "AES");
			IvParameterSpec iv = new IvParameterSpec(Arrays.copyOfRange(aesKey, 0, 16));
			cipher.init(Cipher.DECRYPT_MODE, key_spec, iv);

			// 使用BASE64对密文进行解码
			byte[] encrypted = Base64.decodeBase64(text);

			// 解密
			original = cipher.doFinal(encrypted);
		} catch (Exception e) {
			e.printStackTrace();
			throw new BizException(BizErrorCodeEnum.DecryptAESError);
		}

		String jsonContent, fromCompanyId;
		try {
			// 去除补位字符
			byte[] bytes = PKCS7Encoder.decode(original);

			// 分离16位随机字符串,网络字节序和companyId
			byte[] networkOrder = Arrays.copyOfRange(bytes, 16, 20);

			int jsonLength = recoverNetworkBytesOrder(networkOrder);

			jsonContent = new String(Arrays.copyOfRange(bytes, 20, 20 + jsonLength), CHARSET);
			fromCompanyId = new String(Arrays.copyOfRange(bytes, 20 + jsonLength, bytes.length),
					CHARSET);
		} catch (Exception e) {
			e.printStackTrace();
			throw new BizException(BizErrorCodeEnum.IllegalBuffer);
		}

		// companyId不相同的情况
		if (!fromCompanyId.equals(companyId)) {
			throw new BizException(BizErrorCodeEnum.ValidateCompanyIdError);
		}
		return jsonContent;

	}

	/**
	 * 将尘锋回复用户的消息加密打包.
	 * <ol>
	 * 	<li>对要发送的消息进行AES-CBC加密</li>
	 * 	<li>生成安全签名</li>
	 * 	<li>将消息密文和安全签名打包成xml格式</li>
	 * </ol>
	 * 
	 * @param replyMsg 待回复用户的消息，json格式的字符串
	 * @return 加密后的可以直接回复用户的密文，包括msg_signature, timestamp, nonce, encrypt的xml格式的字符串
	 * @throws BizException 执行失败，请查看该异常的错误码和具体的错误信息
	 */
	public String EncryptMsg(String replyMsg) throws BizException {
		// 加密
		String encrypt = encrypt(getRandomStr(), replyMsg);

		// 生成时间戳
		String timeStamp = Long.toString(System.currentTimeMillis());

		// 生成随机字符串
		String nonce = getRandomStr();

		// 生成安全签名
		String signature = SHA1.getSHA1(token, timeStamp, nonce, encrypt);

		// 生成发送的json
		JSONObject obj = new JSONObject();
		obj.put("encrypt", encrypt);
		obj.put("msgSignature", signature);
		obj.put("timeStamp", timeStamp);
		obj.put("nonce", nonce);
		return obj.toJSONString();
	}

	/**
	 * 检验消息的真实性，并且获取解密后的明文.
	 * <ol>
	 * 	<li>利用收到的密文生成安全签名，进行签名验证</li>
	 * 	<li>若验证通过，则提取json中的加密消息</li>
	 * 	<li>对消息进行解密</li>
	 * </ol>
	 * 
	 * @param msgSignature 签名串，对应URL参数的msg_signature
	 * @param timeStamp 时间戳，对应URL参数的timestamp
	 * @param nonce 随机串，对应URL参数的nonce
	 * @param postData 密文，对应POST请求的数据
	 * 
	 * @return 解密后的原文
	 * @throws BizException 执行失败，请查看该异常的错误码和具体的错误信息
	 */
	public String DecryptMsg(String msgSignature, String timeStamp, String nonce, String postData)
			throws BizException {

		// 密钥，公众账号的app secret
		// 提取密文
		JSONObject data = JSON.parseObject(postData);
		String encrypt = data.getString("encrypt");

		// 验证安全签名
		String signature = SHA1.getSHA1(token, timeStamp, nonce, encrypt);

		// 和URL中的签名比较是否相等
		if (!signature.equals(msgSignature)) {
			throw new BizException(BizErrorCodeEnum.ValidateSignatureError);
		}

		// 解密
		String result = decrypt(encrypt);
		return result;
	}

	/**
	 * 验证URL
	 * @param msgSignature 签名串，对应URL参数的msg_signature
	 * @param timeStamp 时间戳，对应URL参数的timestamp
	 * @param nonce 随机串，对应URL参数的nonce
	 * @param echoStr 随机串，对应URL参数的echostr
	 * 
	 * @return 解密之后的echostr
	 * @throws BizException 执行失败，请查看该异常的错误码和具体的错误信息
	 */
	public String VerifyURL(String msgSignature, String timeStamp, String nonce, String echoStr)
			throws BizException {
		String signature = SHA1.getSHA1(token, timeStamp, nonce, echoStr);

		if (!signature.equals(msgSignature)) {
			throw new BizException(BizErrorCodeEnum.ValidateSignatureError);
		}

		String result = decrypt(echoStr);
		return result;
	}

}