package com.dustess.crypt;


/**
 * @author shupeng
 * @group dustess.com
 * @date 2020/6/28 20:10.
 */
public enum BizErrorCodeEnum implements ErrorCode {


  OK(0, "success"),
  ValidateSignatureError(-40001, "签名验证错误"),
  ParseXmlError(-40002, "XML解析失败"),
  ParseJsonError(-40003, "JSON解析失败"),
  ComputeSignatureError(-40004, "sha加密生成签名失败"),
  IllegalAesKey(-40005, "SymmetricKey非法"),
  ValidateReceiveIdError(-40006, "receiveId校验失败"),
  EncryptAESError(-40007, "aes加密失败"),
  DecryptAESError(-40008, "aes解密失败"),
  IllegalBuffer(-40009, "解密后得到的buffer非法"),
  EncodeBase64Error(-40010, "base64加密错误"),
  DecodeBase64Error(-40011, "base64解密错误"),
  GenReturnXmlError(-40012, "xml生成失败"),
  GenReturnJsonError(-40013, "json生成失败"),
  UNSPECIFIED(-50000, "网络异常，请稍后再试"),
  ;

  /**
   * 错误码
   */
  private final int code;

  /**
   * 描述
   */
  private final String description;

  /**
   * @param code 错误码
   * @param description 描述
   */
  private BizErrorCodeEnum(final int code, final String description) {
    this.code = code;
    this.description = description;
  }

  /**
   * 根据编码查询枚举。
   *
   * @param code 编码。
   * @return 枚举。
   */
  public static BizErrorCodeEnum getByCode(int code) {
    for (BizErrorCodeEnum value : BizErrorCodeEnum.values()) {
      if (code == value.getCode()) {
        return value;
      }
    }
    return UNSPECIFIED;
  }

  /**
   * 枚举是否包含此code
   *
   * @param code 枚举code
   * @return 结果
   */
  public static Boolean contains(int code) {
    for (BizErrorCodeEnum value : BizErrorCodeEnum.values()) {
      if (code == value.getCode()) {
        return true;
      }
    }
    return false;
  }

  @Override
  public int getCode() {
    return code;
  }

  @Override
  public String getDescription() {
    return description;
  }
}
