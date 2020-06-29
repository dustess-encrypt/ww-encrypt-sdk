package com.dustess.crypt;

/**
 * @author shupeng
 * @group dustess.com
 * @date 2020/6/28 20:08.
 */
public interface ErrorCode {

  /**
   * 获取错误码
   */
  int getCode();

  /**
   * 获取错误信息
   */
  String getDescription();
}