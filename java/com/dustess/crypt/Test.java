package com.dustess.crypt;

/**
 * @author shupeng
 * @group dustess.com
 * @date 2020/6/28 15:35.
 */
public class Test {

  public static void main(String[] args) {

    String token = "thisisatoken";
    String encodingAesKey = "jWmYm7qr5nMoAUwZRjGtBxmz3KA1tkAj3ykkR6q2B2C";
    String companyId = "P00000000023";
    BizMsgCrypt bizMsgCrypt = null;
    try {
      bizMsgCrypt = new BizMsgCrypt(token, encodingAesKey, companyId);
    } catch (BizException e) {
      e.printStackTrace();
    }

    /**
     *  数据加密
     */
//    Msg msg = new Msg();
//    msg.setName("yoyo");
//    try {
//      String encryptMsg = bizMsgCrypt.EncryptMsg(JSONObject.toJSONString(msg));
//      System.out.println(encryptMsg);
//    } catch (BizException e) {
//      e.printStackTrace();
//    }



    /**
     * 解密数据
     */
    String msgSignature = "e0a562048b70ea53fc5809aadea7aee67ebb102b";
    String timeStamp = "1593348117305";
    String nonce = "b4gfA2p4PYJZZair";
    String encrypt = "Qt1ZzseK8X8HLa+8AfBOqL3wDgrGKAEsKvQfPjJGbhfDL0R63oObDrH3yhLukrFsEhqp9CgZaLJ29jc0Ols9YQ==";
//    JSONObject object = new JSONObject();
//    object.put("encrypt", encrypt);
//    String decryptMsg = bizMsgCrypt.DecryptMsg(msgSignature, timeStamp, nonce, object.toJSONString());
//    System.out.println(decryptMsg);

    /**
     * 校验回调URL
     */
    String verifyURL = bizMsgCrypt.VerifyURL(msgSignature, timeStamp, nonce, encrypt);
    System.out.println(verifyURL);
  }



}

class Msg {
  private String Name;

  public String getName() {
    return Name;
  }

  public void setName(String name) {
    Name = name;
  }
}
