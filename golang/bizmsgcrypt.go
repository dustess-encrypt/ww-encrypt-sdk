package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"time"
)

const letterBytes = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

const (
	ValidateSignatureError int = -40001
	ParseXmlError          int = -40002
	ComputeSignatureError  int = -40003
	IllegalAesKey          int = -40004
	ValidateReceiveIdError int = -40005
	EncryptAESError        int = -40006
	DecryptAESError        int = -40007
	IllegalBuffer          int = -40008
	EncodeBase64Error      int = -40009
	DecodeBase64Error      int = -40010
	GenXmlError            int = -40011
	ParseJsonError         int = -40012
	GenJsonError           int = -40013
	IllegalProtocolType    int = -40014
)

type ProtocolType int

const (
	XmlType  ProtocolType = 1
	JsonType ProtocolType = 2
)

type Error struct {
	ErrCode int
	ErrMsg  string
}

// NewCryptError 错误信息结构体
func NewCryptError(errCode int, errMsg string) *Error {
	return &Error{ErrCode: errCode, ErrMsg: errMsg}
}

// BizMsg4Recv 接收消息结构体
type BizMsg4Recv struct {
	MsgType string `json:"msgType"` // add_customer|edit_customer|add_user|edit_user
	Encrypt string `json:"encrypt"`
}

// BizMsg4Send 发送消息结构体
type BizMsg4Send struct {
	Encrypt   string `json:"encrypt"`
	Signature string `json:"msgSignature"`
	Timestamp string `json:"timeStamp"`
	Nonce     string `json:"nonce"`
}

// NewBizMsg4Send 消息发送对象
func NewBizMsg4Send(encrypt, signature, timestamp, nonce string) *BizMsg4Send {
	return &BizMsg4Send{Encrypt: encrypt, Signature: signature, Timestamp: timestamp, Nonce: nonce}
}

// ProtocolProcessor 消息处理器
type ProtocolProcessor interface {
	parse(srcData []byte) (*BizMsg4Recv, *Error)
	serialize(msgSend *BizMsg4Send) ([]byte, *Error)
}

type BizMsgCrypt struct {
	token             string
	encodingAesKey    string
	receiveId         string
	protocolProcessor ProtocolProcessor
}

type Processor struct {
}

func (p *Processor) parse(srcData []byte) (*BizMsg4Recv, *Error) {
	var msg4Recv BizMsg4Recv
	err := json.Unmarshal(srcData, &msg4Recv)
	if nil != err {
		return nil, NewCryptError(ParseJsonError, "json to msg fail")
	}
	return &msg4Recv, nil
}

func (p *Processor) serialize(msg4Send *BizMsg4Send) ([]byte, *Error) {
	msg, err := json.Marshal(msg4Send)
	if nil != err {
		return nil, NewCryptError(GenJsonError, err.Error())
	}
	return msg, nil
}

// NewBizMsgCrypt 新建加解密对象
func NewBizMsgCrypt(token, encodingAesKey, receiveId string, protocolType ProtocolType) *BizMsgCrypt {
	var protocolProcessor ProtocolProcessor
	if protocolType != JsonType {
		panic("unsupport protocal")
	} else {
		protocolProcessor = new(Processor)
	}

	return &BizMsgCrypt{token: token, encodingAesKey: encodingAesKey + "=", receiveId: receiveId, protocolProcessor: protocolProcessor}
}

// randString 随机字符串
func (c *BizMsgCrypt) randString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}
	return string(b)
}

func (c *BizMsgCrypt) pKCS7Padding(plainText string, blockSize int) []byte {
	padding := blockSize - (len(plainText) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	var buffer bytes.Buffer
	buffer.WriteString(plainText)
	buffer.Write(padText)
	return buffer.Bytes()
}

func (c *BizMsgCrypt) pKCS7UnPadding(plaintext []byte, blockSize int) ([]byte, *Error) {
	plaintextLen := len(plaintext)
	if nil == plaintext || plaintextLen == 0 {
		return nil, NewCryptError(DecryptAESError, "pKCS7UnPadding error nil or zero")
	}
	if plaintextLen%blockSize != 0 {
		return nil, NewCryptError(DecryptAESError, "pKCS7UnPadding text not a multiple of the block size")
	}
	paddingLen := int(plaintext[plaintextLen-1])
	return plaintext[:plaintextLen-paddingLen], nil
}

func (c *BizMsgCrypt) cbcEncryptors(plaintext string) ([]byte, *Error) {
	aesKey, err := base64.StdEncoding.DecodeString(c.encodingAesKey)
	if nil != err {
		return nil, NewCryptError(DecodeBase64Error, err.Error())
	}
	const blockSize = 32
	padMsg := c.pKCS7Padding(plaintext, blockSize)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, NewCryptError(EncryptAESError, err.Error())
	}

	cipherText := make([]byte, len(padMsg))
	iv := aesKey[:aes.BlockSize]

	mode := cipher.NewCBCEncrypter(block, iv)

	mode.CryptBlocks(cipherText, padMsg)
	base64Msg := make([]byte, base64.StdEncoding.EncodedLen(len(cipherText)))
	base64.StdEncoding.Encode(base64Msg, cipherText)

	return base64Msg, nil
}

func (c *BizMsgCrypt) cbcDecrypter(base64EncryptMsg string) ([]byte, *Error) {
	aesKey, err := base64.StdEncoding.DecodeString(c.encodingAesKey)
	if nil != err {
		return nil, NewCryptError(DecodeBase64Error, err.Error())
	}

	encryptMsg, err := base64.StdEncoding.DecodeString(base64EncryptMsg)
	if nil != err {
		return nil, NewCryptError(DecodeBase64Error, err.Error())
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, NewCryptError(DecryptAESError, err.Error())
	}

	if len(encryptMsg) < aes.BlockSize {
		return nil, NewCryptError(DecryptAESError, "encryptMsg size is not valid")
	}

	iv := aesKey[:aes.BlockSize]

	if len(encryptMsg)%aes.BlockSize != 0 {
		return nil, NewCryptError(DecryptAESError, "encryptMsg not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(encryptMsg, encryptMsg)

	return encryptMsg, nil
}

func (c *BizMsgCrypt) calSignature(timestamp, nonce, data string) string {
	sortArr := []string{c.token, timestamp, nonce, data}
	sort.Strings(sortArr)
	var buffer bytes.Buffer
	for _, value := range sortArr {
		buffer.WriteString(value)
	}

	sha := sha1.New()
	sha.Write(buffer.Bytes())
	signature := fmt.Sprintf("%x", sha.Sum(nil))
	return signature
}

func (c *BizMsgCrypt) ParsePlainText(plainText []byte) ([]byte, uint32, []byte, []byte, *Error) {
	const blockSize = 32
	plainText, err := c.pKCS7UnPadding(plainText, blockSize)
	if nil != err {
		return nil, 0, nil, nil, err
	}

	textLen := uint32(len(plainText))
	if textLen < 20 {
		return nil, 0, nil, nil, NewCryptError(IllegalBuffer, "plain is to small 1")
	}
	random := plainText[:16]
	msgLen := binary.BigEndian.Uint32(plainText[16:20])
	if textLen < (20 + msgLen) {
		return nil, 0, nil, nil, NewCryptError(IllegalBuffer, "plain is to small 2")
	}

	msg := plainText[20 : 20+msgLen]
	receiveId := plainText[20+msgLen:]

	return random, msgLen, msg, receiveId, nil
}

// VerifyURL 验证回调URL
func (c *BizMsgCrypt) VerifyURL(msgSignature, timestamp, nonce, echoStr string) ([]byte, *Error) {
	signature := c.calSignature(timestamp, nonce, echoStr)

	if strings.Compare(signature, msgSignature) != 0 {
		return nil, NewCryptError(ValidateSignatureError, "signature not equal")
	}

	plainText, err := c.cbcDecrypter(echoStr)
	if nil != err {
		return nil, err
	}

	_, _, msg, receiveId, err := c.ParsePlainText(plainText)
	if nil != err {
		return nil, err
	}

	if len(c.receiveId) > 0 && strings.Compare(string(receiveId), c.receiveId) != 0 {
		fmt.Println(string(receiveId), c.receiveId, len(receiveId), len(c.receiveId))
		return nil, NewCryptError(ValidateReceiveIdError, "ReceiveId is not equal")
	}

	return msg, nil
}

// EncryptMsg 消息加密
func (c *BizMsgCrypt) EncryptMsg(replyMsg string) (*BizMsg4Send, *Error) {
	randStr := c.randString(16)
	timeStamp := time.Now().Unix()
	timestamp := strconv.FormatInt(timeStamp, 10)
	var buffer bytes.Buffer
	buffer.WriteString(randStr)

	msgLenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(msgLenBuf, uint32(len(replyMsg)))
	buffer.Write(msgLenBuf)
	buffer.WriteString(replyMsg)
	buffer.WriteString(c.receiveId)

	tmpCipherText, err := c.cbcEncryptors(buffer.String())
	if nil != err {
		return nil, err
	}
	cipherText := string(tmpCipherText)

	signature := c.calSignature(timestamp, randStr, cipherText)

	return NewBizMsg4Send(cipherText, signature, timestamp, randStr), nil
}

// DecryptMsg 消息解密
func (c *BizMsgCrypt) DecryptMsg(msgSignature, timestamp, nonce string, postData []byte) ([]byte, *Error) {
	msg4Recv, cryptErr := c.protocolProcessor.parse(postData)
	if nil != cryptErr {
		return nil, cryptErr
	}

	signature := c.calSignature(timestamp, nonce, msg4Recv.Encrypt)

	if strings.Compare(signature, msgSignature) != 0 {
		return nil, NewCryptError(ValidateSignatureError, "signature not equal")
	}

	plaintext, cryptErr := c.cbcDecrypter(msg4Recv.Encrypt)
	if nil != cryptErr {
		return nil, cryptErr
	}

	_, _, msg, receiveId, cryptErr := c.ParsePlainText(plaintext)
	if nil != cryptErr {
		return nil, cryptErr
	}

	if len(c.receiveId) > 0 && strings.Compare(string(receiveId), c.receiveId) != 0 {
		return nil, NewCryptError(ValidateReceiveIdError, "ReceiveId is not equal")
	}

	return msg, nil
}

// BaseContent 消息基础字段
type BaseContent struct {
	ReceiveId string `json:"receiveId"` // 公司ID
	MsgType   string `json:"msgType"`   // add_customer|edit_customer|add_user|edit_user
}

// Msg 消息字段
type Msg struct {
	BaseContent
	Content    string `json:"content"`    // 具体数据字段 (json字符串)
	CreateTime uint32 `json:"createTime"` // 消息创建时间（整型）单位为秒
}
