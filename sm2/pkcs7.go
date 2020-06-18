package sm2

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1" 
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"
)

type PKCS7 struct {
	Content      []byte
	Certificates []*Certificate
	CRLs         []pkix.CertificateList
	Signers      []signerInfo
	raw          interface{}
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

var ErrUnsupportedContentType = errors.New("pkcs7: cannot parse data: unimplemented content type")

type unsignedData []byte

var (
	oidData                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidSMSignedData           = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 2}
	oidEnvelopedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidSignedAndEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 4}
	oidDigestedData           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 5}
	oidEncryptedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidAttributeContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttributeSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
    oidSM3withSM2=asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}
	oidDSASM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301, 1}
)

type signedData struct {
	Version                    int                        `asn1:"default:1"`
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo                contentInfo
	Certificates               rawCertificates        `asn1:"optional,tag:0"`
	CRLs                       []pkix.CertificateList `asn1:"optional,tag:1"`
	SignerInfos                []signerInfo           `asn1:"set"`
}

type rawCertificates struct {
	Raw asn1.RawContent
}

type envelopedData struct {
	Version              int
	RecipientInfos       []recipientInfo `asn1:"set"`
	EncryptedContentInfo encryptedContentInfo
}

type recipientInfo struct {
	Version                int
	IssuerAndSerialNumber  issuerAndSerial
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional"`
}

type attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type issuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

type MessageDigestMismatchError struct {
	ExpectedDigest []byte
	ActualDigest   []byte
}

func (err *MessageDigestMismatchError) Error() string {
	return fmt.Sprintf("pkcs7: Message digest mismatch\n\tExpected: %X\n\tActual  : %X", err.ExpectedDigest, err.ActualDigest)
}

type signerInfo struct {
	Version                   int `asn1:"default:1"`
	IssuerAndSerialNumber     issuerAndSerial
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   []attribute `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []attribute `asn1:"optional,tag:1"`
}

func ParsePKCS7(data []byte) (p7 *PKCS7, err error) {
	if len(data) == 0 {
		return nil, errors.New("pkcs7: input data is empty")
	}
	var info contentInfo
	der, err := ber2der(data)
	if err != nil {
		return nil, err
	}
	rest, err := asn1.Unmarshal(der, &info)
	if len(rest) > 0 {
		err = asn1.SyntaxError{Msg: "trailing data"}
		return
	}

	if err != nil {
		return
	}

	switch {
	case info.ContentType.Equal(oidSignedData):
		return parseSignedData(info.Content.Bytes)
	case info.ContentType.Equal(oidSMSignedData):
		return parseSignedData(info.Content.Bytes)
	case info.ContentType.Equal(oidEnvelopedData):
		return parseEnvelopedData(info.Content.Bytes)
	}
	return nil, ErrUnsupportedContentType
}

func parseSignedData(data []byte) (*PKCS7, error) {
	var sd signedData
	asn1.Unmarshal(data, &sd)
	certs, err := sd.Certificates.Parse()
	if err != nil {
		return nil, err
	}

	var compound asn1.RawValue
	var content unsignedData

	if len(sd.ContentInfo.Content.Bytes) > 0 {
		if _, err := asn1.Unmarshal(sd.ContentInfo.Content.Bytes, &compound); err != nil {
			return nil, err
		}
	}
	if compound.IsCompound {
		if _, err = asn1.Unmarshal(compound.Bytes, &content); err != nil {
			return nil, err
		}
	} else {
		content = compound.Bytes
	}
	return &PKCS7{
		Content:      content,
		Certificates: certs,
		CRLs:         sd.CRLs,
		Signers:      sd.SignerInfos,
		raw:          sd}, nil
}

func (raw rawCertificates) Parse() ([]*Certificate, error) {
	if len(raw.Raw) == 0 {
		return nil, nil
	}

	var val asn1.RawValue
	if _, err := asn1.Unmarshal(raw.Raw, &val); err != nil {
		return nil, err
	}

	return ParseCertificates(val.Bytes)
}

func parseEnvelopedData(data []byte) (*PKCS7, error) {
	var ed envelopedData
	if _, err := asn1.Unmarshal(data, &ed); err != nil {
		return nil, err
	}
	return &PKCS7{
		raw: ed,
	}, nil
}


func (p7 *PKCS7) Verify() (err error) {
	if len(p7.Signers) == 0 {
		return errors.New("pkcs7: Message has no signers")
	}
	for _, signer := range p7.Signers {
		if err := verifySignature(p7, signer); err != nil {
			return err
		}
	}
	return nil
}

func verifySignature(p7 *PKCS7, signer signerInfo) error {
	signedData := p7.Content
	hash, err := getHashForOID(signer.DigestAlgorithm.Algorithm)
	if err != nil {
		return err
	}
	if len(signer.AuthenticatedAttributes) > 0 {
		var digest []byte
		err := unmarshalAttribute(signer.AuthenticatedAttributes, oidAttributeMessageDigest, &digest)
		if err != nil {
			return err
		}
		h := hash.New()
		h.Write(p7.Content)
		computed := h.Sum(nil)
		if !hmac.Equal(digest, computed) {
			return &MessageDigestMismatchError{
				ExpectedDigest: digest,
				ActualDigest:   computed,
			}
		}
		signedData, err = marshalAttributes(signer.AuthenticatedAttributes)
		if err != nil {
			return err
		}
	}
	cert := getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
	if cert == nil {
		return errors.New("pkcs7: No certificate for signer")
	}

	algo := getSignatureAlgorithmByHash(hash, signer.DigestEncryptionAlgorithm.Algorithm)
	if algo == UnknownSignatureAlgorithm {
		return ErrPKCS7UnsupportedAlgorithm
	}
	return cert.CheckSignature(algo, signedData, signer.EncryptedDigest)
}

func getSignatureAlgorithmByHash(hash Hash, oid asn1.ObjectIdentifier) SignatureAlgorithm {
	switch hash {
	case SM3:
		switch {
		case oid.Equal(oidSM3withSM2):
			return SM2WithSM3
		}
	case SHA256:
		switch {
		case oid.Equal(oidDSASM2):
			return SM2WithSHA256
		}
	}
	return UnknownSignatureAlgorithm
}

func marshalAttributes(attrs []attribute) ([]byte, error) {
	encodedAttributes, err := asn1.Marshal(struct {
		A []attribute `asn1:"set"`
	}{A: attrs})
	if err != nil {
		return nil, err
	}

	var raw asn1.RawValue
	asn1.Unmarshal(encodedAttributes, &raw)
	return raw.Bytes, nil
}

var (
	oidDigestAlgorithmSHA1    = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidEncryptionAlgorithmRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

func getCertFromCertsByIssuerAndSerial(certs []*Certificate, ias issuerAndSerial) *Certificate {
	for _, cert := range certs {
		if isCertMatchForIssuerAndSerial(cert, ias) {
			return cert
		}
	}
	return nil
}

func getHashForOID(oid asn1.ObjectIdentifier) (Hash, error) {
	switch {
	case oid.Equal(oidDigestAlgorithmSHA1):
		return SHA1, nil
	case oid.Equal(oidSHA256):
		return SHA256, nil
	case oid.Equal(oidSM3):
	case oid.Equal(oidHashSM3):
		return SM3, nil
	}
	return Hash(0), ErrPKCS7UnsupportedAlgorithm
}

func (p7 *PKCS7) GetOnlySigner() *Certificate {
	if len(p7.Signers) != 1 {
		return nil
	}
	signer := p7.Signers[0]
	return getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
}

var ErrPKCS7UnsupportedAlgorithm = errors.New("pkcs7: cannot decrypt data: only RSA, DES, DES-EDE3, AES-256-CBC and AES-128-GCM supported")

var ErrNotEncryptedContent = errors.New("pkcs7: content data is a decryptable data type")

func (p7 *PKCS7) Decrypt(cert *Certificate, pk crypto.PrivateKey) ([]byte, error) {
	data, ok := p7.raw.(envelopedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	recipient := selectRecipientForCertificate(data.RecipientInfos, cert)
	if recipient.EncryptedKey == nil {
		return nil, errors.New("pkcs7: no enveloped recipient for provided certificate")
	}
	if priv := pk.(*rsa.PrivateKey); priv != nil {
		var contentKey []byte
		contentKey, err := rsa.DecryptPKCS1v15(rand.Reader, priv, recipient.EncryptedKey)
		if err != nil {
			return nil, err
		}
		return data.EncryptedContentInfo.decrypt(contentKey)
	}
	fmt.Printf("Unsupported Private Key: %v\n", pk)
	return nil, ErrPKCS7UnsupportedAlgorithm
}

var oidEncryptionAlgorithmDESCBC = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
var oidEncryptionAlgorithmDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
var oidEncryptionAlgorithmAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
var oidEncryptionAlgorithmAES128GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 6}
var oidEncryptionAlgorithmAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}

func (eci encryptedContentInfo) decrypt(key []byte) ([]byte, error) {
	alg := eci.ContentEncryptionAlgorithm.Algorithm
	if !alg.Equal(oidEncryptionAlgorithmDESCBC) &&
		!alg.Equal(oidEncryptionAlgorithmDESEDE3CBC) &&
		!alg.Equal(oidEncryptionAlgorithmAES256CBC) &&
		!alg.Equal(oidEncryptionAlgorithmAES128CBC) &&
		!alg.Equal(oidEncryptionAlgorithmAES128GCM) {
		fmt.Printf("Unsupported Content Encryption Algorithm: %s\n", alg)
		return nil, ErrPKCS7UnsupportedAlgorithm
	}

	var cyphertext []byte
	if eci.EncryptedContent.IsCompound {
		var buf bytes.Buffer
		cypherbytes := eci.EncryptedContent.Bytes
		for {
			var part []byte
			cypherbytes, _ = asn1.Unmarshal(cypherbytes, &part)
			buf.Write(part)
			if cypherbytes == nil {
				break
			}
		}
		cyphertext = buf.Bytes()
	} else {
		cyphertext = eci.EncryptedContent.Bytes
	}

	var block cipher.Block
	var err error

	switch {
	case alg.Equal(oidEncryptionAlgorithmDESCBC):
		block, err = des.NewCipher(key)
	case alg.Equal(oidEncryptionAlgorithmDESEDE3CBC):
		block, err = des.NewTripleDESCipher(key)
	case alg.Equal(oidEncryptionAlgorithmAES256CBC):
		fallthrough
	case alg.Equal(oidEncryptionAlgorithmAES128GCM), alg.Equal(oidEncryptionAlgorithmAES128CBC):
		block, err = aes.NewCipher(key)
	}

	if err != nil {
		return nil, err
	}

	if alg.Equal(oidEncryptionAlgorithmAES128GCM) {
		params := aesGCMParameters{}
		paramBytes := eci.ContentEncryptionAlgorithm.Parameters.Bytes

		_, err := asn1.Unmarshal(paramBytes, &params)
		if err != nil {
			return nil, err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		if len(params.Nonce) != gcm.NonceSize() {
			return nil, errors.New("pkcs7: encryption algorithm parameters are incorrect")
		}
		if params.ICVLen != gcm.Overhead() {
			return nil, errors.New("pkcs7: encryption algorithm parameters are incorrect")
		}

		plaintext, err := gcm.Open(nil, params.Nonce, cyphertext, nil)
		if err != nil {
			return nil, err
		}

		return plaintext, nil
	}

	iv := eci.ContentEncryptionAlgorithm.Parameters.Bytes
	if len(iv) != block.BlockSize() {
		return nil, errors.New("pkcs7: encryption algorithm parameters are malformed")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(cyphertext))
	mode.CryptBlocks(plaintext, cyphertext)
	if plaintext, err = unpad(plaintext, mode.BlockSize()); err != nil {
		return nil, err
	}
	return plaintext, nil
}

func selectRecipientForCertificate(recipients []recipientInfo, cert *Certificate) recipientInfo {
	for _, recp := range recipients {
		if isCertMatchForIssuerAndSerial(cert, recp.IssuerAndSerialNumber) {
			return recp
		}
	}
	return recipientInfo{}
}

func isCertMatchForIssuerAndSerial(cert *Certificate, ias issuerAndSerial) bool {
	return cert.SerialNumber.Cmp(ias.SerialNumber) == 0 && bytes.Compare(cert.RawIssuer, ias.IssuerName.FullBytes) == 0
}

func pad(data []byte, blocklen int) ([]byte, error) {
	if blocklen < 1 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	padlen := blocklen - (len(data) % blocklen)
	if padlen == 0 {
		padlen = blocklen
	}
	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(data, pad...), nil
}

func unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen < 1 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}

	padlen := int(data[len(data)-1])

	pad := data[len(data)-padlen:]
	for _, padbyte := range pad {
		if padbyte != byte(padlen) {
			return nil, errors.New("invalid padding")
		}
	}

	return data[:len(data)-padlen], nil
}

func unmarshalAttribute(attrs []attribute, attributeType asn1.ObjectIdentifier, out interface{}) error {
	for _, attr := range attrs {
		if attr.Type.Equal(attributeType) {
			_, err := asn1.Unmarshal(attr.Value.Bytes, out)
			return err
		}
	}
	return errors.New("pkcs7: attribute type not in attributes")
}

func (p7 *PKCS7) UnmarshalSignedAttribute(attributeType asn1.ObjectIdentifier, out interface{}) error {
	sd, ok := p7.raw.(signedData)
	if !ok {
		return errors.New("pkcs7: payload is not signedData content")
	}
	if len(sd.SignerInfos) < 1 {
		return errors.New("pkcs7: payload has no signers")
	}
	attributes := sd.SignerInfos[0].AuthenticatedAttributes
	return unmarshalAttribute(attributes, attributeType, out)
}

type SignedData struct {
	sd            signedData
	certs         []*Certificate
	messageDigest []byte
}

type Attribute struct {
	Type  asn1.ObjectIdentifier
	Value interface{}
}

type SignerInfoConfig struct {
	ExtraSignedAttributes []Attribute
}

func NewSignedData(data []byte) (*SignedData, error) {
	content, err := asn1.Marshal(data)
	if err != nil {
		return nil, err
	}
	ci := contentInfo{
		ContentType: oidData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: content, IsCompound: true},
	}
	digAlg := pkix.AlgorithmIdentifier{
		Algorithm: oidDigestAlgorithmSHA1,
	}
	h := crypto.SHA1.New()
	h.Write(data)
	md := h.Sum(nil)
	sd := signedData{
		ContentInfo:                ci,
		Version:                    1,
		DigestAlgorithmIdentifiers: []pkix.AlgorithmIdentifier{digAlg},
	}
	return &SignedData{sd: sd, messageDigest: md}, nil
}

type attributes struct {
	types  []asn1.ObjectIdentifier
	values []interface{}
}

func (attrs *attributes) Add(attrType asn1.ObjectIdentifier, value interface{}) {
	attrs.types = append(attrs.types, attrType)
	attrs.values = append(attrs.values, value)
}

type sortableAttribute struct {
	SortKey   []byte
	Attribute attribute
}

type attributeSet []sortableAttribute

func (sa attributeSet) Len() int {
	return len(sa)
}

func (sa attributeSet) Less(i, j int) bool {
	return bytes.Compare(sa[i].SortKey, sa[j].SortKey) < 0
}

func (sa attributeSet) Swap(i, j int) {
	sa[i], sa[j] = sa[j], sa[i]
}

func (sa attributeSet) Attributes() []attribute {
	attrs := make([]attribute, len(sa))
	for i, attr := range sa {
		attrs[i] = attr.Attribute
	}
	return attrs
}

func (attrs *attributes) ForMarshaling() ([]attribute, error) {
	sortables := make(attributeSet, len(attrs.types))
	for i := range sortables {
		attrType := attrs.types[i]
		attrValue := attrs.values[i]
		asn1Value, err := asn1.Marshal(attrValue)
		if err != nil {
			return nil, err
		}
		attr := attribute{
			Type:  attrType,
			Value: asn1.RawValue{Tag: 17, IsCompound: true, Bytes: asn1Value}, 
		}
		encoded, err := asn1.Marshal(attr)
		if err != nil {
			return nil, err
		}
		sortables[i] = sortableAttribute{
			SortKey:   encoded,
			Attribute: attr,
		}
	}
	sort.Sort(sortables)
	return sortables.Attributes(), nil
}

func (sd *SignedData) AddSigner(cert *Certificate, pkey crypto.PrivateKey, config SignerInfoConfig) error {
	attrs := &attributes{}
	attrs.Add(oidAttributeContentType, sd.sd.ContentInfo.ContentType)
	attrs.Add(oidAttributeMessageDigest, sd.messageDigest)
	attrs.Add(oidAttributeSigningTime, time.Now())
	for _, attr := range config.ExtraSignedAttributes {
		attrs.Add(attr.Type, attr.Value)
	}
	finalAttrs, err := attrs.ForMarshaling()
	if err != nil {
		return err
	}
	signature, err := signAttributes(finalAttrs, pkey, crypto.SHA1)
	if err != nil {
		return err
	}

	ias, err := cert2issuerAndSerial(cert)
	if err != nil {
		return err
	}

	signer := signerInfo{
		AuthenticatedAttributes:   finalAttrs,
		DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: oidDigestAlgorithmSHA1},
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSignatureSHA1WithRSA},
		IssuerAndSerialNumber:     ias,
		EncryptedDigest:           signature,
		Version:                   1,
	}
	sd.certs = append(sd.certs, cert)
	sd.sd.SignerInfos = append(sd.sd.SignerInfos, signer)
	return nil
}

func (sd *SignedData) AddCertificate(cert *Certificate) {
	sd.certs = append(sd.certs, cert)
}

func (sd *SignedData) Detach() {
	sd.sd.ContentInfo = contentInfo{ContentType: oidData}
}

func (sd *SignedData) Finish() ([]byte, error) {
	sd.sd.Certificates = marshalCertificates(sd.certs)
	inner, err := asn1.Marshal(sd.sd)
	if err != nil {
		return nil, err
	}
	outer := contentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: inner, IsCompound: true},
	}
	return asn1.Marshal(outer)
}

func cert2issuerAndSerial(cert *Certificate) (issuerAndSerial, error) {
	var ias issuerAndSerial
	ias.IssuerName = asn1.RawValue{FullBytes: cert.RawIssuer}
	ias.SerialNumber = cert.SerialNumber

	return ias, nil
}

func signAttributes(attrs []attribute, pkey crypto.PrivateKey, hash crypto.Hash) ([]byte, error) {
	attrBytes, err := marshalAttributes(attrs)
	if err != nil {
		return nil, err
	}
	h := hash.New()
	h.Write(attrBytes)
	hashed := h.Sum(nil)
	switch priv := pkey.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA1, hashed)
	}
	return nil, ErrPKCS7UnsupportedAlgorithm
}

func marshalCertificates(certs []*Certificate) rawCertificates {
	var buf bytes.Buffer
	for _, cert := range certs {
		buf.Write(cert.Raw)
	}
	rawCerts, _ := marshalCertificateBytes(buf.Bytes())
	return rawCerts
}

func marshalCertificateBytes(certs []byte) (rawCertificates, error) {
	var val = asn1.RawValue{Bytes: certs, Class: 2, Tag: 0, IsCompound: true}
	b, err := asn1.Marshal(val)
	if err != nil {
		return rawCertificates{}, err
	}
	return rawCertificates{Raw: b}, nil
}

func DegenerateCertificate(cert []byte) ([]byte, error) {
	rawCert, err := marshalCertificateBytes(cert)
	if err != nil {
		return nil, err
	}
	emptyContent := contentInfo{ContentType: oidData}
	sd := signedData{
		Version:      1,
		ContentInfo:  emptyContent,
		Certificates: rawCert,
		CRLs:         []pkix.CertificateList{},
	}
	content, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}
	signedContent := contentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: content, IsCompound: true},
	}
	return asn1.Marshal(signedContent)
}

const (
	EncryptionAlgorithmDESCBC = iota
	EncryptionAlgorithmAES128GCM
)

var ContentEncryptionAlgorithm = EncryptionAlgorithmDESCBC

var ErrUnsupportedEncryptionAlgorithm = errors.New("pkcs7: cannot encrypt content: only DES-CBC and AES-128-GCM supported")

const nonceSize = 12

type aesGCMParameters struct {
	Nonce  []byte `asn1:"tag:4"`
	ICVLen int
}

func encryptAES128GCM(content []byte) ([]byte, *encryptedContentInfo, error) {
	key := make([]byte, 16)
	nonce := make([]byte, nonceSize)

	_, err := rand.Read(key)
	if err != nil {
		return nil, nil, err
	}

	_, err = rand.Read(nonce)
	if err != nil {
		return nil, nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, content, nil)

	paramSeq := aesGCMParameters{
		Nonce:  nonce,
		ICVLen: gcm.Overhead(),
	}

	paramBytes, err := asn1.Marshal(paramSeq)
	if err != nil {
		return nil, nil, err
	}

	eci := encryptedContentInfo{
		ContentType: oidData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidEncryptionAlgorithmAES128GCM,
			Parameters: asn1.RawValue{
				Tag:   asn1.TagSequence,
				Bytes: paramBytes,
			},
		},
		EncryptedContent: marshalEncryptedContent(ciphertext),
	}

	return key, &eci, nil
}

func encryptDESCBC(content []byte) ([]byte, *encryptedContentInfo, error) {
	key := make([]byte, 8)
	iv := make([]byte, des.BlockSize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, nil, err
	}
	_, err = rand.Read(iv)
	if err != nil {
		return nil, nil, err
	}

	block, err := des.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	plaintext, err := pad(content, mode.BlockSize())
	cyphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(cyphertext, plaintext)

	eci := encryptedContentInfo{
		ContentType: oidData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidEncryptionAlgorithmDESCBC,
			Parameters: asn1.RawValue{Tag: 4, Bytes: iv},
		},
		EncryptedContent: marshalEncryptedContent(cyphertext),
	}

	return key, &eci, nil
}


func PKCS7Encrypt(content []byte, recipients []*Certificate) ([]byte, error) {
	var eci *encryptedContentInfo
	var key []byte
	var err error

	switch ContentEncryptionAlgorithm {
	case EncryptionAlgorithmDESCBC:
		key, eci, err = encryptDESCBC(content)

	case EncryptionAlgorithmAES128GCM:
		key, eci, err = encryptAES128GCM(content)

	default:
		return nil, ErrUnsupportedEncryptionAlgorithm
	}

	if err != nil {
		return nil, err
	}

	recipientInfos := make([]recipientInfo, len(recipients))
	for i, recipient := range recipients {
		encrypted, err := encryptKey(key, recipient)
		if err != nil {
			return nil, err
		}
		ias, err := cert2issuerAndSerial(recipient)
		if err != nil {
			return nil, err
		}
		info := recipientInfo{
			Version:               0,
			IssuerAndSerialNumber: ias,
			KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: oidEncryptionAlgorithmRSA,
			},
			EncryptedKey: encrypted,
		}
		recipientInfos[i] = info
	}

	envelope := envelopedData{
		EncryptedContentInfo: *eci,
		Version:              0,
		RecipientInfos:       recipientInfos,
	}
	innerContent, err := asn1.Marshal(envelope)
	if err != nil {
		return nil, err
	}

	wrapper := contentInfo{
		ContentType: oidEnvelopedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: innerContent},
	}

	return asn1.Marshal(wrapper)
}

func marshalEncryptedContent(content []byte) asn1.RawValue {
	asn1Content, _ := asn1.Marshal(content)
	return asn1.RawValue{Tag: 0, Class: 2, Bytes: asn1Content, IsCompound: true}
}

func encryptKey(key []byte, recipient *Certificate) ([]byte, error) {
	if pub := recipient.PublicKey.(*rsa.PublicKey); pub != nil {
		return rsa.EncryptPKCS1v15(rand.Reader, pub, key)
	}
	return nil, ErrPKCS7UnsupportedAlgorithm
}
