package pkcs12

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"github.com/dannysun85/gmsm/sm2"
	"fmt"
	"math/big"
)

type pkcs8 struct { 
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

var ( 
	oidPublicKeyRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

var ( 
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	oidNamedCurveP256SM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301} 
)

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) { 
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	case sm2.P256Sm2():
		return oidNamedCurveP256SM2, true
	}

	return nil, false
}
func namedCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(oidNamedCurveP224):
		return elliptic.P224()
	case oid.Equal(oidNamedCurveP256):
		return elliptic.P256()
	case oid.Equal(oidNamedCurveP384):
		return elliptic.P384()
	case oid.Equal(oidNamedCurveP521):
		return elliptic.P521()
	case  oid.Equal(oidNamedCurveP256SM2):
		return sm2.P256Sm2()
	}
	return nil
}
func ParsePKCS8PrivateKey(der []byte) (key interface{}, err error) {
	var privKey pkcs8
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, err
	}
	switch {
	case privKey.Algo.Algorithm.Equal(oidPublicKeyECDSA):
		bytes := privKey.Algo.Parameters.FullBytes
		namedCurveOID := new(asn1.ObjectIdentifier)
		if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
			namedCurveOID = nil
		}
		key, err = parseECPrivateKey(namedCurveOID, privKey.PrivateKey)
		if err != nil {
			return nil, errors.New("x509: failed to parse EC private key embedded in PKCS#8: " + err.Error())
		}
		return key, nil

	default:
		return nil, fmt.Errorf("x509: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
	}
}
func parseECPrivateKey(namedCurveOID *asn1.ObjectIdentifier, der []byte) (key *ecdsa.PrivateKey, err error) {
	var privKey ecPrivateKey
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, errors.New("x509: failed to parse EC private key: " + err.Error())
	}
	if privKey.Version != 1 {
		return nil, fmt.Errorf("x509: unknown EC private key version %d", privKey.Version)
	}

	var curve elliptic.Curve
	if namedCurveOID != nil {
		curve = namedCurveFromOID(*namedCurveOID)
	} else {
		curve = namedCurveFromOID(privKey.NamedCurveOID)
	}
	if curve == nil {
		return nil, errors.New("x509: unknown elliptic curve")
	}

	k := new(big.Int).SetBytes(privKey.PrivateKey)
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, errors.New("x509: invalid elliptic curve private key value")
	}
	priv := new(ecdsa.PrivateKey)
	priv.Curve = curve
	priv.D = k

	privateKey := make([]byte, (curveOrder.BitLen()+7)/8)


	for len(privKey.PrivateKey) > len(privateKey) {
		if privKey.PrivateKey[0] != 0 {
			return nil, errors.New("x509: invalid private key length")
		}
		privKey.PrivateKey = privKey.PrivateKey[1:]
	}


	copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)
	priv.X, priv.Y = curve.ScalarBaseMult(privateKey)

	return priv, nil
}
func marshalPKCS8PrivateKey(key interface{}) (der []byte, err error) {
	var privKey pkcs8
	switch key := key.(type) {
	case *rsa.PrivateKey:
		privKey.Algo.Algorithm = oidPublicKeyRSA

		privKey.Algo.Parameters = asn1.RawValue{
			Tag: 5,
		}
		privKey.PrivateKey = x509.MarshalPKCS1PrivateKey(key)
	case *ecdsa.PrivateKey:
		privKey.Algo.Algorithm = oidPublicKeyECDSA
		namedCurveOID, ok := oidFromNamedCurve(key.Curve)
		if !ok {
			return nil, errors.New("go-pkcs12: unknown elliptic curve")
		}
		if privKey.Algo.Parameters.FullBytes, err = asn1.Marshal(namedCurveOID); err != nil {
			return nil, errors.New("go-pkcs12: failed to embed OID of named curve in PKCS#8: " + err.Error())
		}
		if privKey.PrivateKey, err =x509.MarshalECPrivateKey(key); err != nil {
			return nil, errors.New("go-pkcs12: failed to embed EC private key in PKCS#8: " + err.Error())
		}
	case *sm2.PrivateKey:
		privKey.Algo.Algorithm = oidPublicKeyECDSA
		namedCurveOID, ok := oidFromNamedCurve(key.Curve)
		if !ok {
			return nil, errors.New("go-pkcs12: unknown elliptic curve")
		}
		if privKey.Algo.Parameters.FullBytes, err = asn1.Marshal(namedCurveOID); err != nil {
			return nil, errors.New("go-pkcs12: failed to embed OID of named curve in PKCS#8: " + err.Error())
		}
		if privKey.PrivateKey, err = MarshalECPrivateKey(key); err != nil {
			return nil, errors.New("go-pkcs12: failed to embed EC private key in PKCS#8: " + err.Error())
		}
	default:
		return nil, errors.New("go-pkcs12: only RSA and ECDSA private keys supported")
	}
	return asn1.Marshal(privKey)
}
func MarshalECPrivateKey(key *sm2.PrivateKey) ([]byte, error) {
	oid, ok := oidFromNamedCurve(key.Curve)
	if !ok {
		return nil, errors.New("x509: unknown elliptic curve")
	}

	return MarshalPrivateKey(key, oid)
}
func MarshalPrivateKey(key *sm2.PrivateKey, oid asn1.ObjectIdentifier)([]byte,error){
	privateKeyBytes := key.D.Bytes()
	paddedPrivateKey := make([]byte, (key.Curve.Params().N.BitLen()+7)/8)
	copy(paddedPrivateKey[len(paddedPrivateKey)-len(privateKeyBytes):], privateKeyBytes)
	return asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    paddedPrivateKey,
		NamedCurveOID: oid,
		PublicKey:     asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)},
	})
}
type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}