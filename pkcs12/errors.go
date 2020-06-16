package pkcs12

import "errors"

var (
	ErrDecryption = errors.New("go-pkcs12: decryption error, incorrect padding")

	ErrIncorrectPassword = errors.New("go-pkcs12: decryption password incorrect")
)

type NotImplementedError string

func (e NotImplementedError) Error() string {
	return "go-pkcs12: " + string(e)
}
