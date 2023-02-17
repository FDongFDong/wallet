package wallet

import (
	"coin/exam46/utils"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
)

type wallet struct {
	// 아무와도 공유되지 않는다.
	privateKey *ecdsa.PrivateKey
	// 16진수 문자열의 public key가 된다.
	Address string
}

// Singleton을 위해 초기화되지 않은 wallet 선언
var w *wallet

const (
	fileName string = "fdongfdong.wallet"
)

func hasWalletFile() bool {
	_, err := os.Stat(fileName)
	return !os.IsNotExist(err)
}

// named return을 사용하면 variable을 미리 초기화시켜준다.
// return 시 알아서 리턴시켜준다.
// 매우 짧은 function에서 사용해야한다.
func restoreKey() (key *ecdsa.PrivateKey) {
	keyAsByte, err := os.ReadFile(fileName)
	utils.HandleErr(err)
	// x509 : private key를 parse, mershall 할 수 있다.
	key, err = x509.ParseECPrivateKey(keyAsByte)
	utils.HandleErr(err)
	return
}

func createPrivKey() *ecdsa.PrivateKey {
	// 키페어를 생성해준다.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	utils.HandleErr(err)
	return privKey
}

// key를 받아서 byte형태로 파일로 저장한다.
func persistKey(key *ecdsa.PrivateKey) {
	// private key를 받아서 byte slice로 만든다.
	bytes, err := x509.MarshalECPrivateKey(key)
	utils.HandleErr(err)
	// 0644 : 읽기와 쓰기 허용
	err = os.WriteFile(fileName, bytes, 0644)
	utils.HandleErr(err)
}

func encodeBigInts(a, b []byte) string {
	// public key의 a, b값을 합쳐서 16진수 문자열형태로 반환한다.
	z := append(a, b...)
	return fmt.Sprintf("%x", z)
}

func aFromK(key *ecdsa.PrivateKey) string {
	return encodeBigInts(key.X.Bytes(), key.Y.Bytes())
}

// wallet를 변환시키지 않기 위해 receive function으로 사용하지 않았다.
func Sign(payload string, w *wallet) string {
	// payload에 문제가 없는지 확인한다.
	payloadAsB, err := hex.DecodeString(payload)
	utils.HandleErr(err)
	r, s, err := ecdsa.Sign(rand.Reader, w.privateKey, payloadAsB)
	utils.HandleErr(err)
	return encodeBigInts(r.Bytes(), s.Bytes())
}
func restoreBigInt(payload string) (*big.Int, *big.Int, error) {
	bytes, err := hex.DecodeString(payload)
	if err != nil {
		return nil, nil, err
	}
	firstHalfBytes := bytes[:len(bytes)/2]
	secondHalfBytes := bytes[len(bytes)/2:]
	bigA, bigB := big.Int{}, big.Int{}
	bigA.SetBytes(firstHalfBytes)
	bigB.SetBytes(secondHalfBytes)
	return &bigA, &bigB, nil
}

// private키로 서명된 것을 public key로 검증한다.
func Verify(signature, payload, address string) bool {
	r, s, err := restoreBigInt(signature)
	utils.HandleErr(err)
	x, y, err := restoreBigInt(address)
	utils.HandleErr(err)
	publicKey := ecdsa.PublicKey{
		// Curve는 key를 만들었을때와 동일한 curve 값을 사용해야한다.
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
	payloadBytes, err := hex.DecodeString(payload)
	utils.HandleErr(err)
	ok := ecdsa.Verify(&publicKey, payloadBytes, r, s)

	return ok
}

// Singleton 패턴 사용
func Wallet() *wallet {
	if w == nil {
		w = &wallet{}
		// 사용자가 이미 지갑을 가지고 있는지 확인한다.
		if hasWalletFile() {
			w.privateKey = restoreKey()
			// 만약 있다면 그 키를 파일로부터 복구한다.
		} else {
			// 만약 없다면..
			// 키페어를 만들어서
			key := createPrivKey()
			// 파일에 저장해둔다.
			persistKey(key)
			// 생성한 키페어를 등록한다.
			w.privateKey = key
		}
		w.Address = aFromK(w.privateKey)
	}
	return w
}
