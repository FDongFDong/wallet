package controller

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"wallet/model"
	"wallet/utils"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
)

// TODO : mnemonic 패키지의 함수를 사용하여 랜덤한 니모닉 코드를 얻습니다.
func NewMnemonic(c *gin.Context) {
	// entropy 변수에는 hdwallet.NewEntropy 의 결과값을 받습니다.
	// 256 비트의 엔트로피를 생성합니다.
	entropy, err := hdwallet.NewEntropy(256)
	utils.ErrorHandler(err, c, http.StatusServiceUnavailable)

	// mnemonic 변수에는 hdwallet.NewMnemonicFromEntropy 의 결과값을 받습니다.
	// entropy를 인자값으로 줍니다.
	mnemonic, err := hdwallet.NewMnemonicFromEntropy(entropy)
	utils.ErrorHandler(err, c, http.StatusServiceUnavailable)
	// mnemonic 응답 값을 담을 model 구조체를 만듭니다.
	// (응답) model 구조체 변수에 mnemonic을 담아 응답으로 전송합니다.
	c.IndentedJSON(http.StatusOK, model.MnemonicResponse{Mnemonic: mnemonic})
}

// TODO : 니모닉 코드를 이용해 private key, address를 생성합니다.
func NewWallet(c *gin.Context) {
	// 요청에 포함되어 있는 mnemonic을 파싱합니다.
	var body model.WalletCreateRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		utils.ErrorHandler(err, c, http.StatusBadRequest)
	}
	//mnemonic 변수에는 body 값에서 파싱한 mnemonic 값을 받습니다.
	mnemonic := body.Mnemonic

	// seed 변수에는 hdwallet.NewSeedFromMnemonic 의 결과값을 받습니다.
	// mnemonic 값을 인자값으로 줍니다.
	seed, err := hdwallet.NewSeedFromMnemonic(mnemonic)
	utils.ErrorHandler(err, c, http.StatusServiceUnavailable)

	// wallet 변수에는 hdwallet.NewFromSeed 의 결과값을 받습니다.
	// seed 값을 인자값으로 줍니다.
	wallet, err := hdwallet.NewFromSeed(seed)
	utils.ErrorHandler(err, c, http.StatusServiceUnavailable)

	// path 변수에는 hdwallet.MustParseDerivationPath 의 결과값을 받습니다.
	// bip44 경로를 인자값으로 줍니다.
	path := hdwallet.MustParseDerivationPath("m/44'/60'/0'/0/0")

	// account 변수에는 *wallet.Derive 의 결과값을 받습니다.
	// path 값을 인자값으로 줍니다.
	account, err := wallet.Derive(path, false)
	utils.ErrorHandler(err, c, http.StatusServiceUnavailable)

	// privateKey 변수에는 *wallet.PrivateKeyHex 의 결과값을 받습니다.
	// account 값을 인자값으로 줍니다.
	privateKey, _ := wallet.PrivateKeyHex(account)

	// address 변수에는 account.Address 의 결과값을 받습니다.
	address := account.Address.Hex()

	// privateKey, address 응답 값을 담을 model 구조체를 만듭니다.
	var result model.WalletResponse

	// (응답) model 구조체 변수에 privateKey, address 값을 담아 응답으로 전송합니다.
	result.PrivateKey = privateKey
	result.Address = address

	c.IndentedJSON(http.StatusOK, result)

}

// TODO : 니모닉 코드와 패스워드를 이용해 keystore를 생성합
func NewWalletWithKeystore(c *gin.Context) {
	// mnemonic과 password을 body 값으로, 서버에 요청을 보냅니다.
	// 요청에 포함되어 있는 mnemonic, password를 파싱합니다.
	var body model.WalletCreateRequestWithPassword
	err := c.ShouldBindJSON(&body)
	utils.ErrorHandler(err, c, http.StatusBadRequest)

	// mnemonic, password, seed, wallet, privateKey 등 필요한 변수를 선언하고 값을 받습니다.
	mnemonic := body.Mnemonic
	password := body.Password

	seed, _ := hdwallet.NewSeedFromMnemonic(mnemonic)
	wallet, _ := hdwallet.NewFromSeed(seed)
	path := hdwallet.MustParseDerivationPath("m/44'/60'/0'/0/0")

	account, _ := wallet.Derive(path, false)
	privateKey, _ := wallet.PrivateKey(account)

	address := account.Address.Hex()

	id, err := uuid.NewRandom()
	if err != nil {
		panic(fmt.Sprintf("Could not create random uuid: %v", err))
	}

	ks := &keystore.Key{
		Id:         id,
		Address:    crypto.PubkeyToAddress(privateKey.PublicKey),
		PrivateKey: privateKey,
	}
	// EncryptKey 를 활용해 키를 암호화합니다.
	keyjson, err := keystore.EncryptKey(ks, password, keystore.StandardScryptN, keystore.StandardScryptP)
	if err != nil {
		log.Fatalf(err.Error())
	}
	// 저장할 경로를 지정하여 json 형식의 파일을 로컬에 저장합니다.
	keystoreName := strings.Join([]string{address, "json"}, ".")
	keystorefile := strings.Join([]string{"./tmp", keystoreName}, "/")
	if err := os.WriteFile(keystorefile, keyjson, 0777); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// (응답) 로컬에 파일을 저장하기 때문에, 응답으로는 성공 메세지를 전송합니다.
	c.IndentedJSON(http.StatusOK, gin.H{"result": "ok"})
}
