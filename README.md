# wallet

# 목차

- [wallet](#wallet)
- [목차](#목차)
  - [니모닉 지갑이란](#니모닉-지갑이란)
  - [니모닉 생성과 원리](#니모닉-생성과-원리)
    - [Salting](#salting)
    - [키 스트레칭(Key Stretching)](#키-스트레칭key-stretching)
  - [golang을 이용한 니모닉 코드 생성하기](#golang을-이용한-니모닉-코드-생성하기)
    - [go-ethereum-hdwallet 패키지](#go-ethereum-hdwallet-패키지)
    - [소스 코드](#소스-코드)
    - [함수 정리](#함수-정리)
  - [Wallet 생성하기](#wallet-생성하기)
    - [소스 코드](#소스-코드-1)
    - [함수 정리](#함수-정리-1)

## 니모닉 지갑이란

니모닉(Mnemonic)이란 결정적 지갑에서 난수 12개의 영단어로 인코딩한 영단어 그룹으로, BIP-39에서 제안되었습니다.

암호화폐 지갑은 `비대칭키 암호 방식`을 사용합니다. 이때 공개키와 개인키(=비밀키)가 사용이 되는데, 이 개인키를 사람이 쓰기 편하게 만들어진 것이 바로, **니모닉(mnemonic)**입니다.

## 니모닉 생성과 원리

1. 128bit or 256bit 길이의 난수를 생성
2. 난수를 SHA-256알고리즘으로 해싱
    1. 해시 값에서 (시드 키의 길이) / 32 만큼을 떼어낸다.
3. 체크섬을 난수의 뒤에 붙인다
4. 체크섬을 붙인 난수를 11bit 단위로 잘라낸다.
5. 각 11bit의 단어를 사전에 정의된 단어로 치환한다.
6. 각 11bit의 순서를 유지하여 일련의 니모닉 코드를 만든다.

키 스트레칭 함수 PBKDF2() 함수에 니모닉 코드 단어 + Salt를 넣는다.

1. 함수의 첫번째 인자는 6단계에서 생성된 니모닉 코드
2. 두번째 인자는 솔트
    - 솔트는 문자열 상수 “mnemonic”과 선택적으로 사용자가 지정한 암호문을 연결하여 구성한다.
3. PBKDF2는 출력으로 512비트 값의 seed이다
    - 512비트 값을 만드는 HMAC-SHA512 알고리즘으로

### Salting

- 솔팅(Salting)은 원본 데이터에 임의의 문자열인 솔트(Salt)를 추가하여 해싱하는 방식입니다.
- 해커는 솔트 값 까지 맞춰야하므로
  - 레인보우 공격을 피할 수 있다.
  - 무차별 대입 공격을 피할 수 있다.
 <img width="623" alt="image" src="https://user-images.githubusercontent.com/20445415/219228327-e08a8cdf-e9db-49a3-a101-69124bc53335.png">
 
### 키 스트레칭(Key Stretching)

- 솔팅 방식을 여러번 반복하는 것
    - 예측을 더욱 어렵게 하는 것
<img width="342" alt="image" src="https://user-images.githubusercontent.com/20445415/219228397-c4ce2ac7-53b3-40b0-bb6d-4d5ade41a9e0.png">

## golang을 이용한 니모닉 코드 생성하기

### go-ethereum-hdwallet 패키지

Go-ethereum 계정을 구현하는 패키지이다.

<https://github.com/miguelmota/go-ethereum-hdwallet>

```go
go get github.com/miguelmota/go-ethereum-hdwallet
```

### 소스 코드

```go
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
```

### 함수 정리

- **NewEntropy()** : **임의로 생성된 엔트로피를 반환합니다.**

    ```go
    func NewEntropy(bits int) ([]byte, error) {
     return bip39.NewEntropy(bits)
    }
    ```

- **NewMnemonicFromEntropy() :** **엔트로피에서 BIP-39 니모닉을 반환합니다.**

    ```go
    func NewMnemonicFromEntropy(entropy []byte) (string, error) {
     return bip39.NewMnemonic(entropy)
    }
    ```

## Wallet 생성하기

### 소스 코드

```go
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
```

### 함수 정리

- **NewSeedFromMnemonic() :** **BIP-39 니모닉을 기반으로 BIP-39 시드를 반환합니다.**

    ```go
    func NewSeedFromMnemonic(mnemonic string) ([]byte, error) {
     if mnemonic == "" {
      return nil, errors.New("mnemonic is required")
     }
    
     return bip39.NewSeedWithErrorChecking(mnemonic, "")
    }
    ```

- NewFromSeed() : **BIP-39 시드에서 새 지갑을 반환합니다.**

    ```go
    func NewFromSeed(seed []byte) (*Wallet, error) {
     if len(seed) == 0 {
      return nil, errors.New("seed is required")
     }
    
     return newWallet(seed)
    }
    ```

- **MustParseDerivationPath() :** **BIP44는 미리 정의된 다섯 가지 트리 레벨로 구성된 구조를 지정해주면 해당 path를 반환합니다.**
  - ex
    - m/44'/60'/0'/0/0

        ```go
        m / purpose' / coin_type' / account' / change / address_index
        ```

    - purpose : 항상 44
    - coin_type : 코인 종류(암호화폐의 유형)
      - 이더리움은 m/44'/60'
    - account : 계정
    - change : 잔돈 계정 여부
    - address_index : 사용 가능한 주소 인덱스

            ```go
            func MustParseDerivationPath(path string) accounts.DerivationPath {
             parsed, err := accounts.ParseDerivationPath(path)
             if err != nil {
              panic(err)
             }
            
             return parsed
            }
            ```

- **Derive() : accounts.Wallet을 구현하여 특정 위치에서 새 계정을 생성합니다.**
  - **pin을 true로 설정하면 계정이 목록에 추가됩니다.**

    ```go
    func (w *Wallet) Derive(path accounts.DerivationPath, pin bool) (accounts.Account, error) {
     // Try to derive the actual account and update its URL if successful
     w.stateLock.RLock() // Avoid device disappearing during derivation
    
     address, err := w.deriveAddress(path)
    
     w.stateLock.RUnlock()
    
     // If an error occurred or no pinning was requested, return
     if err != nil {
      return accounts.Account{}, err
     }
    ```

- **PrivateKeyHex() : 계정의 16진수 문자열 형식으로 ECDSA 개인 키를 반환합니다.**

    ```go
    func (w *Wallet) PrivateKeyHex(account accounts.Account) (string, error) {
     privateKeyBytes, err := w.PrivateKeyBytes(account)
     if err != nil {
      return "", err
     }
    
     return hexutil.Encode(privateKeyBytes)[2:], nil
    }
    ```

- **Hex() :** **주소의 EIP55 호환 16진수 문자열 표현을 반환합니다.**

    ```go
    func (a Address) Hex() string {
     return string(a.checksumHex())
    }
    ```

