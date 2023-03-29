# 목차

- [Bitcoin Wallet](#bitcoin-wallet)
  - [종류](#종류)
    - [Hardware Wallet](#hardware-wallet)
    - [Cold Wallet, Hot Wallet](#cold-wallet-hot-wallet)
  - [키를 관리하는 방법](#키를-관리하는-방법)
    - [Nondeterministic(Random) Wallet](#nondeterministicrandom-wallet)
    - [Hierarchical Deterministic(Seed) Wallet](#hierarchical-deterministicseed-wallet)
  - [Mnemonic](#mnemonic)
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
- [Wallet 만들기](#wallet-만들기)
  - [서명](#서명)
    - [키 페어 생성하기](#키-페어-생성하기)
  - [서명하기](#서명하기)
  - [검증](#검증)
  - [복구하기](#복구하기)
  - [복구](#복구)
- [코드 설명](#코드-설명)
  - [변수 \& 상수](#변수--상수)
  - [함수](#함수)
    - [Wallet() : 함수 호출 시 사용자가 wallet이 없다면 키페어를 만들어 파일 형태로 저장해준다](#wallet--함수-호출-시-사용자가-wallet이-없다면-키페어를-만들어-파일-형태로-저장해준다)
    - [hasWalletFile() : 해당하는 파일의 이름을 가진 파일이 존재하는지 알려준다](#haswalletfile--해당하는-파일의-이름을-가진-파일이-존재하는지-알려준다)
    - [resotoreKey() : 키 파일을 읽어 해당 키를 반한한다](#resotorekey--키-파일을-읽어-해당-키를-반한한다)
    - [createPrivKey() : Key Pair를 생성해준다](#createprivkey--key-pair를-생성해준다)
    - [persistKey() : key를 받아 byte 타입의 파일로 저장한다](#persistkey--key를-받아-byte-타입의-파일로-저장한다)
    - [aFormK() : private key에서 public key를 가져온다](#aformk--private-key에서-public-key를-가져온다)
    - [encodeBigInts() : public key의, a,b 값을 합쳐 16진수 문자열형태로 반환한다](#encodebigints--public-key의-ab-값을-합쳐-16진수-문자열형태로-반환한다)


# Bitcoin Wallet

사용자의 개인키를 안전하게 관리하고 쉽게 거래를 생성하는 것을 지원한다.

- 실제로 네트워크에 참여하지는 않는다.
- 기능
  - 거래 조회
  - 사용자 잔액 조회
  - 신규 블록 생성 알림
  - 주소록 관리
  - 사용자 키 관

## 종류

- Web Wallet
- App Wallet
- Paper Wallet
- Hardware Wallet

### Hardware Wallet

- 개인키를 Export 할 수 있는 기존 Wallet과는 달리 Hardware Wallet은 Private Key를 Export 하거나 조회할 수 없게 생성되었다.
- 하나의 Hardware Wallet는 **다수의 Address를 생성하고 관리** 할 수 있게 관리된다.
- 지문, PIN 번호 등 **자체 보안기능**을 제공한다.
- 고장 시 복구할 수 있는 방법인 **Mnemonic 기능**을 제공한다.

### Cold Wallet, Hot Wallet

- 개인키를 관리하는 지갑이 인터넷과 연결된 환경인지 아닌지에 따라 구분된다.
- 거래소는 해킹의 위험으로 인해 Cold와 Hot으로 나눠서 관리한다.
- Hot Wallet
  - Web Wallet
  - App Wallet
  - Desktop Wallet
- Code Wallet
  - Hardware Wallet
  - Paper Wallet
  - Offline Computer Wallet

## 키를 관리하는 방법

### Nondeterministic(Random) Wallet

- 100개의 Random 개인키를 생성하고, 이를 한번씩만 사용하는 지갑
- 주소를 한번만 사용하여 Privacy 보장이 높아짐
- Private key 관리를 위해 주기적인 Backup이 필

### Hierarchical Deterministic(Seed) Wallet

- 하나의 Seed값에서 생성된 Master Key를 중심으로 계층적으로 개인키를 생성
- 개인키(Master) 하나로 여러 개의 주소를 관리 가능
- 여러 Branch 키를 생성하여, Branch 마다 용도에 맞는 주소 그룹 분류 가능

## Mnemonic

BIP-39에서 제안된 새로운 Seed 관리 방안

- 기존에는 Random Seed를 통해 개인키 생성을 하고 개인키 분실 시 복구가 불가능하였다.
  - Mnemonic을 통해 개인키를 분실해도 Mnemonic을 통해 개인키 재 생성이 가능하다.

# 니모닉 지갑이란

니모닉(Mnemonic)이란 결정적 지갑에서 난수 12개의 영단어로 인코딩한 영단어 그룹으로, BIP-39에서 제안되었습니다.

암호화폐 지갑은 `비대칭키 암호 방식`을 사용합니다. 이때 공개키와 개인키(=비밀키)가 사용이 되는데, 이 개인키를 사람이 쓰기 편하게 만들어진 것이 바로, **니모닉(mnemonic)**입니다.

# 니모닉 생성과 원리

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

## Salting

- 솔팅(Salting)은 원본 데이터에 임의의 문자열인 솔트(Salt)를 추가하여 해싱하는 방식입니다.
- 해커는 솔트 값 까지 맞춰야하므로
  - 레인보우 공격을 피할 수 있다.
  - 무차별 대입 공격을 피할 수 있다.
 <img width="623" alt="image" src="https://user-images.githubusercontent.com/20445415/219228327-e08a8cdf-e9db-49a3-a101-69124bc53335.png">
 
## 키 스트레칭(Key Stretching)

- 솔팅 방식을 여러번 반복하는 것
    - 예측을 더욱 어렵게 하는 것
<img width="342" alt="image" src="https://user-images.githubusercontent.com/20445415/219228397-c4ce2ac7-53b3-40b0-bb6d-4d5ade41a9e0.png">

# golang을 이용한 니모닉 코드 생성하기
> <https://github.com/FDongFDong/wallet/tree/main/mnemonic>

## go-ethereum-hdwallet 패키지

Go-ethereum 계정을 구현하는 패키지이다.

<https://github.com/miguelmota/go-ethereum-hdwallet>

```go
go get github.com/miguelmota/go-ethereum-hdwallet
```

## 소스 코드

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

## 함수 정리

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

# Wallet 생성하기

## 소스 코드

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

## 함수 정리

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

---

# Wallet 만들기

> <https://github.com/FDongFDong/wallet/tree/main/wallet>

서명과 검증부터 알고가자

## 서명

1. 메세지를 Hash한다.
2. 키 페어를 생성한다.
    1. 공개키(Public Key)
    2. 비공개키(Private Key)로 이루어져 있다.
3. 서명을 만들어낸다.
    1. 1번에서 만든) Hash된 메세지 + 2번에서 만든)Private key = 서명

### 키 페어 생성하기

[ecdsa](https://pkg.go.dev/crypto/ecdsa)

```go
func GenerateKey(c elliptic.Curve, rand io.Reader) (*PrivateKey, error)
```

- GenerateKey() :  개인키 & 공개키 쌍을 생성한다.
  - 첫번째 인자
    - 어떠한 알고리즘을 사용할 것인지
      - 실습에서는 표준 라이브러리에 있는 알고리즘 사용
  - 두번째 인자
    - 난수
  - 예제
  
    ```go
    privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

    utils.HandleErr(err)

    fmt.Println("Private Key", privateKey.D)
    fmt.Println("Public Key, X, Y", privateKey.X, privateKey.Y)
    ```

## 서명하기

- “Hello Golang” 문자열 서명하기

  ```go
  func Start() {

  message := "Hello Golang"

  // 메세지를 Hash 한다.
  hashedMessage := utils.Hash(message)

  // 공개키, 비밀키 키페어를 생성한다.
  privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
  utils.HandleErr(err)
  hashAsBytes, err := hex.DecodeString(hashedMessage)
  utils.HandleErr(err)

  // Hash된 메세지에 비공개 키로 서명한다.
  r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashAsBytes)
  utils.HandleErr(err)
  fmt.Printf("R:%d\nS:%d\n", r, s)
  }
  ```

  - 서명 시 R, S값으로 두개의 숫자가 나온다.

## 검증

누군가 Hash된 메세지에  있는 서명이 너의 서명인지 증명하라고 한다.

→ 공개키만 주면 된다.

- Hash된 메세지 + 서명 + (서명에서 만든)공개 키 = true/false
  - true/false값으로 해당 서명이 공개키와 같이 생성된 비공개키로 서명을 한것인지 확인할 수 있다.

- 예제
  - 앞서 만든 서명코드를 통해 검증을 진행한다.

    ```go
    message := "Hello Golang"
    // ------------------------------------
    // [서명]
    
    // 메세지를 Hash 한다.
    hashedMessage := utils.Hash(message)
    
    // 공개키, 비밀키 키페어를 생성한다.
    privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    utils.HandleErr(err)
    hashAsBytes, err := hex.DecodeString(hashedMessage)
    utils.HandleErr(err)
    
    // Hash된 메세지에 비공개 키로 서명한다.
    r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashAsBytes)
    utils.HandleErr(err)
    
    // -------------------------------------
    // [검증]
    ok := ecdsa.Verify(&privateKey.PublicKey, hashAsBytes, r, s)
    fmt.Println(ok)
    ```

## 복구하기

```go
// 공개키, 비밀키 키페어를 생성한다.
 privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
 // GenerateKey 함수는 실행할 때마다 새로운 키를 발급해준다.

 // Elliptic Curve의 비공개키를 받아서 byte로 변환해주는 함수
 keyAsBytes, err := x509.MarshalECPrivateKey(privateKey)
 // 비공개키를 16진수 형태로 출력
 fmt.Printf("%x\n", keyAsBytes)
 utils.HandleErr(err)

 hashAsBytes, err := hex.DecodeString(hashedMessage)
 utils.HandleErr(err)

 // Hash된 메세지에 비공개 키로 서명한다.
 r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashAsBytes)
 utils.HandleErr(err)

 signature := append(r.Bytes(), s.Bytes()...)
 // 16진수로 변경한 signature
 fmt.Printf("%x\n", signature)
```

- 상기 코드에서 만든 비밀키, 서명, Hash된 메시지를 따로 저장해둔다.

```go
const (
 // "Hello Golang"의 Hash된 값
 signature     string = "3e695e7fba03bf846dc9f948321133dc26ba43045070a7c63d882d2981879624e1eaaf420dd3411e92b355dc987dd027cb7a2b4b88a6279a6b4fc5f24d0f99ca"
 hashedMessage string = "8d2caf9f544c5641e94f35c7dc32ebd5d70bd4c92084c5b6644b017df45406f6"
 privateKey    string = "307702010104204f99a5d356d0721af5bd7fa303ee53bdcc7500db1d17cd1470efe385b513bdf6a00a06082a8648ce3d030107a14403420004653f89e03fdeec0300ced0c7b90c7f72f9dfdbd30c44e6adb345520bebf6cd76d179041a405c71a17fb77e3b41f0ef24c46b23bbae946a5ba6c839629388791d"
)
```

- 실제 블록체인에서는 위에서 변환한 값을 아래와 같이 사용한다.
  - Hash된 메세지
    - 트랜잭션 ID
  - Private Key
    - User가 파일로 가지고 있다.
  - 서명 후에 나온 R,S(32bytes로 된 두개의 slice)
    - 트랜잭션의 서명

## 복구

- Hash화된 비공개 키 복구하기

    ```go
    const (
     privateKey    string = "307702010104204f99a5d356d0721af5bd7fa303ee53bdcc7500db1d17cd1470efe385b513bdf6a00a06082a8648ce3d030107a14403420004653f89e03fdeec0300ced0c7b90c7f72f9dfdbd30c44e6adb345520bebf6cd76d179041a405c71a17fb77e3b41f0ef24c46b23bbae946a5ba6c839629388791d"
    )
    
    // 1. private Key 인코딩 체크
    // 해당 함수는 string을 받아 넘겨받은 문자열의 인코딩이 이상하거나 변형되어 있다면 error을 반환한다.
    // 정상적이라면 []byte 형태로 반환
    privBytes, err := hex.DecodeString(privateKey)
    utils.HandleErr(err)
    
    // 해당 함수는 private key를 []byte로 받아 private key를 가져온다.
    private, err := x509.ParseECPrivateKey(privBytes)
    utils.HandleErr(err)
    
    // 우리가 복구되길 원했던 비공개키와 같은 게 맞는지 아직 확인할 수 없다.
    // 이것으로 서명을 검증할 때 확인할 수 있다.
    fmt.Println(private)
    ```

- Hash화된 서명(Signature) 복구하기

    ```go
    const (
    signature string = "3e695e7fba03bf846dc9f948321133dc26ba43045070a7c63d882d2981879624e1eaaf420dd3411e92b355dc987dd027cb7a2b4b88a6279a6b4fc5f24d0f99ca"
    
    )
    
    // 2. []byte로 변환된 signature를 r과 s로 나눈다.
    rBytes := sigBytes[:len(sigBytes)/2]
    sBytes := sigBytes[len(sigBytes)/2:]
    // 3. big.Int형으로 변환해주기 위해 인스턴스 초기화 진행
    var bigR, bigS = big.Int{}, big.Int{}
    // 3-1.
    bigR.SetBytes(rBytes)
    bigS.SetBytes(sBytes)
    
    fmt.Println(bigR, bigS)
    ```

  - false는 big.Int의 값이 음수(true)인지 양수(false)인지 알려준다.

# 코드 설명
## 변수 & 상수

```go
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
```

## 함수

### Wallet() : 함수 호출 시 사용자가 wallet이 없다면 키페어를 만들어 파일 형태로 저장해준다

```go
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
```

### hasWalletFile() : 해당하는 파일의 이름을 가진 파일이 존재하는지 알려준다

```go
func hasWalletFile() bool {
 _, err := os.Stat(fileName)
 return !os.IsNotExist(err)
}
```

### resotoreKey() : 키 파일을 읽어 해당 키를 반한한다

```go
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
```

### createPrivKey() : Key Pair를 생성해준다

- Public Key
- Private Key

```go
func createPrivKey() *ecdsa.PrivateKey {
 // 키페어를 생성해준다.
 privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
 utils.HandleErr(err)
 return privKey
}
```

### persistKey() : key를 받아 byte 타입의 파일로 저장한다

```go
func persistKey(key *ecdsa.PrivateKey) {
 // private key를 받아서 byte slice로 만든다.
 bytes, err := x509.MarshalECPrivateKey(key)
 utils.HandleErr(err)
 // 0644 : 읽기와 쓰기 허용
 err = os.WriteFile(fileName, bytes, 0644)
 utils.HandleErr(err)
}
```

### aFormK() : private key에서 public key를 가져온다

```go
func aFromK(key *ecdsa.PrivateKey) string {
 return encodeBigInts(key.X.Bytes(), key.Y.Bytes())
}
```

### encodeBigInts() : public key의, a,b 값을 합쳐 16진수 문자열형태로 반환한다

```go
func encodeBigInts(a, b []byte) string {
 // public key의 a, b값을 합쳐서 16진수 문자열형태로 반환한다.
 z := append(a, b...)
 return fmt.Sprintf("%x", z)
}
```
