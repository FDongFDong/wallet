package model

type MnemonicResponse struct {
	Mnemonic string `json:"mnemonic"`
}

type WalletCreateRequest struct {
	Mnemonic string `json:"mnemonic" binding:"required"`
}

type WalletResponse struct {
	PrivateKey string `json:"privateKey"`
	Address    string `json:"address"`
}

type WalletCreateRequestWithPassword struct {
	Mnemonic string `json:"mnemonic" binding:"required"`
	Password string `json:"password" binding:"required"`
}
