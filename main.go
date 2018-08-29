package main

import (
	"context"
	"encoding/hex"
	"math/big"
	"math/rand"
	"strconv"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/caarlos0/env"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type config struct {
	PrivateKey string `env:"E_PRIVATE_KEY,required"`
	ToAddress  string `env:"E_TO_ADDRESS" envDefault:"0x1"`
	RPCPath    string `env:"E_RPC_PATH" envDefault:"http://127.0.0.1:8545"`
	Rate       int    `env:"E_RATE" envDefault:"50"`
}

func main() {
	cfg := config{}
	err := env.Parse(&cfg)
	check(err)

	logrus.Infof("Rate: %dtx per second", cfg.Rate)

	privateKey, err := hex.DecodeString(cfg.PrivateKey)
	if err != nil {
		logrus.Panic("private key decode fail")
	}

	privateKeyECDSA := crypto.ToECDSAUnsafe(privateKey)
	publicKey := crypto.PubkeyToAddress(privateKeyECDSA.PublicKey)
	logrus.Infof("publicKey: %s", publicKey.String())

	addr := cfg.RPCPath
	client, err := ethclient.Dial(addr)
	check(err)

	ctx := context.Background()
	networkID, err := client.NetworkID(ctx)
	check(err)

	nonce, _ := client.NonceAt(ctx, publicKey, nil)
	logrus.Infof("rpcAddress: %s networkID: %d currentNonce: %d", addr, networkID, nonce)

	throttle := time.Tick(time.Second / time.Duration(cfg.Rate))
	for {
		<-throttle // rate limit
		d := rand.Intn(int(time.Second) / cfg.Rate)
		time.Sleep(time.Duration(d))

		data := rand.Int()
		tx := types.NewTransaction(uint64(nonce), // nonce
			common.HexToAddress(cfg.ToAddress), // to address
			big.NewInt(1000),                   // amount
			1000000000,                         // gas limit
			big.NewInt(1),                      // gas price
			[]byte(strconv.Itoa(data)),         // data
		)
		signedTx, _ := types.SignTx(tx, types.NewEIP155Signer(networkID), privateKeyECDSA)
		err := client.SendTransaction(ctx, signedTx)
		if err != nil {
			logrus.Errorf("error: %s nonce: %d", err.Error(), nonce)
		} else {
			nonce++
		}
	}
}

func check(err error) bool {
	if err != nil {
		logrus.Panic(err)
	}
	return false
}
