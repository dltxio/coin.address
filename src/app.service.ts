import { Injectable } from "@nestjs/common";
import { Wallet } from "xrpl";
import * as bip39 from "bip39";
import { AltcoinsResponse, Erc20Response, XrpResponse } from "./interfaces";
import { ethers } from "ethers";
import BIP32Factory from "bip32";
import * as ecc from "tiny-secp256k1";
import * as bitcoin from "bitcoinjs-lib";
import * as thetajs from "@thetalabs/theta-js";
import StellarSdk from "stellar-sdk";
import * as crypto from "crypto";
import * as TronWeb from "tronweb";
import { Seed } from "cardano-wallet-js";
import * as CardanoWasm from "@emurgo/cardano-serialization-lib-nodejs";
import { mnemonicToEntropy } from "bip39";
import * as solanaWeb3 from "@solana/web3.js";
import { Keyring } from "@polkadot/keyring";
import { mnemonicGenerate } from "@polkadot/util-crypto";
import * as croSdk from "@crypto-com/chain-jslib";
import * as Algo from "algosdk";
import { Mnemonic } from "@hashgraph/sdk";
import { CosmosBufferToAddress, CosmosBufferToPublic } from "./utils";
import { Bip32Path, Bip39 } from "@iota/crypto.js";
import {
    Bech32Helper,
    Ed25519Address,
    Ed25519Seed,
    ED25519_ADDRESS_TYPE,
    generateBip44Address,
    SingleNodeClient
} from "@iota/iota.js";
import { Converter } from "@iota/util.js";

@Injectable()
export class AppService {
    public async getIotaAddress() {
        const API_ENDPOINT = "https://chrysalis-nodes.iota.org/";
        const client = new SingleNodeClient(API_ENDPOINT);

        const info = await client.info();
        const randomMnemonic = Bip39.randomMnemonic();
        const baseSeed = Ed25519Seed.fromMnemonic(randomMnemonic);

        const addressGeneratorAccountState = {
            accountIndex: 0,
            addressIndex: 0,
            isInternal: false
        };
        const path = generateBip44Address(addressGeneratorAccountState);

        const addressSeed = baseSeed.generateSeedFromPath(new Bip32Path(path));
        const addressKeyPair = addressSeed.keyPair();
        const indexEd25519Address = new Ed25519Address(
            addressKeyPair.publicKey
        );
        const indexPublicKeyAddress = indexEd25519Address.toAddress();
        return {
            address: Bech32Helper.toBech32(
                ED25519_ADDRESS_TYPE,
                indexPublicKeyAddress,
                info.bech32HRP
            ),
            path: path,
            mnemonic: randomMnemonic,
            seed: Converter.bytesToHex(baseSeed.toBytes()),
            privateKey: Converter.bytesToHex(addressKeyPair.privateKey),
            publicKey: Converter.bytesToHex(addressKeyPair.publicKey)
        };
    }
    public async getXrpAddress(): Promise<XrpResponse> {
        const mnemonic = bip39.generateMnemonic();
        const seed = bip39.mnemonicToSeedSync(mnemonic);
        const wallet = Wallet.fromMnemonic(mnemonic);
        const address = wallet.address;

        return {
            address: address,
            mnemonic: mnemonic,
            seed: seed.toString("hex"),
            privateKey: wallet.privateKey,
            publicKey: wallet.publicKey
        };
    }

    public async getErc20Address(): Promise<Erc20Response> {
        const wallet = ethers.Wallet.createRandom();

        return {
            address: wallet.address,
            mnemonic: wallet.mnemonic.phrase,
            privateKey: wallet.privateKey,
            publicKey: wallet.publicKey
        };
    }

    public async getAtomAddress(): Promise<AltcoinsResponse> {
        const bip32 = BIP32Factory(ecc);
        const mnemonic = bip39.generateMnemonic();
        const seed = bip39.mnemonicToSeedSync(mnemonic);
        const root = bip32.fromSeed(seed);
        const path = "m/44'/118'/0'/0/0";
        const child = root.derivePath(path);

        const hrp = "cosmos";
        return {
            address: CosmosBufferToAddress(child.publicKey, hrp),
            path: path,
            privateKey: child.privateKey.toString("base64"),
            publicKey: CosmosBufferToPublic(child.publicKey, hrp),
            seed: seed.toString("hex"),
            mnemonic: mnemonic
        };
    }

    public async getBchAddress(): Promise<AltcoinsResponse> {
        const bip32 = BIP32Factory(ecc);
        const mnemonic = bip39.generateMnemonic();
        const seed = bip39.mnemonicToSeedSync(mnemonic);
        const root = bip32.fromSeed(seed);

        const path = "m/44'/145'/0'/0";
        const child = root.derivePath(path);

        const { address } = bitcoin.payments.p2sh({
            redeem: bitcoin.payments.p2wpkh({
                pubkey: child.publicKey,
                network: bitcoin.networks.bitcoin
            }),
            network: bitcoin.networks.bitcoin
        });

        return {
            address: address,
            path: path,
            privateKey: child.privateKey.toString("hex"),
            publicKey: child.publicKey.toString("hex"),
            seed: seed.toString("hex"),
            mnemonic: mnemonic
        };
    }

    public async getDogeAddress(): Promise<AltcoinsResponse> {
        const bip32 = BIP32Factory(ecc);
        const mnemonic = bip39.generateMnemonic();
        const seed = bip39.mnemonicToSeedSync(mnemonic);
        const root = bip32.fromSeed(seed);
        const path = "m/44'/3'/0'/0/0";
        const child = root.derivePath(path);

        const { address } = bitcoin.payments.p2pkh({
            pubkey: child.publicKey,
            network: {
                messagePrefix: "\x19Dogecoin Signed Message:\n",
                bech32: "doge",
                bip32: {
                    public: 0x02facafd,
                    private: 0x02fac398
                },
                pubKeyHash: 0x1e,
                scriptHash: 0x16,
                wif: 0x9e
            }
        });

        return {
            address: address,
            path: path,
            privateKey: child.privateKey.toString("hex"),
            publicKey: child.publicKey.toString("hex"),
            seed: seed.toString("hex"),
            mnemonic: mnemonic
        };
    }

    public async getBtcAddress(): Promise<AltcoinsResponse> {
        const bip32 = BIP32Factory(ecc);
        const mnemonic = bip39.generateMnemonic();
        const seed = bip39.mnemonicToSeedSync(mnemonic);
        const root = bip32.fromSeed(seed);
        const path = "m/44'/0'/0'/0";
        const child = root.derivePath(path);

        const { address } = bitcoin.payments.p2pkh({
            pubkey: child.publicKey,
            network: bitcoin.networks.bitcoin
        });

        return {
            address: address,
            path: path,
            publicKey: child.publicKey.toString("hex"),
            privateKey: child.privateKey.toString("hex"),
            seed: seed.toString("hex"),
            mnemonic: mnemonic
        };
    }

    public async getThetaAddress(): Promise<Erc20Response> {
        const wallet = thetajs.Wallet.createRandom();
        const mnemonic = wallet.mnemonic;

        return {
            address: wallet.address,
            mnemonic: mnemonic,
            privateKey: wallet.privateKey,
            publicKey: wallet.publicKey
        };
    }

    public async getStellarAddress() {
        const randomBytes = crypto.randomBytes(32);
        const keyPair = StellarSdk.Keypair.fromRawEd25519Seed(
            Buffer.from(randomBytes)
        );
        return {
            publicKey: keyPair.publicKey(),
            secret: keyPair.secret()
        };
    }

    public async getLitecoinAddress(): Promise<AltcoinsResponse> {
        const LITECOIN = {
            messagePrefix: "\x19Litecoin Signed Message:\n",
            bech32: "ltc",
            bip32: {
                public: 0x019da462,
                private: 0x019d9cfe
            },
            pubKeyHash: 0x30,
            scriptHash: 0x32,
            wif: 0xb0
        };
        const bip32 = BIP32Factory(ecc);
        const mnemonic = bip39.generateMnemonic();
        const seed = bip39.mnemonicToSeedSync(mnemonic);
        const root = bip32.fromSeed(seed);
        const path = "m/49'/1'/0'/0/0";
        const child = root.derivePath(path);

        const { address } = bitcoin.payments.p2sh({
            redeem: bitcoin.payments.p2wpkh({
                pubkey: child.publicKey,
                network: LITECOIN
            })
        });

        return {
            address: address,
            path: path,
            privateKey: child.privateKey.toString("hex"),
            seed: seed.toString("hex"),
            mnemonic: mnemonic
        };
    }

    public async getTronAddress() {
        return TronWeb.utils.accounts.generateAccount();
    }

    public async getCardanoAddress() {
        const mnemonic = Seed.generateRecoveryPhrase();
        const words = Seed.toMnemonicList(mnemonic);
        const entropy = mnemonicToEntropy(words.join(" "));
        const rootKey = CardanoWasm.Bip32PrivateKey.from_bip39_entropy(
            Buffer.from(entropy, "hex"),
            Buffer.from("password")
        );

        const accountKey = rootKey
            .derive(this.harden(1852)) // purpose
            .derive(this.harden(1815)) // coin type
            .derive(this.harden(0)); // account #0

        const utxoPubKey = accountKey
            .derive(0) // external
            .derive(0)
            .to_public();

        const stakeKey = accountKey
            .derive(2) // chimeric
            .derive(0)
            .to_public();

        const baseAddr = CardanoWasm.BaseAddress.new(
            CardanoWasm.NetworkInfo.mainnet().network_id(),
            CardanoWasm.StakeCredential.from_keyhash(
                utxoPubKey.to_raw_key().hash()
            ),
            CardanoWasm.StakeCredential.from_keyhash(
                stakeKey.to_raw_key().hash()
            )
        );
        return {
            mnemonic: mnemonic,
            privateKey: accountKey.to_bech32(),
            utxoPubKey: utxoPubKey.to_bech32(),
            stakeKey: stakeKey.to_bech32(),
            baseAddress: baseAddr.to_address().to_bech32()
        };
    }

    public async getSolanaAddress() {
        const keyPair = solanaWeb3.Keypair.generate();

        return {
            publicKey: keyPair.publicKey.toBase58(),
            secretKey: keyPair.secretKey.toString()
        };
    }

    public async getPolkadotAddress() {
        const keyring = new Keyring();
        const mnemonic = mnemonicGenerate();

        const pair = keyring.createFromUri(mnemonic);
        return {
            mnemonic: mnemonic,
            address: pair.address,
            publicKey: Buffer.from(pair.publicKey).toString("hex"),
            type: pair.type
        };
    }

    public async getCryptoComAddress() {
        const HDkey = croSdk.HDKey;
        const Secp256k1KeyPair = croSdk.Secp256k1KeyPair;

        const cro = croSdk.CroSDK({ network: croSdk.CroNetwork.Mainnet });
        const randomPhrase = HDkey.generateMnemonic(24);

        // Derive a private key from an HDKey at the specified path
        const importedHDKey = HDkey.fromMnemonic(randomPhrase);

        const privateKey = importedHDKey.derivePrivKey("m/44'/60'/0'/0/0");

        // Getting a keyPair from a private key
        const keyPair = Secp256k1KeyPair.fromPrivKey(privateKey);
        const address = new cro.Address(keyPair).account();

        return {
            address: address,
            mnemonic: randomPhrase,
            publicKey: keyPair.getPubKey().toHexString(),
            privateKey: privateKey.toHexString()
        };
    }

    public async getAlgoAddress() {
        const account = Algo.generateAccount();
        const sk = account.sk;
        return {
            address: account.addr,
            mnemonic: Algo.secretKeyToMnemonic(sk),
            publicKey: Buffer.from(
                Algo.decodeAddress(account.addr).publicKey
            ).toString("hex")
        };
    }

    public async getHbarAddress() {
        const mnemonic = await Mnemonic.generate();
        const rootKey = await mnemonic.toPrivateKey();

        const key = await rootKey.derive(0);
        return {
            mnemonic: mnemonic.toString(),
            privateKey: key.toString(),
            publicKey: key.publicKey.toString()
        };
    }

    private harden(num: number): number {
        return 0x80000000 + num;
    }
}
