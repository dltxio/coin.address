export type XrpResponse = {
    address: string;
    mnemonic: string;
    seed: string;
    privateKey: string;
    publicKey: string;
};

export type Erc20Response = {
    address: string;
    mnemonic: string;
    privateKey: string;
    publicKey: string;
};

export type AltcoinsResponse = {
    address: string;
    path?: string;
    passphrase?: string;
    privateKey: string;
    publicKey?: string;
    seed: string;
    mnemonic: string;
};
