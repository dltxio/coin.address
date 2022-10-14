import { bech32 } from "bech32";
import { Buffer } from "node:buffer";
import { createHash } from "crypto";

export const CosmosBufferToPublic = (pubBuf, hrp = "cosmos") => {
    const AminoSecp256k1PubkeyPrefix = Buffer.from("EB5AE987", "hex");
    const AminoSecp256k1PubkeyLength = Buffer.from("21", "hex");
    pubBuf = Buffer.concat([
        AminoSecp256k1PubkeyPrefix,
        AminoSecp256k1PubkeyLength,
        pubBuf
    ]);
    return bech32.encode(`${hrp}pub`, bech32.toWords(pubBuf));
};

export const CosmosBufferToAddress = (pubBuf, hrp = "cosmos") => {
    const sha256_ed = createHash("sha256").update(pubBuf).digest();
    const ripemd160_ed = createHash("rmd160").update(sha256_ed).digest();
    return bech32.encode(hrp, bech32.toWords(ripemd160_ed));
};
