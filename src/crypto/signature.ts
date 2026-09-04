import { createHash, sign } from "node:crypto"


type CreateSignatureArgs = { data: Buffer, privateKey: string }
export function createSignature(args: CreateSignatureArgs) {
    const hash = createHash("sha256")
        .update(args.data)
        .digest()
    return sign(null, hash, args.privateKey).toString("base64")
}