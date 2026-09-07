import { sign } from "node:crypto"


type SignPackageArgs = { encryptedPackage: Buffer, privateKey: string }
export function signPackage(args: SignPackageArgs) {
    return sign(null, args.encryptedPackage, args.privateKey).toString("base64")
}