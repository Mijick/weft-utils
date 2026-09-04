import { createCipheriv, randomBytes, hkdfSync } from "node:crypto"
import { PackageManifest } from "./types.js"


// MARK: Derive Package Key
type DerivePackageKeyArgs = { masterKey: string; manifest: PackageManifest }
export function derivePackageKey(args: DerivePackageKeyArgs) {
    const info = Buffer.from(`${args.manifest.id}@${args.manifest.version}`)
    const derived = hkdfSync("sha256", args.masterKey, Buffer.alloc(0), info, 32)
    return Buffer.from(derived)
}


// MARK: Encrypt Package
export function encryptPackage(zipBuffer: Buffer, manifest: PackageManifest) {
    const iv = randomBytes(12)
    const cipher = createCipheriv("aes-256-gcm", packageKey, iv)
    const encrypted = Buffer.concat([cipher.update(zipBuffer), cipher.final()])
    const authTag = cipher.getAuthTag()

    return Buffer.concat([iv, encrypted, authTag])
}