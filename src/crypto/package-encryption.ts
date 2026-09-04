import { createCipheriv, randomBytes, hkdfSync } from "node:crypto"
import { PackageManifest } from "./types.js"


// MARK: Derive Package Key
type DerivePackageKeyArgs = { masterKey: string; manifest: PackageManifest }
export function derivePackageKey(args: DerivePackageKeyArgs): Buffer {
    const masterKeyBytes = Buffer.from(args.masterKey, "base64")
    if (masterKeyBytes.length !== 32) throw new Error(`masterKey must decode to 32 bytes, got ${masterKeyBytes.length}`)

    const info = Buffer.from(`${args.manifest.id}@${args.manifest.version}`)
    const derived = hkdfSync("sha256", masterKeyBytes, Buffer.alloc(0), info, 32)
    return Buffer.from(derived)
}


// MARK: Encrypt Package
type EncryptPackageArgs = { zipBuffer: Buffer; packageKey: Buffer }
export function encryptPackage(args: EncryptPackageArgs): Buffer {
    const iv = randomBytes(12)
    const cipher = createCipheriv("aes-256-gcm", args.packageKey, iv)
    const encrypted = Buffer.concat([cipher.update(args.zipBuffer), cipher.final()])
    const authTag = cipher.getAuthTag()

    return Buffer.concat([iv, encrypted, authTag])
}