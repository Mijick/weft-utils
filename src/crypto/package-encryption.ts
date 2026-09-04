import { createCipheriv, randomBytes, hkdfSync } from "node:crypto"
import { PackageManifest } from "./types.js"









// MARK: Derive Package Key
export function derivePackageKey(manifest: PackageManifest) {
    const info = Buffer.from(`${id}@${version}`)
    const derived = hkdfSync("sha256", masterKey, Buffer.alloc(0), info, 32)
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