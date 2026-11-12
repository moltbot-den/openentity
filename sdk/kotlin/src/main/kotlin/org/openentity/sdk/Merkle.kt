// Registry log proofs, ported from sdk/ts/src/merkle.ts: RFC 9162 leaf hashes and inclusion proofs, and the C2SP signed note
// that carries a checkpoint. Verify only.
package org.openentity.sdk

import java.util.Base64

/** RFC 9162 leaf hash, SHA-256(0x00 || leaf). A registry leaf's bytes are the UTF-8 of its canonical JSON. */
fun leafHash(leaf: ByteArray): ByteArray = sha256(byteArrayOf(0) + leaf)

private fun nodeHash(left: ByteArray, right: ByteArray): ByteArray = sha256(byteArrayOf(1) + left + right)

/** RFC 9162 section 2.1.3.2: [proof] puts the leaf hash [leaf] at [index] of a tree of [size] leaves whose root is [root]. */
fun verifyInclusion(index: Long, size: Long, leaf: ByteArray, proof: List<ByteArray>, root: ByteArray): Boolean {
    if (index < 0 || index >= size) return false
    var fn = index
    var sn = size - 1
    var r = leaf
    for (p in proof) {
        if (sn == 0L) return false
        if ((fn and 1L) == 1L || fn == sn) {
            r = nodeHash(p, r)
            while ((fn and 1L) == 0L && fn != 0L) {
                fn = fn shr 1
                sn = sn shr 1
            }
        } else {
            r = nodeHash(r, p)
        }
        fn = fn shr 1
        sn = sn shr 1
    }
    return sn == 0L && r.contentEquals(root)
}

/**
 * C2SP signed note, the form of a log checkpoint: true if one signature line by the key named [origin] (the log's origin,
 * `openentity.org/log`) verifies over the note text with the Ed25519 [publicKey]. The key id is the first 4 bytes of
 * SHA-256(origin, 0x0a, 0x01, publicKey).
 */
fun verifyNote(note: String, origin: String, publicKey: ByteArray): Boolean {
    val i = note.lastIndexOf("\n\n")
    if (i < 0 || !note.endsWith("\n") || i + 2 > note.length - 1) return false
    val text = note.substring(0, i + 1).toByteArray()
    val id = sha256(origin.toByteArray() + byteArrayOf(0x0a, 0x01) + publicKey).copyOf(4)
    val prefix = "\u2014 $origin " // signature lines start with U+2014
    for (line in note.substring(i + 2, note.length - 1).split("\n")) {
        if (!line.startsWith(prefix)) continue
        val raw = try {
            Base64.getDecoder().decode(line.substring(prefix.length))
        } catch (e: IllegalArgumentException) {
            continue
        }
        if (raw.size == 68 && raw.copyOf(4).contentEquals(id) && ed25519Verify(publicKey, text, raw.copyOfRange(4, 68))) return true
    }
    return false
}
