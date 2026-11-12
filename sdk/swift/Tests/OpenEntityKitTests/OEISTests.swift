import CryptoKit
import Foundation
import OpenEntityKit
import Testing

// The OEIS-1 vectors in test-vectors/, checked as the "test vectors" suite of sdk/ts/test/sdk.test.ts checks them.
// http-signature.json is the RFC 9421 profile the registry and agents use server side; this SDK does not implement it.

let oeisKeys = (try? vector("keys.json")) ?? .null
let entity = oeisKeys.at("entity").at("eid").str, second = oeisKeys.at("second").at("eid").str

func unsigned(_ v: JSONValue) -> JSONValue {
    guard case .object(let m) = v else { return v }
    return .object(m.filter { $0.key != "proof" && $0.key != "proofs" })
}

@Suite("OEIS-1 vectors")
struct OEISTests {
    @Test(arguments: ["declaration.json", "entity-document.json", "record-1.json", "record-2.json", "attestation.json"] + vectorFiles("", prefix: "claim-"))
    func signedObject(_ file: String) throws {
        let v = try vector(file), object = v.at("object")
        let canonical = try canonicalize(object)
        #expect(canonical == v.at("canonical").str)
        #expect(hex(SHA256.hash(data: Data(canonical.utf8))) == v.at("sha256").str)
        #expect(try canonicalize(unsigned(object)) == v.at("unsigned_canonical").str)
        let signer = try verifyObject(object)
        #expect(signer == (object["issuer"] ?? object.at("eid")).str)
        #expect([entity, second].contains(signer))
    }

    @Test func claimVectorsArePresent() {
        #expect(vectorFiles("", prefix: "claim-").count >= 4)
    }

    @Test func continuityLinkIsSignedByBothKeys() throws {
        let link = try vector("continuity-link.json").at("object")
        #expect(try link.at("proofs").list.map { try verifyProof(link, $0) } == [entity, second])
    }

    @Test func rotationLinkAndSuccessorDocumentVerify() throws {
        let request = try vector("rotation.json").at("request")
        let link = request.at("link"), document = request.at("document")
        #expect(try link.at("proofs").list.map { try verifyProof(link, $0) } == [entity, second])
        #expect(try verifyObject(document) == second)
        #expect(document.at("eid").str == second && document.at("continuity").at("previous").str == entity)
    }

    @Test func logLeavesAndCheckpoint() throws {
        let cp = try vector("checkpoint.json")
        let logKey = unhex(oeisKeys.at("log").at("publicKeyHex").str)
        #expect(cp.at("origin").str == "openentity.org/log")
        #expect(verifyNote(note: cp.at("note").str, origin: "openentity.org/log", publicKey: logKey))
        let size = Int(cp.at("tree_size").int), root = unhex(cp.at("root_hash").str)
        #expect(size == 6)
        for i in 0..<size {
            let leaf = try vector("log-leaf-\(i).json")
            #expect(try canonicalize(leaf.at("object")) == leaf.at("canonical").str)
            let hash = leafHash(Data(leaf.at("canonical").str.utf8))
            #expect(hex(hash) == leaf.at("leaf_hash").str, "leaf \(i)")
            let proof = cp.at("inclusion_proofs").list[i].strings.map(unhex)
            #expect(verifyInclusion(index: i, size: size, leaf: hash, proof: proof, root: root), "leaf \(i)")
            #expect(!verifyInclusion(index: (i + 1) % size, size: size, leaf: hash, proof: proof, root: root), "leaf \(i) at another index")
            #expect(!verifyInclusion(index: i, size: size, leaf: hash, proof: Array(proof.dropLast()), root: root), "leaf \(i) short proof")
            #expect(!verifyInclusion(index: i, size: size, leaf: leafHash(Data("x".utf8)), proof: proof, root: root), "another leaf at \(i)")
        }
    }

    @Test func tamperedObjectsAndWrongKeysFail() throws {
        guard case .object(let members) = try vector("attestation.json").at("object") else { Issue.record("no object"); return }
        let tampered = JSONValue.object(members.map { m -> (key: String, value: JSONValue) in
            m.key == "subject" ? (key: "subject", value: .string(second)) : m
        })
        #expect(throws: OpenEntityError.self) { try verifyObject(tampered) }
        let noProof = JSONValue.object(members.filter { $0.key != "proof" })
        #expect(throws: OpenEntityError.self) { try verifyObject(noProof) }

        let cp = try vector("checkpoint.json")
        let note = cp.at("note").str
        #expect(!verifyNote(note: note, origin: "openentity.org/log", publicKey: unhex(oeisKeys.at("entity").at("publicKeyHex").str)))
        #expect(!verifyNote(note: note, origin: "openentity.org/other", publicKey: unhex(oeisKeys.at("log").at("publicKeyHex").str)))
        #expect(!verifyNote(note: note.replacingOccurrences(of: "\n6\n", with: "\n7\n"), origin: "openentity.org/log",
                            publicKey: unhex(oeisKeys.at("log").at("publicKeyHex").str)))
    }

    @Test func eip712IsUnsupported() throws {
        let object = try JSONValue.parse("""
            {"type":"EntityDocument","proof":{"type":"EthereumEip712Signature2021","created":"2026-01-01T00:00:00Z",
             "verificationMethod":"did:pkh:eip155:8453:0x52908400098527886E0F7030069857D2E4169EE7#blockchainAccountId",
             "proofPurpose":"assertionMethod","proofValue":"0x00"}}
            """)
        if case .failure(let e) = outcome({ () throws(OpenEntityError) in try verifyObject(object) }) {
            #expect(e.code == "unsupported")
        } else {
            Issue.record("accepted an EIP-712 proof")
        }
    }
}
