// Object storage for log tiles, checkpoints and snapshots: S3 in production, a Map in tests.
import { GetObjectCommand, NoSuchKey, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";

export interface Blobs {
  get(key: string): Promise<Uint8Array | null>;
  put(key: string, body: Uint8Array | string, contentType?: string): Promise<void>;
}

export function s3Blobs(bucket: string): Blobs {
  const s3 = new S3Client({});
  return {
    async get(key) {
      try {
        return await (await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }))).Body!.transformToByteArray();
      } catch (e) {
        if (e instanceof NoSuchKey) return null;
        throw e;
      }
    },
    async put(key, body, contentType = "application/octet-stream") {
      // Object Lock buckets require a checksum on every PUT.
      await s3.send(new PutObjectCommand({ Bucket: bucket, Key: key, Body: body, ContentType: contentType, ChecksumAlgorithm: "SHA256" }));
    },
  };
}

export function memoryBlobs(): Blobs {
  const m = new Map<string, Uint8Array>();
  return {
    get: async (key) => m.get(key) ?? null,
    put: async (key, body) => { m.set(key, typeof body === "string" ? new TextEncoder().encode(body) : body); },
  };
}
