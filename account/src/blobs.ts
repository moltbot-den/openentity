// Message attachments in S3 (POST /v1/agent/uploads, GET /v1/attachments/{id}). The bucket is private: an agent PUTs
// through a 5-minute presigned URL whose content-type and content-length are signed, so the upload is exactly the
// declared size; the owner GETs through a 5-minute presigned URL that downloads as a file.
import { GetObjectCommand, HeadObjectCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

export const URL_TTL = 300;

export interface Blobs {
  /** A presigned PUT for exactly `size` bytes of `contentType`, and the headers the uploader must send. */
  putUrl(key: string, contentType: string, size: number): Promise<{ url: string; headers: Record<string, string> }>;
  /** The stored object's size, or null when nothing was uploaded. */
  size(key: string): Promise<number | null>;
  /** A presigned GET that downloads as `name`. */
  getUrl(key: string, name: string, contentType: string): Promise<string>;
}

export function s3Blobs(bucket: string): Blobs {
  const s3 = new S3Client({});
  const signed = new Set(["content-type", "content-length"]);
  return {
    async putUrl(key, contentType, size) {
      const url = await getSignedUrl(s3, new PutObjectCommand({ Bucket: bucket, Key: key, ContentType: contentType, ContentLength: size }),
        { expiresIn: URL_TTL, signableHeaders: signed, unhoistableHeaders: signed });
      return { url, headers: { "content-type": contentType, "content-length": String(size) } };
    },
    async size(key) {
      try {
        return (await s3.send(new HeadObjectCommand({ Bucket: bucket, Key: key }))).ContentLength ?? null;
      } catch (e) {
        if ((e as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode === 404) return null;
        throw e;
      }
    },
    getUrl: (key, name, contentType) => getSignedUrl(s3, new GetObjectCommand({
      Bucket: bucket, Key: key, ResponseContentType: contentType, ResponseContentDisposition: `attachment; filename*=UTF-8''${encodeURIComponent(name)}`,
    }), { expiresIn: URL_TTL }),
  };
}
