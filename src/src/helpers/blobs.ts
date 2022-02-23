const ALLOWED_BLOB_MIMETYPES = [
  'image/jpeg',
  'image/gif',
  'image/png',

  'video/mp4',
  'video/webm',
  'video/ogg',

  'audio/mp4',
  'audio/webm',
  'audio/aac',
  'audio/mpeg',
  'audio/ogg',
  'audio/wave',
  'audio/wav',
  'audio/x-wav',
  'audio/x-pn-wav',
  'audio/flac',
  'audio/x-flac'
];

export function GetBlobSafeMimeType(mimetype: string): string {
  if (!ALLOWED_BLOB_MIMETYPES.includes(mimetype)) {
    return 'application/octet-stream';
  }
  return mimetype;
}
