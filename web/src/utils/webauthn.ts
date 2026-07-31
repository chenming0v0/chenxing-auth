/**
 * WebAuthn bridge between webauthn-rs (server) and the browser credential API.
 *
 * The server returns/expects base64url-encoded buffers, while
 * navigator.credentials works with ArrayBuffers. These helpers convert the
 * challenge options before a create/get call and re-encode the resulting
 * credential before sending it back.
 */

function base64urlToBytes(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function bytesToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** webauthn-rs wraps its options in a `publicKey` member. */
interface CredentialOptions {
  publicKey: Record<string, unknown>;
}

/**
 * Decode the base64url buffers in a registration challenge so it can be passed
 * to navigator.credentials.create().
 */
export function decodeCreationOptions(options: CredentialOptions): PublicKeyCredentialCreationOptions {
  const publicKey = options.publicKey as unknown as PublicKeyCredentialCreationOptions;
  const user = publicKey.user as unknown as { id: string };
  return {
    ...publicKey,
    challenge: base64urlToBytes(publicKey.challenge as unknown as string),
    user: { ...publicKey.user, id: base64urlToBytes(user.id) },
    excludeCredentials: decodeCredentialList(publicKey.excludeCredentials),
  };
}

/**
 * Decode the base64url buffers in an authentication challenge so it can be
 * passed to navigator.credentials.get().
 */
export function decodeRequestOptions(options: CredentialOptions): PublicKeyCredentialRequestOptions {
  const publicKey = options.publicKey as unknown as PublicKeyCredentialRequestOptions;
  return {
    ...publicKey,
    challenge: base64urlToBytes(publicKey.challenge as unknown as string),
    allowCredentials: decodeCredentialList(publicKey.allowCredentials),
  };
}

function decodeCredentialList(list?: PublicKeyCredentialDescriptor[]): PublicKeyCredentialDescriptor[] | undefined {
  return list?.map((descriptor) => ({
    ...descriptor,
    id: base64urlToBytes(descriptor.id as unknown as string),
  }));
}

/** Re-encode a registration credential into the JSON shape webauthn-rs expects. */
export function encodeRegistrationCredential(credential: PublicKeyCredential) {
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: bytesToBase64url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: bytesToBase64url(response.attestationObject),
      clientDataJSON: bytesToBase64url(response.clientDataJSON),
    },
    extensions: credential.getClientExtensionResults(),
  };
}

/** Re-encode an authentication credential into the JSON shape webauthn-rs expects. */
export function encodeAuthenticationCredential(credential: PublicKeyCredential) {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: bytesToBase64url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: bytesToBase64url(response.authenticatorData),
      clientDataJSON: bytesToBase64url(response.clientDataJSON),
      signature: bytesToBase64url(response.signature),
      userHandle: response.userHandle ? bytesToBase64url(response.userHandle) : null,
    },
    extensions: credential.getClientExtensionResults(),
  };
}
