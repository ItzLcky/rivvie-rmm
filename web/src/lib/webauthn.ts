// WebAuthn in the browser. The server (webauthn-rs) sends options with base64url strings where
// the browser API wants buffers, and wants buffers sent back as base64url.

interface DescriptorJson { id: string; type: string; transports?: AuthenticatorTransport[] }
interface CreationOptionsJson {
	publicKey: Omit<PublicKeyCredentialCreationOptions, 'challenge' | 'user' | 'excludeCredentials'> & {
		challenge: string;
		user: { id: string; name: string; displayName: string };
		excludeCredentials?: DescriptorJson[];
	};
}
interface RequestOptionsJson {
	publicKey: Omit<PublicKeyCredentialRequestOptions, 'challenge' | 'allowCredentials'> & { challenge: string; allowCredentials?: DescriptorJson[] };
}

function fromB64url(s: string): ArrayBuffer {
	const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '='));
	return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
}

function toB64url(b: ArrayBuffer | null | undefined): string | null {
	if (!b) return null;
	let s = '';
	for (const byte of new Uint8Array(b)) s += String.fromCharCode(byte);
	return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const descriptors = (list?: DescriptorJson[]): PublicKeyCredentialDescriptor[] | undefined =>
	list?.map((c) => ({ ...c, type: c.type as PublicKeyCredentialType, id: fromB64url(c.id) }));

/** Whether this browser can do passkeys at all (it needs a secure context). */
export function passkeysSupported(): boolean {
	return typeof window !== 'undefined' && !!window.PublicKeyCredential && !!navigator.credentials;
}

/** True when the person closed the browser's prompt or it timed out. */
export function cancelled(e: unknown): boolean {
	return e instanceof DOMException && (e.name === 'NotAllowedError' || e.name === 'AbortError');
}

/** Asks the browser to make a passkey; returns what `/auth/passkeys/register/finish` takes. */
export async function createPasskey(options: CreationOptionsJson) {
	const pk = options.publicKey;
	const cred = (await navigator.credentials.create({
		publicKey: { ...pk, challenge: fromB64url(pk.challenge), user: { ...pk.user, id: fromB64url(pk.user.id) }, excludeCredentials: descriptors(pk.excludeCredentials) }
	})) as PublicKeyCredential | null;
	if (!cred) throw new Error('No passkey was created');
	const r = cred.response as AuthenticatorAttestationResponse;
	return {
		id: cred.id,
		rawId: toB64url(cred.rawId),
		type: cred.type,
		extensions: cred.getClientExtensionResults(),
		response: { attestationObject: toB64url(r.attestationObject), clientDataJSON: toB64url(r.clientDataJSON), transports: r.getTransports?.() ?? [] }
	};
}

/** Asks the browser to sign in with a passkey; returns what `/auth/login` takes under `passkey.credential`. */
export async function usePasskey(options: RequestOptionsJson) {
	const pk = options.publicKey;
	const cred = (await navigator.credentials.get({ publicKey: { ...pk, challenge: fromB64url(pk.challenge), allowCredentials: descriptors(pk.allowCredentials) } })) as PublicKeyCredential | null;
	if (!cred) throw new Error('No passkey was used');
	const r = cred.response as AuthenticatorAssertionResponse;
	return {
		id: cred.id,
		rawId: toB64url(cred.rawId),
		type: cred.type,
		extensions: cred.getClientExtensionResults(),
		response: { authenticatorData: toB64url(r.authenticatorData), clientDataJSON: toB64url(r.clientDataJSON), signature: toB64url(r.signature), userHandle: toB64url(r.userHandle) }
	};
}
