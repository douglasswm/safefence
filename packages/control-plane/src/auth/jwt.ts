/**
 * JWT utilities for instance token creation and verification.
 * Uses the `jose` library for compact JWTs.
 */

import { SignJWT, jwtVerify, type JWTPayload } from "jose";

export interface InstanceTokenPayload extends JWTPayload {
  sub: string;  // instance_id
  org: string;  // org_id
  iss: string;  // "safefence"
}

const ALGORITHM = "HS256";
const ISSUER = "safefence";
const DEFAULT_EXPIRY = "24h";

let secretKey: Uint8Array;

export function initJwtSecret(secret: string): void {
  secretKey = new TextEncoder().encode(secret);
}

export async function createInstanceToken(instanceId: string, orgId: string): Promise<string> {
  return new SignJWT({ org: orgId })
    .setProtectedHeader({ alg: ALGORITHM })
    .setSubject(instanceId)
    .setIssuer(ISSUER)
    .setIssuedAt()
    .setExpirationTime(DEFAULT_EXPIRY)
    .sign(secretKey);
}

export async function verifyInstanceToken(token: string): Promise<InstanceTokenPayload> {
  const { payload } = await jwtVerify(token, secretKey, { issuer: ISSUER });
  return payload as InstanceTokenPayload;
}
