import { Buffer } from "buffer";
import { Connection, PublicKey } from "@solana/web3.js";
import { PROGRAM_ID } from "@grapenpm/grape-verification-registry";
import { sha256 } from "@noble/hashes/sha256";
import { utf8ToBytes } from "@noble/hashes/utils";

export async function loadCommunityStats(connection: Connection, space: PublicKey) {
  const filter = (name: string) => ({ memcmp: {
    offset: 0, bytes: Buffer.from(sha256(utf8ToBytes(`account:${name}`)).slice(0, 8)).toString("base64"),
    encoding: "base64" as const,
  } });
  const [identities, links] = await Promise.all([
    connection.getProgramAccounts(PROGRAM_ID, { filters: [filter("GrapeVerificationIdentity"), { memcmp: { offset: 9, bytes: space.toBase58() } }] }),
    connection.getProgramAccounts(PROGRAM_ID, { filters: [filter("GrapeVerificationLink")] }),
  ]);
  const now = Math.floor(Date.now() / 1000);
  const active = new Map<string, boolean>();
  for (const { pubkey, account } of identities) {
    const data = account.data;
    if (!account.owner.equals(PROGRAM_ID) || data.length < 123 || !new PublicKey(data.subarray(9, 41)).equals(space)) throw new Error("Invalid identity record");
    const expires = Number(data.readBigInt64LE(83));
    active.set(pubkey.toBase58(), data[74] === 1 && (expires === 0 || expires >= now));
  }
  const linked = new Set<string>();
  const verified = new Set<string>();
  for (const { account } of links) {
    const data = account.data;
    if (!account.owner.equals(PROGRAM_ID) || data.length < 81) throw new Error("Invalid wallet link record");
    const identity = new PublicKey(data.subarray(9, 41)).toBase58();
    if (!active.has(identity)) continue;
    const hash = data.subarray(41, 73).toString("hex");
    linked.add(hash);
    if (active.get(identity)) verified.add(hash);
  }
  return { linked: linked.size, verified: verified.size, identities: active.size, checkedAt: Date.now() };
}
