import { Buffer } from "buffer";
import { Connection, PublicKey } from "@solana/web3.js";
import { PROGRAM_ID, type LinkedWallet } from "@grapenpm/grape-verification-registry";
import { sha256 } from "@noble/hashes/sha256";
import { utf8ToBytes } from "@noble/hashes/utils";

/** Discover distinct wallets without converting failed RPC requests into an empty list. */
export async function loadLinkedWallets(
  connection: Connection,
  identities: PublicKey[],
  currentHash: Uint8Array,
): Promise<LinkedWallet[]> {
  const currentHex = Buffer.from(currentHash).toString("hex");
  const wallets = new Map<string, LinkedWallet>();
  const discriminator = sha256(utf8ToBytes("account:GrapeVerificationLink")).slice(0, 8);
  const uniqueIdentities = new Map(identities.map((identity) => [identity.toBase58(), identity]));
  for (const identity of uniqueIdentities.values()) {
    const accounts = await connection.getProgramAccounts(PROGRAM_ID, {
      filters: [
        { memcmp: { offset: 0, bytes: Buffer.from(discriminator).toString("base64"), encoding: "base64" } },
        { memcmp: { offset: 9, bytes: identity.toBase58() } },
      ],
    });
    for (const { pubkey, account } of accounts) {
      const data = account.data;
      if (!account.owner.equals(PROGRAM_ID) || data.length < 81 ||
          !new PublicKey(data.slice(9, 41)).equals(identity)) {
        throw new Error("Invalid linked wallet record");
      }
      const walletHashBytes = data.slice(41, 73);
      const walletHashHex = Buffer.from(walletHashBytes).toString("hex");
      const linkedAt = Number(new DataView(data.buffer, data.byteOffset, data.byteLength).getBigInt64(73, true));
      const previous = wallets.get(walletHashHex);
      if (!previous || linkedAt < previous.linkedAt) {
        wallets.set(walletHashHex, { pubkey, identity, walletHashBytes, walletHashHex, linkedAt,
          isCurrentWallet: walletHashHex === currentHex });
      }
    }
  }
  return [...wallets.values()].sort((a, b) => Number(b.isCurrentWallet) - Number(a.isCurrentWallet) || a.linkedAt - b.linkedAt);
}
