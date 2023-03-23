import STATIC_LOGO from '../../public/grape_white_logo.svg';
import RAYDIUM_STATIC_LOGO from '../../public/logos/platforms/raydium.png';
export const GRAPE_APP_API_URL = process.env.REACT_APP_API_URL || null;
export const TX_RPC_ENDPOINT = process.env.REACT_APP_API_GRAPE_RPC_ENDPOINT || 'https://api.mainnet-beta.solana.com';
export const GRAPE_RPC_ENDPOINT = process.env.REACT_APP_API_GRAPE_RPC_ENDPOINT || 'https://api.mainnet-beta.solana.com';
//export const GOVERNANCE_RPC_ENDPOINT = process.env.REACT_APP_API_GOVERNANCE_RPC_ENDPOINT || 'https://api.mainnet-beta.solana.com';
export const GOVERNANCE_RPC_ENDPOINT = process.env.REACT_APP_API_GRAPE_RPC_ENDPOINT || 'https://api.mainnet-beta.solana.com';
export const BONFIDA_TWITTER_REGISTRAR_URL = process.env.REACT_APP_API_BONFIDA_TWITTER_REGISTRAR_SERVER_URL || null;
export const GRAPE_TREASURY = 'GrapevviL94JZRiZwn2LjpWtmDacXU8QhAJvzpUMMFdL';

export const GOVERNANCE_PROGRAM_ID = 'GovER5Lthms3bLBqWub97yVrMmEogzX7xNjdXpPPCVZw';
export const REALM_ID = 'By2sVGZXwfQq6rAiAM3rNPJ9iQfb5e2QhnF4YjJ4Bip'; // Grape RealmId
export const GOVERNING_TOKEN = '8upjSpvjcdpuzhfR1zriwg5NXkwDruejqNE9WNbPRtyA'; // Grape Mint

export const DASHBOARD_LOGO = STATIC_LOGO;
export const RAYDIUM_LOGO = RAYDIUM_STATIC_LOGO;