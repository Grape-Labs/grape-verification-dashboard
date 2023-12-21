export const PRICE_REFRESH_TIMEOUT = 10 * 60 * 1000;
export const STREAMS_REFRESH_TIMEOUT = 5 * 60 * 1000;
export const TRANSACTION_STATUS_RETRY = 3 * 1000;            // Retry fetch transaction status every 3 seconds
export const TRANSACTION_STATUS_RETRY_TIMEOUT = 30 * 1000;   // Max timeout for trying fetch
export const INPUT_AMOUNT_PATTERN = /^[0-9]*[.,]?[0-9]*$/;
export const SIMPLE_DATE_FORMAT = 'mm/dd/yyyy';
export const SIMPLE_DATE_TIME_FORMAT = 'mm/dd/yyyy HH:MM';
export const SIMPLE_DATE_TIME_FORMAT_WITH_SECONDS = 'mm/dd/yyyy HH:MM:ss';
export const UTC_DATE_TIME_FORMAT = "UTC:ddd, dd mmm HH:MM:ss";
export const UTC_DATE_TIME_FORMAT2 = "UTC:ddd, dd mmm HH:MM:ss Z";
export const UTC_FULL_DATE_TIME_FORMAT = "UTC:dddd, mmm dS 'at' HH:MM Z";
export const VERBOSE_DATE_FORMAT = 'ddd mmm dd yyyy';
export const VERBOSE_DATE_TIME_FORMAT = 'ddd mmm dd yyyy HH:MM';
export const SOLANA_EXPLORER_URI_INSPECT_ADDRESS = 'https://solscan.io/account/';
export const SOLANA_EXPLORER_URI_INSPECT_TRANSACTION = 'https://solscan.io/tx/';
export const DEDICATED_FREE_FAST_RPC = process.env.REACT_APP_API_RPC_ENDPOINT || 'https://api.mainnet-beta.solana.com';
export const BANNED_TOKENS = [
    'CRT',
    'FROG',
    'DGX',
    'DOGA',
    'CHIH',
    'INO',
    'GSTONKS'
];

export const MONEY_STREAMING_PROGRAM_ADDRESS = 'MSPCUMbLfy2MeT6geLMMzrUkv1Tx88XRApaVRdyxTuu';
