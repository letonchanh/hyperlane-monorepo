import type { Chain as WagmiChain } from '@wagmi/chains';

import { test1 } from '../consts/testChains.js';
import {
  ChainMetadata,
  getChainIdNumber,
} from '../metadata/chainMetadataTypes.js';

export function chainMetadataToWagmiChain(metadata: ChainMetadata): WagmiChain {
  return {
    id: getChainIdNumber(metadata),
    name: metadata.displayName || metadata.name,
    network: metadata.name,
    nativeCurrency: metadata.nativeToken || test1.nativeToken!,
    rpcUrls: {
      public: { http: [metadata.rpcUrls[0].http] },
      default: { http: [metadata.rpcUrls[0].http] },
    },
    blockExplorers: metadata.blockExplorers?.length
      ? {
          default: {
            name: metadata.blockExplorers[0].name,
            url: metadata.blockExplorers[0].url,
          },
        }
      : undefined,
    testnet: !!metadata.isTestnet,
  };
}
