# Cross-Chain Gas Comparison

## Overview

The Cross-Chain Gas Comparison feature provides real-time gas cost analysis across multiple blockchain networks, enabling developers to make informed decisions about which chain offers the most cost-effective transaction execution at any given time.

## Features

### 🔄 Real-Time Gas Aggregation
- Collects gas metrics from all supported chains
- Monitors base fees, priority fees, and average gas usage
- Updates native token prices for USD normalization

### 💰 Cost Normalization
- Converts all gas costs to USD equivalents
- Maintains native token values for transparency
- Uses consistent calculation methodology across chains

### 📊 Chain Ranking
- Ranks chains by transaction cost efficiency
- Provides confirmation time estimates
- Offers deterministic, transparent ranking criteria

## Supported Chains

| Chain ID | Chain Name | Native Token | Block Time |
|-----------|-------------|---------------|-------------|
| 1 | Ethereum | ETH | 12s |
| 137 | Polygon | MATIC | 2s |
| 56 | Binance Smart Chain | BNB | 3s |
| 42161 | Arbitrum | ETH | 0.5s |
| 10 | Optimism | ETH | 2s |

## API Endpoints

### GET /v1/analytics/cross-chain-gas

Compare gas costs across all supported chains for a specific transaction type.

**Parameters:**
- `txType` (required): Transaction type (`transfer`, `contract-call`, `swap`)

**Example Request:**
```
GET /v1/analytics/cross-chain-gas?txType=transfer
```

**Example Response:**
```json
{
  "txType": "transfer",
  "timestamp": 1700000000,
  "chains": [
    {
      "chainId": 137,
      "estimatedCostUSD": 0.12,
      "estimatedCostNative": "0.00045",
      "averageConfirmationTime": "2 seconds",
      "rank": 1
    },
    {
      "chainId": 42161,
      "estimatedCostUSD": 0.18,
      "estimatedCostNative": "0.00009",
      "averageConfirmationTime": "500ms",
      "rank": 2
    },
    {
      "chainId": 1,
      "estimatedCostUSD": 1.85,
      "estimatedCostNative": "0.00052",
      "averageConfirmationTime": "12 seconds",
      "rank": 5
    }
  ]
}
```

### GET /v1/analytics/supported-chains

Retrieve all supported chains with their metadata and configuration.

**Example Response:**
```json
[
  {
    "chainId": 1,
    "chainName": "Ethereum",
    "nativeToken": "ETH",
    "rpcUrl": "https://eth-mainnet.alchemyapi.io/v2/demo",
    "blockTime": 12
  }
]
```

### GET /v1/analytics/cross-chain-gas/refresh

Force refresh of gas price data and native token prices (admin endpoint).

**Example Response:**
```json
{
  "message": "Gas price data refreshed successfully",
  "timestamp": 1700000000
}
```

### GET /v1/analytics/cross-chain-gas/history

Retrieve historical gas price data for a specific chain.

**Parameters:**
- `chainId` (required): Chain ID to fetch historical data for
- `hours` (optional): Number of hours of historical data to fetch (default: 24)

**Example Request:**
```
GET /v1/analytics/cross-chain-gas/history?chainId=1&hours=24
```

## Calculation Methodology

### Gas Cost Normalization
```
Total Cost = Gas Used × Effective Gas Price
USD Cost = Total Cost × Native Token Price USD
```

### Transaction Types
- **Transfer**: 21,000 gas units (standard ETH transfer)
- **Contract Call**: 50,000 gas units (average contract interaction)
- **Swap**: 150,000 gas units (DEX swap transaction)

### Ranking Criteria
1. **Primary**: Lowest USD cost
2. **Secondary**: Confirmation time
3. **Tertiary**: Chain stability

## Integration Guide

### Basic Usage

```typescript
// Get gas comparison for transfer
const response = await fetch('/v1/analytics/cross-chain-gas?txType=transfer');
const data = await response.json();

// Find cheapest chain
const cheapestChain = data.chains.find(chain => chain.rank === 1);
console.log(`Cheapest chain: ${cheapestChain.chainName} - $${cheapestChain.estimatedCostUSD}`);
```

### Advanced Usage

```typescript
// Get supported chains
const chains = await fetch('/v1/analytics/supported-chains');
const supportedChains = await chains.json();

// Filter chains by block time
const fastChains = supportedChains.filter(chain => chain.blockTime < 3);

// Get historical data
const history = await fetch('/v1/analytics/cross-chain-gas/history?chainId=1&hours=24');
const historicalData = await history.json();
```

## Configuration

### Environment Variables

```bash
ETHEREUM_RPC_URL=https://eth-mainnet.alchemyapi.io/v2/your-api-key
POLYGON_RPC_URL=https://polygon-mainnet.alchemyapi.io/v2/your-api-key
BSC_RPC_URL=https://bsc-dataseed.binance.org
ARBITRUM_RPC_URL=https://arb1.arbitrum.io/rpc
OPTIMISM_RPC_URL=https://mainnet.optimism.io
```

### Mock Data

In development mode, the service uses mock data:
- Gas prices based on typical network conditions
- Native token prices set to realistic values
- Historical data returns empty arrays

## Performance Considerations

### Caching
- Gas price data cached for 30 seconds
- Native token prices cached for 60 seconds
- Historical data cached for 5 minutes

### Rate Limiting
- API endpoints limited to 10 requests per minute per IP
- Historical endpoints limited to 5 requests per minute per IP

### Error Handling
- Invalid transaction types return 400 status
- Unsupported chain IDs return 404 status
- Network timeouts handled gracefully with fallback data

## Testing

### Unit Tests
```bash
# Run all tests
npm test

# Run specific test file
npm test -- cross-chain-gas.service.spec.ts
```

### Integration Tests
```bash
# Test API endpoints
curl "http://localhost:3000/v1/analytics/cross-chain-gas?txType=transfer"

# Test supported chains
curl "http://localhost:3000/v1/analytics/supported-chains"
```

## Monitoring

### Metrics to Track
- API response times
- Gas price update frequency
- Cache hit rates
- Error rates by chain

### Alerts
- Gas price anomalies (>50% change in 5 minutes)
- Chain connectivity issues
- API performance degradation

## Troubleshooting

### Common Issues

**High Gas Prices**
- Check network congestion
- Verify RPC endpoint connectivity
- Consider alternative chains

**Inaccurate Rankings**
- Refresh gas price data
- Verify native token prices
- Check calculation methodology

**API Timeouts**
- Increase timeout values
- Check network connectivity
- Verify RPC endpoint status

### Debug Mode

Enable debug logging:
```bash
DEBUG=gasguard:* npm run start:dev
```

## Future Enhancements

### Volatility-Adjusted Costs
- Calculate cost volatility over time
- Provide risk-adjusted rankings
- Include confidence intervals

### Advanced Transaction Types
- DeFi protocol interactions
- NFT minting/transfers
- Multi-signature transactions

### Real-Time Alerts
- Gas price drop notifications
- Chain congestion warnings
- Cost optimization recommendations

## Contributing

### Adding New Chains

1. Update `supportedChains` array in `CrossChainGasService`
2. Add chain configuration to environment variables
3. Update documentation
4. Add unit tests
5. Update API documentation

### Testing Changes

1. Write unit tests for new functionality
2. Test API endpoints manually
3. Verify calculation accuracy
4. Update documentation

## Support

For issues or questions regarding the Cross-Chain Gas Comparison feature:

1. Check this documentation
2. Review API response formats
3. Verify configuration
4. Check GitHub Issues
5. Contact development team
