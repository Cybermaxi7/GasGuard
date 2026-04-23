# Failed Transaction Cost Analyzer

## Overview

The Failed Transaction Cost Analyzer is a comprehensive analytics module that tracks, analyzes, and provides mitigation strategies for reverted transactions in the GasGuard ecosystem. It helps users understand why transactions fail, quantify the cost of failures, and receive actionable recommendations to reduce transaction waste.

## Features

### 1. Reverted Transaction Tracking
- **Real-time Monitoring**: Tracks failed transactions sent via GasGuard
- **Multi-chain Support**: Works across Ethereum, Polygon, BSC, Arbitrum, and Optimism
- **Comprehensive Data Capture**: Stores gas usage, pricing, block information, and revert reasons
- **Structured Logging**: Organized failure data for efficient analysis

### 2. Root Cause Analysis Engine
- **Intelligent Classification**: Automatically categorizes failures into:
  - Underpriced Gas
  - Out of Gas
  - Contract Revert
  - Slippage Exceeded
  - Nonce Conflict
  - Insufficient Balance
  - Network Error
  - Unknown
- **Evidence Collection**: Gathers supporting evidence for each classification
- **Pattern Recognition**: Identifies recurring failure patterns
- **Confidence Scoring**: Provides confidence levels for each diagnosis

### 3. Cost Quantification
- **Gas Waste Calculation**: Precise computation of wasted gas in native tokens
- **USD Conversion**: Real-time conversion to USD value
- **Historical Tracking**: 30-day trend analysis
- **Category Breakdown**: Waste analysis by failure category
- **Chain Comparison**: Cross-chain waste metrics

### 4. Mitigation Suggestion Engine
- **Deterministic Recommendations**: Provides specific, actionable advice
- **Priority-based**: High, medium, and low priority suggestions
- **Real-time Fixes**: Immediate actions for stuck transactions
- **Pattern-based**: Long-term optimization strategies
- **Chain-specific**: Tailored advice for each network

## API Endpoints

### Analyze Wallet Failures
```http
POST /v1/failed-transactions/analyze
```

**Request Body:**
```json
{
  "wallet": "0x1234567890abcdef1234567890abcdef12345678",
  "chainIds": [1, 137, 42161],
  "timeframe": {
    "start": "2024-01-01T00:00:00Z",
    "end": "2024-01-31T23:59:59Z"
  },
  "includeRecommendations": true
}
```

**Response:**
```json
{
  "wallet": "0x1234567890abcdef1234567890abcdef12345678",
  "analysis": {
    "totalFailures": 14,
    "totalGasWasted": "0.052 ETH",
    "totalGasWastedUSD": 104.00,
    "failureCategories": {
      "underpriced_gas": 6,
      "slippage_exceeded": 4,
      "out_of_gas": 2,
      "nonce_conflict": 2
    },
    "topFailureCategory": "underpriced_gas",
    "recommendations": [
      {
        "id": "increase_gas_price",
        "category": "underpriced_gas",
        "priority": "high",
        "title": "Increase Gas Price",
        "description": "Your transactions are failing due to gas prices that are too low for network conditions.",
        "action": "Increase priority fee by 25-50% during peak hours",
        "estimatedImpact": "Reduces failure rate by 80-90%"
      }
    ],
    "timeframe": {
      "start": "2024-01-01T00:00:00Z",
      "end": "2024-01-31T23:59:59Z"
    },
    "chainBreakdown": {
      "1": {
        "chainId": 1,
        "failures": 8,
        "gasWasted": "0.032 ETH",
        "mostCommonCategory": "underpriced_gas"
      },
      "137": {
        "chainId": 137,
        "failures": 6,
        "gasWasted": "0.020 ETH",
        "mostCommonCategory": "slippage_exceeded"
      }
    }
  },
  "processedAt": "2024-01-31T12:00:00Z",
  "requestId": "req_1234567890_abcdef123"
}
```

### Get Wallet Summary
```http
GET /v1/failed-transactions/{wallet}/summary?chainIds=1,137
```

**Response:**
```json
{
  "wallet": "0x1234567890abcdef1234567890abcdef12345678",
  "summary": {
    "totalFailures": 25,
    "totalGasWasted": "0.125 ETH",
    "totalGasWastedUSD": 250.00,
    "last30DaysFailures": 14,
    "last7DaysFailures": 3,
    "averageFailuresPerDay": "0.83",
    "mostActiveChain": 1,
    "topFailureCategory": "underpriced_gas"
  },
  "processedAt": "2024-01-31T12:00:00Z"
}
```

### Get Immediate Mitigation
```http
GET /v1/failed-transactions/{wallet}/mitigation?txHash=0x123...
```

**Response:**
```json
{
  "transaction": {
    "id": "ft_1234567890_abcdef123",
    "hash": "0x1234567890abcdef1234567890abcdef12345678",
    "wallet": "0x1234567890abcdef1234567890abcdef12345678",
    "chainId": 1,
    "failureCategory": "underpriced_gas",
    "gasUsed": "21000",
    "gasPrice": "10000000000",
    "effectiveFee": "210000000000000"
  },
  "recommendations": [
    {
      "id": "immediate_gas_increase",
      "category": "underpriced_gas",
      "priority": "high",
      "title": "Immediate Gas Price Increase",
      "description": "Replace transaction with higher gas price.",
      "action": "Set gas price to 30000000000 wei",
      "estimatedImpact": "Immediate transaction confirmation"
    }
  ],
  "processedAt": "2024-01-31T12:00:00Z"
}
```

### Track Failed Transaction
```http
POST /v1/failed-transactions/track
```

**Request Body:**
```json
{
  "hash": "0x1234567890abcdef1234567890abcdef12345678",
  "wallet": "0x1234567890abcdef1234567890abcdef12345678",
  "chainId": 1,
  "gasUsed": "21000",
  "gasPrice": "10000000000",
  "revertReason": "transaction underpriced",
  "metadata": {
    "nonce": 1,
    "gasLimit": "21000",
    "transactionType": "legacy"
  }
}
```

## Failure Categories

### Underpriced Gas
**Description**: Transaction gas price is too low for current network conditions.
**Detection**: Gas price significantly below network average.
**Recommendations**:
- Increase priority fee by 25-50%
- Use dynamic gas pricing
- Monitor network congestion

### Out of Gas
**Description**: Transaction execution exceeds gas limit.
**Detection**: Gas usage ≥ 99.5% of gas limit.
**Recommendations**:
- Increase gas limit by 20-30%
- Optimize contract interactions
- Break complex operations

### Slippage Exceeded
**Description**: DEX trade fails due to price movement.
**Detection**: Revert reason contains slippage-related keywords.
**Recommendations**:
- Increase slippage tolerance to 1-2%
- Use volatility indicators
- Time trades optimally

### Nonce Conflict
**Description**: Multiple transactions with same nonce.
**Detection**: Duplicate nonce in recent transactions.
**Recommendations**:
- Replace stuck transactions
- Implement nonce management
- Use transaction queueing

### Insufficient Balance
**Description**: Not enough ETH for gas + transaction value.
**Detection**: Balance < gas cost + transaction value.
**Recommendations**:
- Pre-transaction balance checks
- Split large transactions
- Use gas estimation

## Integration Guide

### 1. Tracking Failed Transactions

```typescript
import { FailedTransactionService } from './services/failed-transaction.service';

// Track a failed transaction
const failedTx = await failedTransactionService.trackFailedTransaction({
  hash: '0x123...',
  wallet: '0xabc...',
  chainId: 1,
  gasUsed: '21000',
  gasPrice: '20000000000',
  revertReason: 'transaction underpriced',
  metadata: {
    nonce: 1,
    gasLimit: '21000',
    transactionType: 'legacy'
  }
});
```

### 2. Analyzing Wallet Failures

```typescript
import { TransactionAnalysisService } from './services/transaction-analysis.service';

// Analyze wallet failures
const analysis = await transactionAnalysisService.analyzeWalletFailures({
  wallet: '0xabc...',
  chainIds: [1, 137],
  timeframe: {
    start: '2024-01-01T00:00:00Z',
    end: '2024-01-31T23:59:59Z'
  },
  includeRecommendations: true
});
```

### 3. Getting Mitigation Recommendations

```typescript
import { MitigationService } from './services/mitigation.service';

// Get immediate mitigation
const mitigation = await mitigationService.getImmediateMitigation(failedTransaction);
```

## Configuration

### Environment Variables

```bash
# Gas price oracle endpoints
ETHEREUM_GAS_ORACLE=https://api.etherscan.io/api?module=gastracker
POLYGON_GAS_ORACLE=https://api.polygonscan.com/api?module=gastracker

# Price oracle for USD conversion
PRICE_ORACLE=https://api.coingecko.com/api/v3/simple/price

# Database configuration
DATABASE_URL=postgresql://user:pass@localhost/gasguard

# Redis for caching
REDIS_URL=redis://localhost:6379
```

### Service Configuration

```typescript
// In your app.module.ts
import { FailedTransactionModule } from './modules/failed-transaction.module';

@Module({
  imports: [
    FailedTransactionModule.forRoot({
      gasOracleEndpoints: {
        1: 'https://api.etherscan.io/api?module=gastracker',
        137: 'https://api.polygonscan.com/api?module=gastracker'
      },
      priceOracleUrl: 'https://api.coingecko.com/api/v3/simple/price',
      cacheEnabled: true,
      cacheTtl: 300 // 5 minutes
    })
  ]
})
export class AppModule {}
```

## Performance Considerations

### Caching
- Gas price data cached for 5 minutes
- Price data cached for 1 minute
- Analysis results cached for 15 minutes

### Rate Limiting
- 10 requests per minute per IP
- Burst capacity of 20 requests
- Automatic backoff for exceeded limits

### Database Optimization
- Indexed by wallet address
- Partitioned by timestamp
- Compressed historical data

## Testing

### Unit Tests
```bash
npm run test
```

### Integration Tests
```bash
npm run test:e2e
```

### Coverage
```bash
npm run test:cov
```

## Monitoring

### Metrics
- Transaction failure rate by chain
- Average gas waste per failure
- Recommendation effectiveness
- API response times

### Alerts
- High failure rate (>10% in 1 hour)
- Unusual gas waste patterns
- API performance degradation

## Security

### Data Protection
- Wallet addresses hashed for privacy
- Sensitive data encrypted at rest
- API access rate limited

### Validation
- Input sanitization
- Address format validation
- Chain ID verification

## Troubleshooting

### Common Issues

1. **Missing Dependencies**
   ```bash
   npm install
   ```

2. **Database Connection Issues**
   ```bash
   # Check DATABASE_URL
   echo $DATABASE_URL
   ```

3. **Gas Oracle Failures**
   ```bash
   # Test gas oracle endpoint
   curl https://api.etherscan.io/api?module=gastracker
   ```

### Debug Mode
```bash
# Enable debug logging
DEBUG=failed-transactions npm run start:dev
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see LICENSE file for details.
