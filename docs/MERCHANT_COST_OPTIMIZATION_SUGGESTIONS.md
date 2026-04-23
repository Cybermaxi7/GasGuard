# Merchant Cost Optimization Suggestions

## Overview

The Merchant Cost Optimization Suggestions feature provides automated, data-driven recommendations to help merchants reduce their gas costs while maintaining performance. The system analyzes historical gas usage and transaction patterns to identify inefficiencies and generate actionable suggestions.

## Features

### 1. Data Analysis
- Aggregates merchant transaction data:
  - Gas used per transaction
  - Gas price paid
  - Chain selection and frequency
  - Transaction success/failure rates
- Identifies patterns such as:
  - Overpaying for priority gas
  - Frequent failed transactions causing wasted gas
  - Suboptimal chain selection

### 2. Optimization Engine
- Generates automated suggestions:
  - Switch to lower-cost chains when feasible
  - Adjust transaction timing based on gas volatility
  - Optimize batch or contract function execution
- Ranks suggestions by potential savings or impact
- Includes estimated gas and USD savings

### 3. API Access
- GET `/merchant/:merchantId/cost-optimization` - Retrieve optimization suggestions
- GET `/merchant/:merchantId/cost-optimization/summary` - Get optimization summary
- GET `/merchant/:merchantId/cost-optimization/history` - Get suggestions history

## Architecture

### Core Components

#### Entities
- `OptimizationSuggestion` - Stores recommendation data with metadata

#### Services
- `DataAnalysisService` - Aggregates and analyzes merchant transaction data
- `OptimizationEngineService` - Generates actionable recommendations

#### Controllers
- `CostOptimizationController` - Provides REST API endpoints

## Usage

### Getting Optimization Suggestions

Retrieve optimization suggestions for a merchant:

```bash
curl -X GET "http://localhost:3000/merchant/merchant-123/cost-optimization"
```

With custom parameters:

```bash
curl -X GET "http://localhost:3000/merchant/merchant-123/cost-optimization?days=60&status=pending"
```

### Response Format

```json
{
  "merchantId": "merchant-123",
  "suggestions": [
    {
      "type": "ChainSwitch",
      "description": "Switch 25% of transfers from Ethereum to Polygon to reduce gas costs",
      "estimatedSavingsUSD": 125,
      "priority": 4,
      "category": "gas",
      "metadata": {
        "fromChain": "ethereum",
        "toChain": "polygon",
        "transactionCount": 150,
        "percentageOfTotal": 25
      }
    },
    {
      "type": "TimingAdjustment",
      "description": "Schedule contract interactions during low gas periods (UTC 02:00–04:00)",
      "estimatedSavingsUSD": 80,
      "priority": 3,
      "category": "gas",
      "metadata": {
        "optimalHour": 2,
        "worstHour": 15,
        "avgGasPriceLow": 10,
        "avgGasPriceHigh": 40
      }
    }
  ],
  "summary": {
    "totalPotentialSavingsUSD": 205,
    "totalSuggestions": 5,
    "highPrioritySuggestions": 2,
    "appliedSuggestions": 1
  }
}
```

### Getting Optimization Summary

Get a summary of optimization opportunities:

```bash
curl -X GET "http://localhost:3000/merchant/merchant-123/cost-optimization/summary"
```

### Getting Suggestions History

Get historical suggestions with status tracking:

```bash
curl -X GET "http://localhost:3000/merchant/merchant-123/cost-optimization/history?status=pending&limit=10"
```

## Suggestion Types

### ChainSwitch
- Recommends switching from high-cost to low-cost chains
- Calculates potential savings based on transaction volume
- Considers success rates on alternative chains

### TimingAdjustment
- Identifies optimal times for transaction submission
- Based on historical gas price patterns
- Helps avoid peak gas price periods

### BatchOptimization
- Suggests batching multiple transactions
- Reduces overhead costs
- Particularly beneficial for high-frequency traders

### FailedTransactionReduction
- Identifies causes of transaction failures
- Estimates gas wasted on failed transactions
- Provides recommendations to improve success rates

### GasPriceOptimization
- Monitors gas price volatility
- Suggests strategies for dynamic fee management
- Recommends gas price prediction tools

## Data Analysis Methodology

### Chain Cost Comparison
- Compares average transaction costs across different chains
- Factors in success rates and network reliability
- Calculates potential savings from chain switching

### Time-Based Patterns
- Analyzes gas price fluctuations throughout the day
- Identifies optimal transaction submission windows
- Considers historical volatility patterns

### Failure Analysis
- Calculates cost of failed transactions
- Identifies common failure patterns
- Estimates potential savings from reduced failures

## Priority Scoring

Suggestions are scored on a 1-5 scale:
- 1: Low priority, minor impact
- 2: Medium-low priority, modest savings
- 3: Medium priority, reasonable savings
- 4: High priority, significant savings
- 5: Critical priority, major savings or risk reduction

## Integration

The optimization suggestions can be integrated into:
- Merchant dashboards
- Automated trading systems
- Cost management tools
- Reporting systems

## Security

- Suggestions are merchant-specific
- All data access follows standard authentication protocols
- Sensitive financial data is protected according to security standards

## Testing

Unit tests cover:
- Data analysis accuracy
- Suggestion generation algorithms
- API endpoint functionality
- Edge case handling

Run tests with:
```bash
npm run test
```

## Performance

- Efficient database queries with proper indexing
- Caching for frequently accessed data
- Asynchronous processing for heavy computations
- Pagination for large datasets

The Merchant Cost Optimization Suggestions feature provides merchants with actionable insights to reduce their gas expenses while maintaining operational efficiency.