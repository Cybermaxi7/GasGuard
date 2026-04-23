# Scheduled Gas Report Generator

## Overview

The Scheduled Gas Report Generator is a comprehensive system that automatically aggregates gas usage data for merchants and generates periodic reports. The system supports both scheduled (weekly/monthly) and ad-hoc report generation with automated email delivery.

## Features

### 1. Data Aggregation
- Collects gas usage data per merchant
- Calculates gas cost in ETH/native token and USD equivalent
- Provides chain-specific usage breakdown
- Tracks transaction counts and success metrics

### 2. Report Generation
- Generates reports in multiple formats (CSV, HTML)
- Supports weekly and monthly reporting periods
- Highlights abnormal or peak usage patterns
- Includes merchant details and chain-wise breakdown

### 3. Email Automation
- Sends scheduled reports automatically
- Weekly: every Monday at 08:00 UTC
- Monthly: first day of the month at 08:00 UTC
- Handles failed email deliveries with retry mechanism
- Configurable recipients per merchant

### 4. API Access
- POST `/reports/gas` - Trigger ad-hoc report generation
- GET `/reports/gas/status/:reportId` - Check report status
- GET `/reports/gas/history` - Get report history
- GET `/reports/gas/download/:reportId` - Download generated report

## Architecture

### Core Components

#### Entities
- `Report` - Stores report metadata, status, and file paths

#### Services
- `DataAggregationService` - Collects and processes gas usage data
- `ReportGenerationService` - Creates reports in various formats
- `EmailNotificationService` - Handles email delivery
- `SchedulingService` - Manages cron jobs for automatic reports
- `ReportService` - Orchestrates the entire report generation process

#### Controllers
- `ReportController` - Provides REST API endpoints

## Configuration

### Environment Variables

```env
# SMTP Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_SECURE=false
SMTP_FROM_EMAIL=noreply@gasguard.com

# Database Configuration (inherited from main app)
DATABASE_URL=postgresql://user:password@localhost:5432/gasguard
```

### Scheduling Configuration

The system uses `@nestjs/schedule` for cron jobs:
- Weekly reports: Run every Monday at 08:00 UTC
- Monthly reports: Run on the first day of each month at 08:00 UTC
- Pending report processor: Runs every 30 minutes as a fallback

## Usage

### Ad-hoc Report Generation

Trigger a one-time report:

```bash
curl -X POST "http://localhost:3000/reports/gas?merchantId=merchant-123&period=weekly"
```

### Check Report Status

```bash
curl -X GET "http://localhost:3000/reports/gas/status/report-456"
```

### Get Report History

```bash
curl -X GET "http://localhost:3000/reports/gas/history?merchantId=merchant-123&period=weekly&limit=5"
```

## Data Aggregation Methodology

### Weekly Reports
- Data collected from the previous Monday to Sunday
- Includes total gas consumed, cost in USD, chain breakdown, and success metrics
- Compares with the previous week to detect anomalies

### Monthly Reports
- Data collected from the first to the last day of the previous month
- Similar metrics as weekly reports but for a monthly period
- Compares with the previous month to detect anomalies

### Anomaly Detection
- Identifies significant increases in gas consumption (>50%)
- Detects changes in transaction success rates (>10% difference)

## Report Formats

### CSV Format
- Contains detailed breakdown by chain
- Columns: Merchant ID, Name, Chain ID, Name, Gas Used, Cost (USD), Transaction Count, Success Rate

### HTML Format
- Formatted summary with tables and styling
- Includes visual indicators for anomalies
- Downloadable as attachment in email

## Email Templates

The system uses professional email templates with:
- Clear subject lines indicating report type and merchant
- Summary of key metrics
- Direct links to download reports
- Professional branding

## Error Handling

### Retry Mechanism
- Failed reports are marked as 'failed' status
- System attempts to retry failed reports periodically
- Failure notifications sent to merchants

### Logging
- All report generation and email events are logged
- Audit trail maintained for compliance
- Error details captured for debugging

## Testing

Unit tests cover:
- Report generation correctness
- Email delivery success/failure scenarios
- API endpoint functionality
- Data aggregation accuracy

Run tests with:
```bash
npm run test
```

## Security

- Reports are generated with secure file paths
- Access to reports requires valid report IDs
- Email content is sanitized to prevent injection attacks
- Authentication can be added to API endpoints as needed

## Monitoring

Key metrics tracked:
- Report generation success/failure rates
- Email delivery success rates
- Processing time for different report types
- System resource utilization during report generation

## Deployment

### Prerequisites
- Node.js 18+
- PostgreSQL database
- SMTP server access
- Cron capability for scheduling

### Installation
1. Install dependencies: `npm install`
2. Configure environment variables
3. Run database migrations
4. Start the application: `npm run start`

The system will automatically begin processing scheduled reports based on the configured cron schedules.