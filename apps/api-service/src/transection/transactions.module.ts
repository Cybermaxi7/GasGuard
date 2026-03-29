import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Transaction } from './transaction.entity';
import { TransactionsService } from './transactions.service';
import { TransactionsController } from './transactions.controller';
import { RateLimitService } from './rate-limit.service';
import { SuspiciousActivityService } from './suspicious-activity.service';

@Module({
  imports: [TypeOrmModule.forFeature([Transaction])],
  providers: [TransactionsService, RateLimitService, SuspiciousActivityService],
  controllers: [TransactionsController],
  exports: [TransactionsService, RateLimitService, SuspiciousActivityService],
})
export class TransactionsModule {}