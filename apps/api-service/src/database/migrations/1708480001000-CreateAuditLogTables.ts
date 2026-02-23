import { MigrationInterface, QueryRunner, Table, TableIndex } from 'typeorm';

export class CreateAuditLogTables1708480001000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // Create audit_logs table
    await queryRunner.createTable(
      new Table({
        name: 'audit_logs',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'gen_random_uuid()',
          },
          {
            name: 'eventType',
            type: 'enum',
            enum: ['APIRequest', 'KeyCreated', 'KeyRotated', 'KeyRevoked', 'GasTransaction', 'GasSubmission'],
          },
          {
            name: 'timestamp',
            type: 'timestamp',
          },
          {
            name: 'user',
            type: 'varchar',
            length: '255',
            isNullable: true,
          },
          {
            name: 'apiKey',
            type: 'varchar',
            length: '255',
            isNullable: true,
          },
          {
            name: 'chainId',
            type: 'integer',
            isNullable: true,
          },
          {
            name: 'details',
            type: 'jsonb',
          },
          {
            name: 'outcome',
            type: 'enum',
            enum: ['success', 'failure', 'warning'],
          },
          {
            name: 'endpoint',
            type: 'varchar',
            length: '255',
            isNullable: true,
          },
          {
            name: 'httpMethod',
            type: 'varchar',
            length: '10',
            isNullable: true,
          },
          {
            name: 'responseStatus',
            type: 'integer',
            isNullable: true,
          },
          {
            name: 'ipAddress',
            type: 'varchar',
            length: '255',
            isNullable: true,
          },
          {
            name: 'errorMessage',
            type: 'text',
            isNullable: true,
          },
          {
            name: 'responseDuration',
            type: 'bigint',
            isNullable: true,
          },
          {
            name: 'integrity',
            type: 'varchar',
            length: '64',
            isNullable: true,
          },
          {
            name: 'createdAt',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP',
          },
        ],
      }),
      true,
    );

    // Create indexes for efficient queries
    await queryRunner.createIndex(
      'audit_logs',
      new TableIndex({
        name: 'idx_audit_event_type',
        columnNames: ['eventType'],
      }),
    );

    await queryRunner.createIndex(
      'audit_logs',
      new TableIndex({
        name: 'idx_audit_user',
        columnNames: ['user'],
      }),
    );

    await queryRunner.createIndex(
      'audit_logs',
      new TableIndex({
        name: 'idx_audit_timestamp',
        columnNames: ['timestamp'],
      }),
    );

    await queryRunner.createIndex(
      'audit_logs',
      new TableIndex({
        name: 'idx_audit_chain_id',
        columnNames: ['chainId'],
      }),
    );

    await queryRunner.createIndex(
      'audit_logs',
      new TableIndex({
        name: 'idx_audit_composite',
        columnNames: ['eventType', 'user', 'timestamp'],
      }),
    );

    // Create api_keys table
    await queryRunner.createTable(
      new Table({
        name: 'api_keys',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            default: 'gen_random_uuid()',
          },
          {
            name: 'merchantId',
            type: 'varchar',
            length: '100',
          },
          {
            name: 'name',
            type: 'varchar',
            length: '255',
          },
          {
            name: 'keyHash',
            type: 'varchar',
            length: '255',
          },
          {
            name: 'status',
            type: 'enum',
            enum: ['active', 'rotated', 'revoked', 'expired'],
            default: "'active'",
          },
          {
            name: 'lastUsedAt',
            type: 'timestamp',
            isNullable: true,
          },
          {
            name: 'requestCount',
            type: 'integer',
            default: 0,
          },
          {
            name: 'expiresAt',
            type: 'timestamp',
            isNullable: true,
          },
          {
            name: 'description',
            type: 'text',
            isNullable: true,
          },
          {
            name: 'role',
            type: 'varchar',
            length: '50',
            default: "'user'",
          },
          {
            name: 'metadata',
            type: 'jsonb',
            isNullable: true,
          },
          {
            name: 'rotatedFromId',
            type: 'uuid',
            isNullable: true,
          },
          {
            name: 'createdAt',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP',
          },
          {
            name: 'updatedAt',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP',
            onUpdate: 'CURRENT_TIMESTAMP',
          },
        ],
      }),
      true,
    );

    // Create indexes for api_keys
    await queryRunner.createIndex(
      'api_keys',
      new TableIndex({
        name: 'idx_apikey_hash',
        columnNames: ['keyHash'],
      }),
    );

    await queryRunner.createIndex(
      'api_keys',
      new TableIndex({
        name: 'idx_apikey_merchant',
        columnNames: ['merchantId'],
      }),
    );

    await queryRunner.createIndex(
      'api_keys',
      new TableIndex({
        name: 'idx_apikey_status',
        columnNames: ['status'],
      }),
    );

    await queryRunner.createIndex(
      'api_keys',
      new TableIndex({
        name: 'idx_apikey_created',
        columnNames: ['createdAt'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('api_keys');
    await queryRunner.dropTable('audit_logs');
  }
}
