# Local development infra

Bring it up:

```bash
docker compose -f docker/docker-compose.dev.yml up -d
```

Services exposed:

| Service     | Host port | Notes                              |
| ----------- | --------- | ---------------------------------- |
| Postgres    | 5432      | user `nexus`, password `nexus_dev` |
| TimescaleDB | 5433      | episodic memory                    |
| Neo4j       | 7474/7687 | password `nexus_dev_password`      |
| NATS        | 4222      | with JetStream enabled             |
| Redis       | 6379      |                                    |
| LocalStack  | 4566      | AWS services for testing           |

Tear down:

```bash
docker compose -f docker/docker-compose.dev.yml down -v
```

State persists in `docker/.data/`. Add to `.gitignore` (already done).
