<?php

declare(strict_types=1);

namespace Ph20sr\ApiKeys;

use PDO;

/**
 *     $keys = new ApiKeys($pdo, new KeyFormat('vx_live'), pepper: getenv('API_KEY_PEPPER'));
 *     ['key' => $plain] = $keys->create($userId, 'Integração ERP', ['invoices:read']);   // mostre UMA vez
 *     $check = $keys->verify($bearerToken, 'invoices:read');
 */
final class ApiKeys
{
    private const DATE = 'Y-m-d H:i:s';
    /** Grava last_used_at no máximo uma vez por minuto (evita escrita a cada requisição). */
    private const TOUCH_INTERVAL = 60;

    /** @var \Closure(): \DateTimeImmutable */
    private \Closure $clock;

    /**
     * @param string|null $pepper segredo do servidor misturado ao hash (HMAC):
     *                            quem copia só o banco não consegue testar chaves offline
     */
    public function __construct(
        private readonly PDO $pdo,
        private readonly KeyFormat $format = new KeyFormat(),
        #[\SensitiveParameter] private readonly ?string $pepper = null,
        private readonly string $table = 'api_keys',
        ?callable $clock = null,
    ) {
        if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $table)) {
            throw new \InvalidArgumentException("Nome de tabela inválido: {$table}");
        }
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->clock = $clock !== null
            ? \Closure::fromCallable($clock)
            : static fn (): \DateTimeImmutable => new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
    }

    public function install(): void
    {
        $this->pdo->exec("CREATE TABLE IF NOT EXISTS {$this->table} (
            id CHAR(12) NOT NULL PRIMARY KEY,
            owner_id VARCHAR(64) NOT NULL,
            name VARCHAR(120) NOT NULL,
            scopes TEXT NOT NULL,
            secret_hash CHAR(64) NOT NULL,
            created_at DATETIME NOT NULL,
            expires_at DATETIME NULL,
            revoked_at DATETIME NULL,
            last_used_at DATETIME NULL
        )");
    }

    /**
     * Cria uma chave. O texto em `key` só existe agora: mostre ao usuário uma
     * única vez, porque depois não há como recuperá-lo (só o hash fica salvo).
     *
     * @param list<string> $scopes
     * @return array{key: string, apiKey: ApiKey}
     */
    public function create(string $ownerId, string $name, array $scopes = [], ?\DateTimeImmutable $expiresAt = null): array
    {
        $id = KeyFormat::random(KeyFormat::ID_LENGTH);
        $secret = KeyFormat::random(KeyFormat::SECRET_LENGTH);
        $now = ($this->clock)();

        $this->pdo->prepare(
            "INSERT INTO {$this->table} (id, owner_id, name, scopes, secret_hash, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )->execute([
            $id, $ownerId, $name, json_encode(array_values($scopes)), $this->hash($secret),
            $now->format(self::DATE), $expiresAt?->format(self::DATE),
        ]);

        return ['key' => $this->format->build($id, $secret), 'apiKey' => $this->find($id)];
    }

    /** Verifica uma chave recebida (ex.: "Authorization: Bearer ..."). */
    public function verify(string $key, ?string $requiredScope = null): Verification
    {
        $parsed = $this->format->parse($key);
        if ($parsed === null) {
            return new Verification(false, reason: Verification::MALFORMED);
        }

        $stmt = $this->pdo->prepare("SELECT * FROM {$this->table} WHERE id = ?");
        $stmt->execute([$parsed['id']]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        // Calcula o hash mesmo sem a linha: o tempo de resposta não revela se o id existe
        $hash = $this->hash($parsed['secret']);
        if (!$row) {
            return new Verification(false, reason: Verification::NOT_FOUND);
        }
        if (!hash_equals((string) $row['secret_hash'], $hash)) {
            return new Verification(false, reason: Verification::WRONG_SECRET);
        }

        $apiKey = $this->hydrate($row);
        $now = ($this->clock)();
        if ($apiKey->revokedAt !== null) {
            return new Verification(false, $apiKey, Verification::REVOKED);
        }
        if ($apiKey->expiresAt !== null && $apiKey->expiresAt <= $now) {
            return new Verification(false, $apiKey, Verification::EXPIRED);
        }
        if ($requiredScope !== null && !$apiKey->can($requiredScope)) {
            return new Verification(false, $apiKey, Verification::MISSING_SCOPE);
        }

        if ($apiKey->lastUsedAt === null || $now->getTimestamp() - $apiKey->lastUsedAt->getTimestamp() >= self::TOUCH_INTERVAL) {
            $this->pdo->prepare("UPDATE {$this->table} SET last_used_at = ? WHERE id = ?")->execute([$now->format(self::DATE), $apiKey->id]);
        }
        return new Verification(true, $apiKey);
    }

    public function revoke(string $id): bool
    {
        $stmt = $this->pdo->prepare("UPDATE {$this->table} SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL");
        $stmt->execute([($this->clock)()->format(self::DATE), $id]);
        return $stmt->rowCount() > 0;
    }

    /**
     * Gera uma chave nova com o mesmo dono, nome e escopos. A antiga continua
     * valendo por `graceSeconds` para dar tempo de trocar nos sistemas que a
     * usam (rotação sem derrubar a integração).
     *
     * @return array{key: string, apiKey: ApiKey}
     */
    public function rotate(string $id, int $graceSeconds = 86400): array
    {
        $old = $this->find($id) ?? throw new \InvalidArgumentException("Chave {$id} não encontrada");
        if ($old->revokedAt !== null) {
            throw new \LogicException('Não é possível rotacionar uma chave revogada');
        }
        $new = $this->create($old->ownerId, $old->name, $old->scopes, $old->expiresAt);
        $graceEnd = ($this->clock)()->modify("+{$graceSeconds} seconds");
        if ($old->expiresAt === null || $old->expiresAt > $graceEnd) {
            $this->pdo->prepare("UPDATE {$this->table} SET expires_at = ? WHERE id = ?")->execute([$graceEnd->format(self::DATE), $id]);
        }
        return $new;
    }

    public function find(string $id): ?ApiKey
    {
        $stmt = $this->pdo->prepare("SELECT * FROM {$this->table} WHERE id = ?");
        $stmt->execute([$id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ? $this->hydrate($row) : null;
    }

    /** @return list<ApiKey> chaves do dono, mais recentes primeiro */
    public function list(string $ownerId): array
    {
        $stmt = $this->pdo->prepare("SELECT * FROM {$this->table} WHERE owner_id = ? ORDER BY created_at DESC, id");
        $stmt->execute([$ownerId]);
        return array_map($this->hydrate(...), $stmt->fetchAll(PDO::FETCH_ASSOC));
    }

    private function hash(string $secret): string
    {
        return $this->pepper !== null ? hash_hmac('sha256', $secret, $this->pepper) : hash('sha256', $secret);
    }

    /** @param array<string, mixed> $row */
    private function hydrate(array $row): ApiKey
    {
        $date = static fn ($v) => $v === null ? null : new \DateTimeImmutable((string) $v, new \DateTimeZone('UTC'));
        return new ApiKey(
            (string) $row['id'],
            (string) $row['owner_id'],
            (string) $row['name'],
            json_decode((string) $row['scopes'], true) ?: [],
            $date($row['created_at']),
            $date($row['expires_at']),
            $date($row['revoked_at']),
            $date($row['last_used_at']),
        );
    }
}
