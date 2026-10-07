<?php

declare(strict_types=1);

namespace Ph20sr\ApiKeys;

/** Metadados de uma chave (nunca contém o segredo). */
final class ApiKey
{
    /** @param list<string> $scopes */
    public function __construct(
        public readonly string $id,
        public readonly string $ownerId,
        public readonly string $name,
        public readonly array $scopes,
        public readonly \DateTimeImmutable $createdAt,
        public readonly ?\DateTimeImmutable $expiresAt,
        public readonly ?\DateTimeImmutable $revokedAt,
        public readonly ?\DateTimeImmutable $lastUsedAt,
    ) {
    }

    /**
     * "invoices:read" é atendido por "invoices:read", "invoices:*" ou "*".
     */
    public function can(string $scope): bool
    {
        foreach ($this->scopes as $granted) {
            if ($granted === '*' || $granted === $scope) {
                return true;
            }
            if (str_ends_with($granted, ':*') && str_starts_with($scope, substr($granted, 0, -1))) {
                return true;
            }
        }
        return false;
    }

    public function isActive(\DateTimeImmutable $now): bool
    {
        return $this->revokedAt === null && ($this->expiresAt === null || $this->expiresAt > $now);
    }
}
