<?php

declare(strict_types=1);

namespace Ph20sr\ApiKeys;

/**
 * Resultado da verificação. O motivo é para LOG; para o cliente, responda
 * sempre um 401 genérico (detalhar ajudaria quem está tentando adivinhar).
 */
final class Verification
{
    public const MALFORMED = 'malformed';       // formato ou checksum inválido
    public const NOT_FOUND = 'not_found';
    public const WRONG_SECRET = 'wrong_secret';
    public const REVOKED = 'revoked';
    public const EXPIRED = 'expired';
    public const MISSING_SCOPE = 'missing_scope'; // chave válida, mas sem permissão (→ 403)

    public function __construct(
        public readonly bool $valid,
        public readonly ?ApiKey $key = null,
        public readonly ?string $reason = null,
    ) {
    }

    /** Status HTTP adequado: 200, 401 ou 403. */
    public function httpStatus(): int
    {
        return $this->valid ? 200 : ($this->reason === self::MISSING_SCOPE ? 403 : 401);
    }
}
