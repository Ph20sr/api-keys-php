<?php

declare(strict_types=1);

namespace Ph20sr\ApiKeys;

/**
 * Formato: <prefixo>_<id público: 12><segredo: 32><checksum: 6>
 * ex.: vx_live_3kTq9ZcW1mPa8fJ2nX0bR7yLsD4vH6gQ1tE5uK9wC0zA2oB
 *
 * - O prefixo identifica a origem (útil para secret scanning e para o
 *   usuário saber o que é aquilo colado num log).
 * - O id público localiza a chave no banco sem expor o segredo.
 * - O checksum (CRC32) detecta erro de digitação ou cópia sem ir ao banco.
 */
final class KeyFormat
{
    public const ID_LENGTH = 12;
    public const SECRET_LENGTH = 32;
    public const CHECKSUM_LENGTH = 6;
    private const ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

    public function __construct(public readonly string $prefix = 'vx_live')
    {
        if (!preg_match('/^[a-z][a-z0-9]*(_[a-z0-9]+)*$/', $prefix)) {
            throw new \InvalidArgumentException("Prefixo inválido: {$prefix} (use minúsculas, números e _)");
        }
    }

    /** Texto base62 aleatório, sem viés de módulo (amostragem por rejeição). */
    public static function random(int $length): string
    {
        $out = '';
        while (strlen($out) < $length) {
            foreach (str_split(random_bytes($length * 2)) as $byte) {
                $b = ord($byte);
                if ($b < 248) { // 248 = 62 * 4: descarta o resto para não favorecer caracteres
                    $out .= self::ALPHABET[$b % 62];
                    if (strlen($out) === $length) {
                        break;
                    }
                }
            }
        }
        return $out;
    }

    public static function base62(int $n, int $length): string
    {
        $out = '';
        do {
            $out = self::ALPHABET[$n % 62] . $out;
            $n = intdiv($n, 62);
        } while ($n > 0);
        return str_pad($out, $length, '0', STR_PAD_LEFT);
    }

    public function checksum(string $id, string $secret): string
    {
        return self::base62(crc32("{$this->prefix}_{$id}{$secret}"), self::CHECKSUM_LENGTH);
    }

    public function build(string $id, string $secret): string
    {
        return "{$this->prefix}_{$id}{$secret}" . $this->checksum($id, $secret);
    }

    /**
     * Separa a chave em id e segredo. null se o formato ou o checksum não
     * conferem (nem vale a pena consultar o banco).
     *
     * @return array{id: string, secret: string}|null
     */
    public function parse(string $key): ?array
    {
        $key = trim($key);
        $body = self::ID_LENGTH + self::SECRET_LENGTH + self::CHECKSUM_LENGTH;
        if (!preg_match('/^' . preg_quote($this->prefix, '/') . '_([0-9A-Za-z]{' . $body . '})$/', $key, $m)) {
            return null;
        }
        $id = substr($m[1], 0, self::ID_LENGTH);
        $secret = substr($m[1], self::ID_LENGTH, self::SECRET_LENGTH);
        $checksum = substr($m[1], -self::CHECKSUM_LENGTH);
        return hash_equals($this->checksum($id, $secret), $checksum) ? ['id' => $id, 'secret' => $secret] : null;
    }

    /** Versão segura para exibir: vx_live_3kTq9ZcW…wC0zA2oB */
    public function mask(string $key): string
    {
        $parsed = $this->parse($key);
        return $parsed ? "{$this->prefix}_{$parsed['id']}…" . substr($key, -4) : '(chave inválida)';
    }

    /** Expressão para encontrar chaves vazadas em código, logs e tickets. */
    public function scanPattern(): string
    {
        return '/\b' . preg_quote($this->prefix, '/') . '_[0-9A-Za-z]{' . (self::ID_LENGTH + self::SECRET_LENGTH + self::CHECKSUM_LENGTH) . '}\b/';
    }
}
