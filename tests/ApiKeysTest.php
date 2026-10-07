<?php

declare(strict_types=1);

namespace Ph20sr\ApiKeys\Tests;

use PDO;
use Ph20sr\ApiKeys\ApiKeys;
use Ph20sr\ApiKeys\KeyFormat;
use Ph20sr\ApiKeys\Verification;
use PHPUnit\Framework\TestCase;

final class ApiKeysTest extends TestCase
{
    private PDO $pdo;
    private ApiKeys $keys;
    private \DateTimeImmutable $now;

    protected function setUp(): void
    {
        $this->now = new \DateTimeImmutable('2026-10-07 12:00:00', new \DateTimeZone('UTC'));
        $this->pdo = new PDO('sqlite::memory:');
        $this->keys = new ApiKeys($this->pdo, new KeyFormat('vx_test'), pepper: 'pepper-do-servidor', clock: fn () => $this->now);
        $this->keys->install();
    }

    public function testFormatChecksumAndMask(): void
    {
        $format = new KeyFormat('vx_test');
        $key = $format->build(str_repeat('a', 12), str_repeat('b', 32));
        $this->assertSame(8 + 12 + 32 + 6, strlen($key));
        $this->assertSame(['id' => str_repeat('a', 12), 'secret' => str_repeat('b', 32)], $format->parse($key));

        // Um caractere trocado é detectado pelo checksum, sem ir ao banco
        $typo = substr_replace($key, 'c', 20, 1);
        $this->assertNull($format->parse($typo));
        $this->assertNull($format->parse('vx_live_' . substr($key, 8)), 'prefixo de outro ambiente');

        $this->assertSame('vx_test_aaaaaaaaaaaa…' . substr($key, -4), $format->mask($key));
        $this->assertSame(1, preg_match($format->scanPattern(), "log: token={$key} fim"));
    }

    public function testRandomIsBase62(): void
    {
        $r = KeyFormat::random(1000);
        $this->assertSame(1000, strlen($r));
        $this->assertSame(1, preg_match('/^[0-9A-Za-z]+$/', $r));
        $this->assertTrue(count(array_unique(str_split($r))) > 50, 'usa praticamente todo o alfabeto');
    }

    public function testCreateStoresOnlyTheHash(): void
    {
        ['key' => $plain, 'apiKey' => $apiKey] = $this->keys->create('user:7', 'Integração ERP', ['invoices:read']);

        $stored = $this->pdo->query('SELECT * FROM api_keys')->fetch(PDO::FETCH_ASSOC);
        $this->assertStringNotContainsString(substr($plain, 20, 32), json_encode($stored), 'segredo não fica no banco');
        $this->assertSame(64, strlen($stored['secret_hash']));
        $this->assertSame($apiKey->id, $stored['id']);
        $this->assertSame(['invoices:read'], $apiKey->scopes);
    }

    public function testVerifyValidKeyAndScopes(): void
    {
        ['key' => $plain] = $this->keys->create('user:7', 'ERP', ['invoices:*', 'customers:read']);

        $ok = $this->keys->verify("  {$plain} ", 'invoices:write');
        $this->assertTrue($ok->valid);
        $this->assertSame('user:7', $ok->key->ownerId);
        $this->assertSame(200, $ok->httpStatus());

        $denied = $this->keys->verify($plain, 'customers:delete');
        $this->assertFalse($denied->valid);
        $this->assertSame(Verification::MISSING_SCOPE, $denied->reason);
        $this->assertSame(403, $denied->httpStatus());
    }

    public function testRejectionReasons(): void
    {
        ['key' => $plain, 'apiKey' => $apiKey] = $this->keys->create('user:7', 'ERP');

        $this->assertSame(Verification::MALFORMED, $this->keys->verify('qualquer coisa')->reason);

        // Mesmo id, outro segredo (com checksum válido): segredo errado
        $format = new KeyFormat('vx_test');
        $forged = $format->build($apiKey->id, str_repeat('Z', 32));
        $this->assertSame(Verification::WRONG_SECRET, $this->keys->verify($forged)->reason);
        $this->assertSame(Verification::NOT_FOUND, $this->keys->verify($format->build('nao0existe00', str_repeat('Z', 32)))->reason);

        // A mesma chave com outro "pepper" não confere
        $otherServer = new ApiKeys($this->pdo, $format, pepper: 'outro', clock: fn () => $this->now);
        $this->assertSame(Verification::WRONG_SECRET, $otherServer->verify($plain)->reason);
        $this->assertSame(401, $otherServer->verify($plain)->httpStatus());
    }

    public function testRevokeAndExpire(): void
    {
        ['key' => $a, 'apiKey' => $ka] = $this->keys->create('user:7', 'A');
        ['key' => $b] = $this->keys->create('user:7', 'B', [], $this->now->modify('+1 hour'));

        $this->assertTrue($this->keys->revoke($ka->id));
        $this->assertFalse($this->keys->revoke($ka->id), 'já revogada');
        $this->assertSame(Verification::REVOKED, $this->keys->verify($a)->reason);

        $this->assertTrue($this->keys->verify($b)->valid);
        $this->now = $this->now->modify('+2 hours');
        $this->assertSame(Verification::EXPIRED, $this->keys->verify($b)->reason);
    }

    public function testRotationKeepsOldKeyDuringGracePeriod(): void
    {
        ['key' => $old, 'apiKey' => $k] = $this->keys->create('user:7', 'ERP', ['invoices:read']);
        ['key' => $new, 'apiKey' => $k2] = $this->keys->rotate($k->id, graceSeconds: 3600);

        $this->assertNotSame($k->id, $k2->id);
        $this->assertSame(['invoices:read'], $k2->scopes);
        $this->assertTrue($this->keys->verify($old)->valid, 'antiga ainda vale');
        $this->assertTrue($this->keys->verify($new)->valid);

        $this->now = $this->now->modify('+61 minutes');
        $this->assertSame(Verification::EXPIRED, $this->keys->verify($old)->reason);
        $this->assertTrue($this->keys->verify($new)->valid);
    }

    public function testLastUsedIsThrottled(): void
    {
        ['key' => $plain, 'apiKey' => $k] = $this->keys->create('user:7', 'ERP');
        $this->keys->verify($plain);
        $this->assertSame('2026-10-07 12:00:00', $this->keys->find($k->id)->lastUsedAt->format('Y-m-d H:i:s'));

        $this->now = $this->now->modify('+30 seconds');
        $this->keys->verify($plain);
        $this->assertSame('2026-10-07 12:00:00', $this->keys->find($k->id)->lastUsedAt->format('Y-m-d H:i:s'), 'não grava de novo em menos de 1 min');

        $this->now = $this->now->modify('+31 seconds');
        $this->keys->verify($plain);
        $this->assertSame('2026-10-07 12:01:01', $this->keys->find($k->id)->lastUsedAt->format('Y-m-d H:i:s'));
    }

    public function testListByOwner(): void
    {
        $this->keys->create('user:7', 'A');
        $this->keys->create('user:7', 'B');
        $this->keys->create('user:9', 'C');
        $this->assertCount(2, $this->keys->list('user:7'));
        $this->assertSame('C', $this->keys->list('user:9')[0]->name);
    }

    public function testRejectsBadPrefix(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new KeyFormat('VX-Live');
    }
}
