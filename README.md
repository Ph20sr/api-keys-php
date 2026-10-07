# api-keys-php

[![CI](https://github.com/Ph20sr/api-keys-php/actions/workflows/ci.yml/badge.svg)](https://github.com/Ph20sr/api-keys-php/actions/workflows/ci.yml)
![PHP](https://img.shields.io/badge/php-%3E%3D8.1-777bb4)
![license](https://img.shields.io/badge/license-MIT-blue)

Chaves de API para o seu sistema PHP, no padrão de GitHub e Stripe: quando o cliente integra o ERP, o site ou o n8n com a sua plataforma, cada integração recebe uma chave própria, com permissões, que pode ser revogada sem afetar as outras.

```
vx_live_3kTq9ZcW1mPa8fJ2nX0bR7yLsD4vH6gQ1tE5uK9wC0zA2oB
└──┬──┘ └────┬─────┘└──────────────┬───────────────┘└─┬──┘
 prefixo  id público          segredo              checksum
```

## Segurança

| risco | proteção |
| --- | --- |
| banco de dados vaza | só o **hash** do segredo é guardado (HMAC-SHA256 com *pepper* do servidor) |
| alguém testa chaves no seu endpoint | o checksum descarta lixo **sem ir ao banco**; a resposta é sempre 401 genérico |
| *timing attack* | comparação com `hash_equals`, e o hash é calculado mesmo quando o id não existe |
| chave colada no GitHub ou no Slack | prefixo + `scanPattern()` para varredura de segredos |
| chave com poder demais | **escopos** (`invoices:read`, `invoices:*`, `*`) |
| funcionário saiu ou chave vazou | `revoke()` na hora |
| troca de chave derruba a integração | `rotate()` com período de carência: as duas valem por um tempo |

## Uso

```php
use Ph20sr\ApiKeys\{ApiKeys, KeyFormat};

$keys = new ApiKeys($pdo, new KeyFormat('vx_live'), pepper: getenv('API_KEY_PEPPER'));
$keys->install();   // cria a tabela api_keys (uma vez)

// Painel do cliente: criar chave (mostre o texto UMA vez)
['key' => $plain, 'apiKey' => $apiKey] = $keys->create(
    ownerId: "account:{$accountId}",
    name: 'Integração ERP',
    scopes: ['invoices:read', 'customers:*'],
    expiresAt: new DateTimeImmutable('+1 year'),
);

// Na API
$token = preg_replace('/^Bearer\s+/i', '', $_SERVER['HTTP_AUTHORIZATION'] ?? '');
$check = $keys->verify($token, 'invoices:read');

if (!$check->valid) {
    error_log("api key rejeitada: {$check->reason}");   // malformed, not_found, revoked, expired...
    http_response_code($check->httpStatus());           // 401, ou 403 se faltou escopo
    exit(json_encode(['error' => 'unauthorized']));
}
$accountId = $check->key->ownerId;
```

### Gestão

```php
$keys->list("account:{$accountId}");     // id, nome, escopos, criada, expira, último uso (sem segredo)
$keys->revoke($id);
['key' => $nova] = $keys->rotate($id, graceSeconds: 7 * 86400);   // a antiga vale por mais 7 dias

$format = new KeyFormat('vx_live');
$format->mask($plain);           // 'vx_live_3kTq9ZcW1mPa…2oB' (para exibir em telas e logs)
preg_match_all($format->scanPattern(), $textoDoTicket, $vazadas);
```

`last_used_at` é gravado no máximo uma vez por minuto por chave. Assim o painel mostra "usada há 3 min" sem gerar uma escrita no banco a cada requisição.

## Testes

```bash
composer install
vendor/bin/phpunit
```

Os testes cobrem: checksum contra erro de digitação, ausência do segredo no banco, escopos com curinga, cada motivo de rejeição, pepper diferente, revogação, expiração, rotação com carência e o limite de gravação do `last_used_at`.

## Licença

MIT
