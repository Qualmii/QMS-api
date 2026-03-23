<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Str;

/**
 * Модель для хранения токенов подтверждения логина
 * Каждый логин с нового устройства требует подтверждения по email
 */
class LoginToken extends Model
{
    use HasFactory;

    protected $fillable = [
        'user_id',
        'token',
        'device_name',
        'ip_address',
        'user_agent',
        'device_token',
        'is_confirmed',
        'confirmed_at',
        'expires_at',
    ];

    protected $casts = [
        'user_id' => 'string',
        'is_confirmed' => 'boolean',
        'confirmed_at' => 'datetime',
        'expires_at' => 'datetime',
    ];

    /**
     * Пользователь, для которого создан логин-токен
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Генерировать уникальный токен
     */
    public static function generateToken(): string
    {
        return Str::random(64);
    }

    /**
     * Проверить, истёк ли токен.
     * null означает бессрочный токен — никогда не истекает.
     */
    public function isExpired(): bool
    {
        if ($this->expires_at === null) {
            return false;
        }

        return now()->isAfter($this->expires_at);
    }

    /**
     * Проверить, подтверждён ли логин
     */
    public function isConfirmed(): bool
    {
        return $this->is_confirmed && ! $this->isExpired();
    }

    /**
     * Подтвердить логин.
     *
     * При подтверждении генерируется бессрочный device_token, который клиент
     * сохраняет (localStorage / Keychain) и отправляет в заголовке
     * X-Device-Token при каждом последующем входе.
     * expires_at обнуляется — доверенное устройство не протухает.
     */
    public function confirm(): void
    {
        if (! $this->isExpired()) {
            $this->update([
                'is_confirmed' => true,
                'confirmed_at' => now(),
                'device_token' => Str::random(64),
                'expires_at'   => null, // бессрочно
            ]);
        }
    }

    /**
     * Найти действительный токен
     */
    public static function findValidToken(string $token): ?self
    {
        $loginToken = self::where('token', $token)->first();

        if ($loginToken && ! $loginToken->isExpired()) {
            return $loginToken;
        }

        return null;
    }

    /**
     * Получить неподтвержденные логины пользователя
     */
    public static function getUnconfirmedLogins(string $userId)
    {
        return self::where('user_id', $userId)
            ->where('is_confirmed', false)
            ->where('expires_at', '>', now())
            ->get();
    }

    /**
     * Удалить истекшие токены.
     * Записи с expires_at = null (подтверждённые устройства) не трогаем.
     */
    public static function deleteExpired(): int
    {
        return self::whereNotNull('expires_at')
            ->where('expires_at', '<', now())
            ->delete();
    }
}
