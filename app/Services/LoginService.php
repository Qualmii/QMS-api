<?php

declare(strict_types=1);

namespace App\Services;

use App\Events\LoginConfirmationRequested;
use App\Mail\LoginConfirmationMail;
use App\Models\LoginToken;
use App\Models\User;
use Illuminate\Support\Facades\Mail;
use Tymon\JWTAuth\Facades\JWTAuth;

/**
 * Сервис для управления аутентификацией и подтверждением логинов
 */
class LoginService
{
    /**
     * Создать токен логина для подтверждения
     * Отправить письмо с ссылкой подтверждения
     */
    public function createLoginToken(
        User    $user,
        string  $deviceName,
        ?string $ipAddress = null,
        ?string $userAgent = null
    ): LoginToken
    {
        // Удаляем истекшие токены
        LoginToken::deleteExpired();

        // Создаем новый токен
        $loginToken = LoginToken::create([
            'user_id' => $user->id,
            'token' => LoginToken::generateToken(),
            'device_name' => $deviceName,
            'ip_address' => $ipAddress,
            'user_agent' => $userAgent,
            'is_confirmed' => false,
            'expires_at' => now()->addHours(3), // Действителен 3 часа
        ]);

        // Генерируем событие - слушатель отправит письмо
        event(new LoginConfirmationRequested($user, $loginToken, $deviceName));

        return $loginToken;
    }

    /**
     * Подтвердить логин и выдать JWT + бессрочный device_token.
     *
     * @return array{jwt: string, device_token: string}|null
     */
    public function confirmLoginAndGetToken(string $token): ?array
    {
        $loginToken = LoginToken::findValidToken($token);

        if (!$loginToken) {
            return null;
        }

        $loginToken->confirm();
        $loginToken->refresh();

        return [
            'jwt'          => JWTAuth::fromUser($loginToken->user),
            'device_token' => $loginToken->device_token,
        ];
    }

    /**
     * Проверить, является ли устройство новым (не доверенным).
     *
     * Идентификация выполняется исключительно по бессрочному device_token,
     * который клиент получает после первого подтверждения и отправляет
     * в заголовке X-Device-Token. IP и User-Agent не используются:
     * IP меняется слишком часто и провоцирует лишние подтверждения.
     */
    public function isNewDevice(User $user, ?string $deviceToken): bool
    {
        if (!$deviceToken) {
            return true;
        }

        return !LoginToken::where('user_id', $user->id)
            ->where('device_token', $deviceToken)
            ->where('is_confirmed', true)
            ->exists();
    }

    /**
     * Получить список неподтвержденных логинов пользователя
     */
    public function getUnconfirmedLogins(User $user)
    {
        return LoginToken::getUnconfirmedLogins($user->id);
    }

    /**
     * Получить список подтверждённых сессий пользователя.
     * Подтверждённые устройства бессрочны (expires_at = null),
     * поэтому фильтрация по времени не нужна.
     */
    public function getConfirmedSessions(User $user)
    {
        return LoginToken::where('user_id', $user->id)
            ->where('is_confirmed', true)
            ->orderBy('confirmed_at', 'desc')
            ->get();
    }

    /**
     * Завершить сессию (удалить токен логина)
     */
    public function endSession(User $user, int $loginTokenId): bool
    {
        $loginToken = LoginToken::where('id', $loginTokenId)
            ->where('user_id', $user->id)
            ->first();

        if ($loginToken) {
            $loginToken->delete();
            return true;
        }

        return false;
    }

    /**
     * Получить пользователя по токену подтверждения (если токен действителен)
     */
    public function getUserFromToken(string $token): ?User
    {
        return LoginToken::findValidToken($token)?->user;
    }
}
