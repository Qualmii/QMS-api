<?php

namespace Tests\Feature;

use App\Mail\LoginConfirmationMail;
use App\Mail\RegistrationConfirmationMail;
use App\Models\LoginToken;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class AuthenticationTest extends TestCase
{
    use RefreshDatabase;

    private const DEFAULT_PASSWORD = 'SecurePass123!';

    /**
     * Test 1: Регистрация - проверка ответа и создания пользователя
     */
    public function test_user_can_register_and_get_confirmation_message(): void
    {
        Mail::fake();

        $response = $this->registerUser();

        $response->assertStatus(201)
            ->assertJsonStructure([
                'message',
                'user' => ['id', 'name', 'email', 'uin', 'username'],
            ])
            ->assertJsonMissingPath('access_token');

        $this->assertDatabaseHas('users', [
            'email' => 'john@example.com',
            'name' => 'John Doe',
        ]);

        $user = User::where('email', 'john@example.com')->firstOrFail();
        $this->assertNull($user->email_verified_at);

        Mail::assertSent(RegistrationConfirmationMail::class, function ($mail) use ($user) {
            return $mail->hasTo($user->email);
        });
    }

    /**
     * Test 2: До подтверждения почты логин запрещен
     */
    public function test_user_cannot_login_before_email_confirmation(): void
    {
        $this->registerUser();

        $response = $this->login('john@example.com', self::DEFAULT_PASSWORD);

        $response->assertStatus(200)
            ->assertJson([
                'requires_confirmation' => true,
            ])
            ->assertJsonMissingPath('access_token');
    }

    /**
     * Test 3: Регистрация сохраняет в БД всю необходимую информацию и присваивает UIN
     */
    public function test_user_registration_stores_all_required_data_and_generates_uin(): void
    {
        $this->registerUser([
            'name' => 'Jane Doe',
            'email' => 'jane@example.com',
        ]);

        $user = User::where('email', 'jane@example.com')->first();

        $this->assertNotNull($user);
        $this->assertEquals('Jane Doe', $user->name);
        $this->assertNotNull($user->uin);
        $this->assertTrue(strlen($user->uin) === 8);
        $this->assertTrue(ctype_digit($user->uin));
        $this->assertNotNull($user->public_key);
        $this->assertNull($user->username);
    }

    /**
     * Test 4-7: Невалидные сценарии регистрации
     *
     * @dataProvider invalidRegistrationProvider
     */
    public function test_registration_validation_fails(array $overrides): void
    {
        if (($overrides['precreate_duplicate'] ?? false) === true) {
            User::factory()->create(['email' => 'john@example.com']);
            unset($overrides['precreate_duplicate']);
        }

        $response = $this->registerUser($overrides);
        $response->assertStatus(422);
    }

    public static function invalidRegistrationProvider(): array
    {
        return [
            'invalid email' => [[
                'email' => 'invalid-email',
            ]],
            'short password' => [[
                'password' => 'Short1!',
                'password_confirmation' => 'Short1!',
            ]],
            'mismatched passwords' => [[
                'password_confirmation' => 'DifferentPass123!',
            ]],
            'duplicate email' => [[
                'precreate_duplicate' => true,
            ]],
        ];
    }

    /**
     * Test 7: При входе с нового устройства отправляется письмо с подтверждением
     */
    public function test_login_from_new_device_sends_confirmation_email(): void
    {
        Mail::fake();

        $user = User::factory()->create([
            'email' => 'john@example.com',
            'password' => bcrypt(self::DEFAULT_PASSWORD),
        ]);

        $response = $this->login('john@example.com', self::DEFAULT_PASSWORD, [
            'device_name' => 'iPhone 13',
        ]);

        $response->assertStatus(200)
            ->assertJson([
                'requires_confirmation' => true,
                'message' => 'Confirmation email sent. Link is valid for 3 hours.',
            ]);

        Mail::assertSent(LoginConfirmationMail::class);

        $this->assertDatabaseHas('login_tokens', [
            'user_id' => $user->id,
            'device_name' => 'iPhone 13',
            'is_confirmed' => false,
        ]);
    }

    /**
     * Test 8: После подтверждения по почте пользователь получает JWT токен
     */
    public function test_user_can_confirm_login_and_receive_jwt_token(): void
    {
        $user = User::factory()->create([
            'email' => 'john@example.com',
            'password' => bcrypt(self::DEFAULT_PASSWORD),
        ]);

        $loginToken = LoginToken::create([
            'user_id' => $user->id,
            'token' => LoginToken::generateToken(),
            'device_name' => 'iPhone 13',
            'is_confirmed' => false,
            'expires_at' => now()->addHours(3),
        ]);

        $response = $this->postJson('/api/v1/login/confirm', [
            'token' => $loginToken->token,
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'access_token',
                'token_type',
                'expires_in',
                'device_token',
                'user' => ['id', 'name', 'email', 'uin'],
            ]);

        $loginToken->refresh();
        $this->assertTrue($loginToken->is_confirmed);
        $this->assertNotNull($loginToken->device_token);
        $this->assertNull($loginToken->expires_at); // бессрочный
    }

    /**
     * Test 9: Подтверждение с неверным токеном возвращает ошибку
     */
    public function test_confirm_login_with_invalid_token_fails(): void
    {
        $response = $this->postJson('/api/v1/login/confirm', [
            'token' => 'invalid-token-that-does-not-exist',
        ]);

        $response->assertStatus(401);
    }

    /**
     * Test 10: Истекший токен не может быть использован
     */
    public function test_expired_login_token_cannot_be_used(): void
    {
        $user = User::factory()->create();

        LoginToken::create([
            'user_id' => $user->id,
            'token' => 'expired-token',
            'device_name' => 'iPhone 13',
            'is_confirmed' => false,
            'expires_at' => now()->subHour(),
        ]);

        $response = $this->postJson('/api/v1/login/confirm', [
            'token' => 'expired-token',
        ]);

        $response->assertStatus(401);
    }

    public function test_confirm_login_web_redirects_to_frontend_with_confirmation_token(): void
    {
        $user = User::factory()->create();

        $loginToken = LoginToken::create([
            'user_id' => $user->id,
            'token' => LoginToken::generateToken(),
            'device_name' => 'Safari on macOS',
            'is_confirmed' => false,
            'expires_at' => now()->addHours(3),
        ]);

        $response = $this->get('/api/v1/login/confirm/' . $loginToken->token);

        $response->assertRedirect(config('app.frontend_url') . '/login?confirmation_token=' . $loginToken->token);
    }

    public function test_confirm_login_web_redirects_with_error_for_invalid_or_expired_token(): void
    {
        $response = $this->get('/api/v1/login/confirm/expired-or-invalid-token');

        $response->assertRedirect(config('app.frontend_url') . '/login?confirmation_error=invalid_or_expired');
    }

    /**
     * Test 11: Известное устройство получает JWT токен сразу без подтверждения
     */
    public function test_login_from_known_device_returns_token_immediately(): void
    {
        Mail::fake();

        $user = User::factory()->create([
            'email' => 'john@example.com',
            'password' => bcrypt(self::DEFAULT_PASSWORD),
        ]);

        // Создаём уже подтверждённое устройство с бессрочным device_token
        $deviceToken = Str::random(64);

        LoginToken::create([
            'user_id'      => $user->id,
            'token'        => LoginToken::generateToken(),
            'device_name'  => 'iPhone 13',
            'device_token' => $deviceToken,
            'is_confirmed' => true,
            'confirmed_at' => now(),
            'expires_at'   => null, // бессрочный
        ]);

        // Логин с заголовком X-Device-Token — подтверждение не требуется
        $response = $this->postJson('/api/v1/login', [
            'login'    => 'john@example.com',
            'password' => self::DEFAULT_PASSWORD,
        ], [
            'X-Device-Token' => $deviceToken,
        ]);

        $response->assertStatus(200)
            ->assertJson(['requires_confirmation' => false])
            ->assertJsonStructure(['access_token', 'token_type', 'device_token']);

        Mail::assertNotSent(\App\Mail\LoginConfirmationMail::class);
    }

    /**
     * Test 12: Активные сессии продолжают работать при новом логине
     */
    public function test_existing_sessions_remain_active_after_new_login(): void
    {
        $user = User::factory()->create([
            'email' => 'john@example.com',
            'password' => bcrypt(self::DEFAULT_PASSWORD),
        ]);

        // Создаем активную сессию
        $activeSession = LoginToken::create([
            'user_id' => $user->id,
            'token' => 'active-session-token',
            'device_name' => 'Desktop',
            'is_confirmed' => true,
            'expires_at' => now()->addHours(2),
        ]);

        // Логинимся с нового устройства
        $this->postJson('/api/v1/login', [
            'login' => 'john@example.com',
            'password' => self::DEFAULT_PASSWORD,
            'device_name' => 'Mobile',
        ]);

        // Проверяем, что старая сессия остается активной
        $activeSession->refresh();
        $this->assertTrue($activeSession->is_confirmed);
        $this->assertGreaterThan(now(), $activeSession->expires_at);
    }

    /**
     * Test 13: Логин с невалидными учетными данными
     *
     * @dataProvider loginInvalidCredentialsProvider
     */
    public function test_login_with_invalid_credentials(
        string $login,
        string $password,
        int $expectedStatus,
        array $expectedJson
    ): void {
        User::factory()->create([
            'email' => 'john@example.com',
            'password' => bcrypt(self::DEFAULT_PASSWORD),
        ]);

        $response = $this->login($login, $password);

        $response->assertStatus($expectedStatus)
            ->assertJson($expectedJson);
    }

    public static function loginInvalidCredentialsProvider(): array
    {
        return [
            'wrong password' => [
                'john@example.com',
                'WrongPassword123!',
                401,
                ['error' => 'Invalid credentials'],
            ],
            'unknown email' => [
                'unknown@example.com',
                self::DEFAULT_PASSWORD,
                401,
                ['error' => 'Invalid credentials'],
            ],
            'empty password' => [
                'john@example.com',
                '',
                422,
                ['message' => 'Validation failed'],
            ],
            'empty login' => [
                '',
                self::DEFAULT_PASSWORD,
                422,
                ['message' => 'Validation failed'],
            ],
        ];
    }

    /**
     * Test 14: Логин с UIN вместо email
     */
    public function test_login_with_uin_instead_of_email(): void
    {
        Mail::fake();

        $user = User::factory()->create([
            'email' => 'john@example.com',
            'password' => bcrypt(self::DEFAULT_PASSWORD),
            'email_verified_at' => now(),
        ]);

        $response = $this->login($user->uin, self::DEFAULT_PASSWORD);

        $response->assertStatus(200)
            ->assertJsonStructure(['requires_confirmation', 'message']);
    }

    /**
     * Test 15: Логаут удаляет сессию
     */
    public function test_user_can_logout(): void
    {
        $user = User::factory()->create();

        $token = \Tymon\JWTAuth\Facades\JWTAuth::fromUser($user);

        $response = $this->withHeaders([
            'Authorization' => "Bearer $token",
        ])->postJson('/api/v1/logout');

        $response->assertStatus(200);
    }

    private function registerUser(array $overrides = [])
    {
        return $this->postJson('/api/v1/register', $this->registrationPayload($overrides));
    }

    private function registrationPayload(array $overrides = []): array
    {
        return array_merge([
            'name' => 'John Doe',
            'email' => 'john@example.com',
            'password' => self::DEFAULT_PASSWORD,
            'password_confirmation' => self::DEFAULT_PASSWORD,
        ], $overrides);
    }

    private function login(string $login, string $password, array $overrides = [], array $headers = [])
    {
        return $this->postJson('/api/v1/login', array_merge([
            'login' => $login,
            'password' => $password,
        ], $overrides), $headers);
    }
}
