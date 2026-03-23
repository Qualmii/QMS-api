<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Events\LoginConfirmed;
use App\Events\UserPresenceChanged;
use App\Http\Requests\User\ConfirmLoginRequest;
use App\Http\Requests\User\LoginRequest;
use App\Http\Requests\User\RegisterRequest;
use App\Models\LoginToken;
use App\Models\User;
use App\Services\LoginService;
use App\Services\RegistrationService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;
use Jenssegers\Agent\Agent;
use OpenApi\Annotations as OA;
use Symfony\Component\HttpFoundation\Response;
use Tymon\JWTAuth\Facades\JWTAuth;

/**
 * @OA\Tag(
 *     name="Authentication",
 *     description="User registration, login, and token management endpoints. Implements two-factor authentication via email for new devices."
 * )
 */
class AuthController extends Controller
{
    public Agent $agent;

    public function __construct(Agent $agent)
    {
        $this->agent = $agent;
    }

    /**
     * @OA\Post(
     *     path="/api/v1/register",
     *     operationId="register",
     *     summary="Register a new user account",
     *     description="Create a new user account with email and password. User automatically receives a unique UIN (8-digit identifier) and can optionally set a custom username later. RSA key pair is generated for end-to-end encryption.",
     *     tags={"Authentication"},
     *     @OA\RequestBody(
     *         required=true,
     *         description="User registration data",
     *         @OA\JsonContent(
     *             required={"name", "email", "password", "password_confirmation"},
     *             @OA\Property(property="name", type="string", minLength=2, maxLength=255, example="John Doe", description="User full name"),
     *             @OA\Property(property="email", type="string", format="email", example="john@example.com", description="Valid email address (must be unique)"),
     *             @OA\Property(property="password", type="string", format="password", minLength=8, example="SecurePass123!", description="Password (min 8 chars, must include uppercase, lowercase, digit)"),
     *             @OA\Property(property="password_confirmation", type="string", format="password", example="SecurePass123!", description="Password confirmation (must match password)")
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="User registered successfully. JWT token issued for immediate access.",
     *         @OA\JsonContent(ref="#/components/schemas/RegisterResponse")
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(ref="#/components/schemas/ValidationError")
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Server error (e.g., encryption key generation failed)"
     *     )
     * )
     */
    public function register(RegisterRequest $request): JsonResponse
    {
        $data = $request->validated();
        $registrationService = new RegistrationService();

        // Сервис обрабатывает всю логику регистрации и генерирует событие
        $user = $registrationService->register(
            $data['name'],
            $data['email'],
            $data['password']
        );

        return response()->json(
            [
                'message' => 'Registration successful. Please check your email to confirm your account.',
                'user' => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'uin' => $user->uin,
                    'username' => $user->username,
                ],
            ],
            Response::HTTP_CREATED
        );
    }

    /**
     * @OA\Post(
     *     path="/api/v1/login",
     *     operationId="login",
     *     summary="Authenticate user - Step 1 (Initiate login)",
     *     description="Start the login process. For new devices, sends a confirmation email with a link valid for 3 hours. For known devices, returns JWT token immediately. Users can login with either email or UIN.",
     *     tags={"Authentication"},
     *     @OA\RequestBody(
     *         required=true,
     *         description="Login credentials",
     *         @OA\JsonContent(
     *             required={"login", "password"},
     *             @OA\Property(property="login", type="string", example="john@example.com", description="Email address or UIN (8 digits)"),
     *             @OA\Property(property="password", type="string", format="password", example="SecurePass123!", description="User password"),
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Check your email for confirmation link (new device) or token issued immediately (known device)",
     *         @OA\JsonContent(
     *             oneOf={
     *                 @OA\Schema(ref="#/components/schemas/LoginStep1Response"),
     *                 @OA\Schema(ref="#/components/schemas/LoginStep2Response")
     *             }
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Invalid credentials (wrong email/UIN or password)",
     *         @OA\JsonContent(
     *             @OA\Property(property="error", type="string", example="Invalid credentials")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(ref="#/components/schemas/ValidationError")
     *     )
     * )
     */
    public function login(LoginRequest $request): JsonResponse
    {
        $data = $request->validated();
        $loginService = new LoginService();

        // Ищем пользователя по email или UIN
        $user = User::where('email', $data['login'])
            ->orWhere('uin', $data['login'])
            ->first();

        if (!$user || !Hash::check($data['password'], $user->password)) {
            return response()->json(
                ['error' => 'Invalid credentials'],
                Response::HTTP_UNAUTHORIZED
            );
        }

        $deviceNameFromRequest = request()->input('device_name');
        $agentDetectedDevice = $this->agent->device();

        // Agent::device() может вернуть false, а сервис ожидает string.
        $deviceName = is_string($deviceNameFromRequest) && trim($deviceNameFromRequest) !== ''
            ? trim($deviceNameFromRequest)
            : (is_string($agentDetectedDevice) && trim($agentDetectedDevice) !== ''
                ? trim($agentDetectedDevice)
                : 'Unknown Device');
        $userAgent   = request()->header('User-Agent');
        $ipAddress   = request()->ip();
        $deviceToken = request()->header('X-Device-Token');

        // Идентификация устройства только по device_token.
        // IP и UA сохраняются для отображения в истории сессий, но не влияют на проверку.
        $isNewDevice = $loginService->isNewDevice($user, $deviceToken);

        if ($isNewDevice) {
            // Новое устройство — требуем подтверждение по email
            $loginService->createLoginToken(
                $user,
                $deviceName,
                $ipAddress,
                $userAgent
            );

            return response()->json([
                'message' => 'Confirmation email sent. Link is valid for 3 hours.',
                'requires_confirmation' => true,
            ]);
        }

        // Известное устройство — выдаём JWT сразу
        $token = JWTAuth::fromUser($user);

        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => config('jwt.ttl') * 60,
            'device_token' => $deviceToken,
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'uin' => $user->uin,
                'username' => $user->username,
                'status' => $user->status,
                'online_status' => $user->online_status,
                'custom_status' => $user->custom_status,
                'locale' => $user->locale,
                'last_seen_at' => $user->last_seen_at,
                'avatar_url' => $user->avatar ? Storage::disk('public')->url($user->avatar) : null,
            ],
            'requires_confirmation' => false,
        ]);
    }

    /**
     * @OA\Post(
     *     path="/api/v1/login/confirm",
     *     operationId="confirmLogin",
     *     summary="Confirm login - Step 2 (Verify email token)",
     *     description="Verify the confirmation token received via email. After successful verification, JWT token is issued. Token must be confirmed within 3 hours or it expires.",
     *     tags={"Authentication"},
     *     @OA\RequestBody(
     *         required=true,
     *         description="Confirmation token from email",
     *         @OA\JsonContent(
     *             required={"token"},
     *             @OA\Property(property="token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...", description="Token received in confirmation email")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Login confirmed successfully. JWT token issued.",
     *         @OA\JsonContent(ref="#/components/schemas/ConfirmLoginResponse")
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="Token is invalid or expired (expired after 3 hours)",
     *         @OA\JsonContent(
     *             @OA\Property(property="error", type="string", example="Invalid or expired token")
     *         )
     *     )
     * )
     */
    public function confirmLogin(ConfirmLoginRequest $request): JsonResponse
    {
        $data = $request->validated();
        $loginService = new LoginService();

        // Сначала найдем login token напрямую
        $loginToken = LoginToken::where('token', $data['token'])->first();

        if (!$loginToken || $loginToken->isExpired()) {
            return response()->json(
                ['error' => 'Invalid or expired token'],
                Response::HTTP_UNAUTHORIZED
            );
        }

        // Подтверждаем и получаем JWT + device_token
        $result = $loginService->confirmLoginAndGetToken($data['token']);

        if (!$result) {
            return response()->json(
                ['error' => 'Invalid or expired token'],
                Response::HTTP_UNAUTHORIZED
            );
        }

        // Гарантированно загрузим пользователя
        $user = $loginToken->user()->first();

        // Генерируем событие подтверждения входа
        event(new LoginConfirmed($user, $loginToken->device_name));

        return response()->json([
            'access_token' => $result['jwt'],
            'token_type'   => 'bearer',
            'expires_in'   => config('jwt.ttl') * 60,
            'device_token' => $result['device_token'],
            'user' => $user ? [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'uin' => $user->uin,
                'username' => $user->username,
                'status' => $user->status,
                'online_status' => $user->online_status,
                'custom_status' => $user->custom_status,
                'locale' => $user->locale,
                'last_seen_at' => $user->last_seen_at,
                'avatar_url' => $user->avatar ? Storage::disk('public')->url($user->avatar) : null,
            ] : null,
        ], Response::HTTP_OK);
    }

    /**
     * @OA\Get(
     *     path="/api/v1/login/confirm/{token}",
     *     operationId="confirmLoginWeb",
     *     summary="Confirm login via web link (browser)",
     *     description="Verification endpoint for web-based confirmation link from email. Can redirect to mobile app or return token directly. Primarily used for browser/web clients.",
     *     tags={"Authentication"},
     *     @OA\Parameter(
     *         name="token",
     *         in="path",
     *         required=true,
     *         description="Confirmation token from email",
     *         @OA\Schema(type="string", format="uuid")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Login confirmed. Redirect to mobile app or return token.",
     *         @OA\JsonContent(ref="#/components/schemas/ConfirmLoginResponse")
     *     ),
     *     @OA\Response(
     *         response=302,
     *         description="Redirect to mobile app with token parameter",
     *         @OA\Header(
     *             header="Location",
     *             description="Redirect URL with token parameter",
     *             @OA\Schema(type="string", format="uri")
     *         )
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="Token is invalid or expired",
     *         @OA\JsonContent(
     *             @OA\Property(property="error", type="string")
     *         )
     *     )
     * )
     */
    public function confirmLoginWeb(string $token): RedirectResponse
    {
        $loginToken = LoginToken::where('token', $token)->first();
        $frontendLoginUrl = rtrim((string) config('app.frontend_url'), '/') . '/login';

        if (! $loginToken || $loginToken->isExpired()) {
            return redirect()->away(
                $this->buildRedirectUrl($frontendLoginUrl, [
                    'confirmation_error' => 'invalid_or_expired',
                ])
            );
        }

        return redirect()->away(
            $this->buildRedirectUrl($frontendLoginUrl, [
                'confirmation_token' => $token,
            ])
        );
    }

    /**
     * @param array<string, scalar|null> $params
     */
    private function buildRedirectUrl(string $baseUrl, array $params): string
    {
        $query = http_build_query(array_filter($params, static fn ($value) => $value !== null));

        if ($query === '') {
            return $baseUrl;
        }

        $separator = str_contains($baseUrl, '?') ? '&' : '?';

        return $baseUrl . $separator . $query;
    }

    /**
     * @OA\Post(
     *     path="/api/v1/logout",
     *     operationId="logout",
     *     summary="Logout and invalidate JWT token",
     *     description="Invalidate the current JWT token and end the session. Existing sessions on other devices remain valid. Must be called before discarding the token.",
     *     tags={"Authentication"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="Successfully logged out",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Successfully logged out")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthenticated (no valid token provided)"
     *     )
     * )
     */
    public function logout(): JsonResponse
    {
        /** @var User $user */
        $user = Auth::user();

        // Переводим пользователя в офлайн и уведомляем всех участников его чатов
        if ($user) {
            $user->setOffline();
            event(new UserPresenceChanged($user));
        }

        JWTAuth::invalidate(JWTAuth::getToken());

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * @OA\Post(
     *     path="/api/v1/refresh",
     *     operationId="refresh",
     *     summary="Refresh JWT token",
     *     description="Extend the current session by issuing a new JWT token. Call this when token is about to expire (check expires_in value). Old token becomes invalid immediately.",
     *     tags={"Authentication"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="Token refreshed successfully",
     *         @OA\JsonContent(ref="#/components/schemas/ConfirmLoginResponse")
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Token is invalid or expired and cannot be refreshed"
     *     )
     * )
     */
    public function refresh(): JsonResponse
    {
        return $this->respondWithToken(JWTAuth::refresh(JWTAuth::getToken()));
    }

    /**
     * @OA\Get(
     *     path="/api/v1/me",
     *     operationId="me",
     *     summary="Get the authenticated user profile",
     *     description="Retrieve the complete profile information of the authenticated user, including personal data, status, and settings.",
     *     tags={"Authentication"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="Current user details",
     *         @OA\JsonContent(ref="#/components/schemas/UserProfileResponse")
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthenticated (no valid token provided)"
     *     )
     * )
     */
    public function me(): JsonResponse
    {
        return response()->json(auth()->user());
    }

    protected function respondWithToken(string $token): JsonResponse
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => config('jwt.ttl') * 60,
            'user' => auth()->user()
        ]);
    }
}
