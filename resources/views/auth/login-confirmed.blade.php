<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Вход подтверждён — QMS</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #f0f2f5;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            color: #333;
        }

        .card {
            background: #fff;
            border-radius: 12px;
            box-shadow: 0 4px 24px rgba(0,0,0,0.10);
            padding: 48px 40px;
            max-width: 420px;
            width: 100%;
            text-align: center;
        }

        .icon {
            width: 72px;
            height: 72px;
            border-radius: 50%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 24px;
            font-size: 36px;
        }

        h1 {
            font-size: 22px;
            font-weight: 700;
            margin-bottom: 10px;
            color: #1a1a2e;
        }

        p {
            font-size: 15px;
            color: #666;
            line-height: 1.6;
            margin-bottom: 8px;
        }

        .redirect-hint {
            font-size: 13px;
            color: #aaa;
            margin-top: 24px;
        }

        .spinner {
            display: inline-block;
            width: 16px;
            height: 16px;
            border: 2px solid #ddd;
            border-top-color: #764ba2;
            border-radius: 50%;
            animation: spin 0.7s linear infinite;
            vertical-align: middle;
            margin-right: 6px;
        }

        @keyframes spin { to { transform: rotate(360deg); } }

        .manual-link {
            display: inline-block;
            margin-top: 20px;
            color: #764ba2;
            text-decoration: underline;
            font-size: 14px;
            cursor: pointer;
        }

        .error-card .icon { background: linear-gradient(135deg, #f5576c 0%, #f093fb 100%); }
        .error-card h1 { color: #c0392b; }
    </style>
</head>
<body>

<div class="card" id="main-card">
    <div class="icon">✅</div>
    <h1>Вход подтверждён!</h1>
    <p>Вы успешно вошли в аккаунт.</p>
    <p class="redirect-hint">
        <span class="spinner"></span>
        Перенаправление в приложение…
    </p>
    <a class="manual-link" id="manual-link" href="{{ $frontendUrl }}">
        Нажмите здесь, если не перенаправляет
    </a>
</div>

<script>
    (function () {
        var token       = @json($accessToken);
        var deviceToken = @json($deviceToken);
        var tokenType   = @json($tokenType);
        var expiresIn   = @json($expiresIn);
        var frontendUrl = @json($frontendUrl);

        // Сохраняем токены в localStorage
        try {
            localStorage.setItem('access_token', token);
            localStorage.setItem('device_token', deviceToken);
            localStorage.setItem('token_type', tokenType);
            localStorage.setItem('expires_in', expiresIn);
            localStorage.setItem('token_expires_at', Date.now() + expiresIn * 1000);
        } catch (e) {
            // Если localStorage недоступен — просто редиректим
        }

        // device_token передаётся в hash-фрагменте (#) — не попадает в server-логи
        var redirectUrl = frontendUrl + '#access_token=' + encodeURIComponent(token)
                        + '&device_token=' + encodeURIComponent(deviceToken)
                        + '&token_type=' + encodeURIComponent(tokenType)
                        + '&expires_in=' + expiresIn;

        document.getElementById('manual-link').href = redirectUrl;

        setTimeout(function () {
            window.location.href = redirectUrl;
        }, 1500);
    })();
</script>

</body>
</html>

