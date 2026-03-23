<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::table('login_tokens', function (Blueprint $table) {
            // Бессрочный токен доверенного устройства.
            // Генерируется при первом подтверждении; клиент хранит его
            // и присылает в заголовке X-Device-Token при последующих входах.
            $table->string('device_token')->nullable()->unique()->after('user_agent');

            // Для подтверждённых устройств expires_at = null (бессрочно).
            // Для неподтверждённых ссылок expires_at = +3 часа (как раньше).
            $table->timestamp('expires_at')->nullable()->change();
        });
    }

    public function down(): void
    {
        Schema::table('login_tokens', function (Blueprint $table) {
            $table->dropColumn('device_token');
            $table->timestamp('expires_at')->nullable(false)->change();
        });
    }
};

