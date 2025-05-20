<?php
/**
 * Plugin Name: PressHook - Custom WP Webhooks
 * Description: Create and manage custom webhook endpoints from the WordPress admin.
 * Version: 0.3.0
 * Author: You
 */

// Register custom menu in admin
add_action('admin_menu', function() {
    add_menu_page('PressHook', 'PressHook', 'manage_options', 'presshook', 'presshook_admin_page');
});

// Add REST route for incoming hooks
add_action('rest_api_init', function () {
    register_rest_route('presshook/v1', '/hook/(?P<slug>[a-zA-Z0-9_-]+)/', [
        'methods'  => 'POST',
        'callback' => 'presshook_handle_webhook',
        'permission_callback' => '__return_true'
    ]);
});

function presshook_handle_webhook(WP_REST_Request $request) {
    $slug = $request->get_param('slug');
    $payload = $request->get_json_params();
    $headers = $request->get_headers();

    $hooks = get_option('presshook_hooks', []);
    $code = $hooks[$slug] ?? '';

    if (!$code) {
        presshook_log_event($slug, 'No hook found for slug', $payload);
        return new WP_REST_Response(['error' => 'No hook found for slug'], 404);
    }

    // Signature-based validation for Lemon Squeezy and Green Invoice
    $secret = get_option('presshook_secret_' . $slug);
    if ($secret) {
        $raw_body = file_get_contents('php://input');

        // Detect signature header
        $sigHeader = $_SERVER['HTTP_X_SIGNATURE'] ?? $_SERVER['HTTP_X_WEBHOOK_SIGNATURE'] ?? '';

        $expected_signature = hash_hmac('sha256', $raw_body, $secret);

        if (!hash_equals($expected_signature, $sigHeader)) {
            presshook_log_event($slug, 'Invalid signature', json_decode($raw_body, true));
            return new WP_REST_Response(['error' => 'Unauthorized'], 403);
        }
    }

    ob_start();
    try {
        $eventName = $payload['meta']['event_name'] ?? 'unknown';
        error_log("[PressHook:$slug] Incoming event: $eventName");
        eval($code);
        $output = ob_get_clean();
        presshook_log_event($slug, "Executed successfully (event: $eventName)", $payload, $output);
    } catch (Throwable $e) {
        $output = 'Error: ' . $e->getMessage();
        presshook_log_event($slug, $output, $payload);
    }

    return new WP_REST_Response(['output' => $output], 200);
}

function presshook_admin_page() {
    if (!current_user_can('manage_options')) return;

    $hooks = get_option('presshook_hooks', []);
    $slug = $_GET['slug'] ?? '';
    $code = $hooks[$slug] ?? '';
    $secret = get_option('presshook_secret_' . $slug);

    if (isset($_POST['presshook_code'])) {
        check_admin_referer('presshook_save');
        $hooks[$_POST['presshook_slug']] = stripslashes($_POST['presshook_code']);
        update_option('presshook_hooks', $hooks);
        update_option('presshook_secret_' . $_POST['presshook_slug'], sanitize_text_field($_POST['presshook_secret']));
        echo '<div class="updated"><p>Hook saved.</p></div>';
    }

    echo '<div class="wrap"><h1>PressHook - Manage Webhooks</h1>';
    echo '<form method="post">';
    wp_nonce_field('presshook_save');
    echo '<input type="text" name="presshook_slug" value="' . esc_attr($slug) . '" placeholder="hook-name" required style="width:200px;" />';
    echo '<br><br><textarea name="presshook_code" rows="15" cols="100" placeholder="PHP code executed when webhook is called.">' . esc_textarea($code) . '</textarea>';
    echo '<br><br><input type="text" name="presshook_secret" value="' . esc_attr($secret) . '" placeholder="signing secret (for Lemon Squeezy)" style="width:300px;" />';
    echo '<br><br><input type="submit" class="button-primary" value="Save Hook">';
    echo '</form><hr><h2>Existing Hooks</h2><ul>';
    foreach ($hooks as $key => $_) {
        echo '<li><a href="?page=presshook&slug=' . urlencode($key) . '">' . esc_html($key) . '</a></li>';
    }
    echo '</ul><hr><h2>Webhook URLs</h2><ul>';
    foreach ($hooks as $key => $_) {
        $url = rest_url('presshook/v1/hook/' . $key);
        echo '<li><code>' . esc_html($url) . '</code></li>';
    }
    echo '</ul><hr><h2>Recent Logs</h2><table class="widefat fixed striped"><thead><tr><th>Time</th><th>Slug</th><th>Message</th><th>Payload</th><th>Output</th></tr></thead><tbody>';
    $logs = get_option('presshook_logs', []);
    foreach (array_reverse($logs) as $entry) {
        echo '<tr>';
        echo '<td>' . esc_html($entry['time']) . '</td>';
        echo '<td>' . esc_html($entry['slug']) . '</td>';
        echo '<td>' . esc_html($entry['message']) . '</td>';
        echo '<td><pre>' . esc_html(json_encode($entry['payload'], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)) . '</pre></td>';
        echo '<td><pre>' . esc_html($entry['output']) . '</pre></td>';
        echo '</tr>';
    }
    echo '</tbody></table></div>';
}

function presshook_log_event($slug, $message, $payload = [], $output = '') {
    $log = get_option('presshook_logs', []);
    $log[] = [
        'time' => current_time('mysql'),
        'slug' => $slug,
        'message' => $message,
        'payload' => $payload,
        'output' => $output
    ];
    update_option('presshook_logs', array_slice($log, -50)); // keep last 50 logs
}
