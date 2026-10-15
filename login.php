<?php
// Being able to access this page means the user has logged in
// http://localhost.edu/redcap_v99.9.99/ExternalModules/?prefix=shibboleth_survey_auth&page=login&pid=16&s=1234567890

/** @var \UWMadison\ShibbolethSurveyAuth\ShibbolethSurveyAuth $module */
/** @var \UWMadison\ShibbolethSurveyAuth\ShibbolethSurveyAuth $project_id */
$generic_error = "Unable to authenticate user. Please contact your REDCap administrator.";
$session = null;
foreach ($_COOKIE as $key => $value) {
    $session = str_starts_with($key, "redcap_survey_session_") ? $value : $session;
}
$survey = $_GET["s"] ?? "";
$time = time();
$item = $module->getSystemSetting("user-item");
$allowlist = $module->getProjectSetting("allowlist") == "1";
$user = $_SERVER[empty($item) ? $module->defaultItem : $item];

// No session, try to refresh
if (empty($session)) {
    header("Refresh:0");
    exit;
}

// Check for bad configuration or something else went wrong
if (empty($survey) || empty($user) || empty($session) || !preg_match('/^[A-Za-z0-9]{16}$/', $survey))
    die($generic_error);

// Normalize the survey code before using it in a redirect; it is expected to be a fixed
// alphanumeric token and this prevents tainted input from flowing into the header.
$survey = rawurlencode($survey);

// Check if user is on the allowlist
if ($allowlist) {
    $q = $module->query('SELECT * FROM redcap_user_allowlist WHERE username = ?', $user);
    if (db_num_rows($q) == 0)
        die($generic_error);
}

// Build hash and redirect to survey
$hash = $module->makeHash($project_id, $session, $user, $time);
$base = defined("APP_PATH_WEBROOT_FULL") ? rtrim(APP_PATH_WEBROOT_FULL, "/") . "/" : ("https://" . $_SERVER["HTTP_HOST"] . "/");

// Set cookie and redirect
setcookie("ShibbolethSurveyAuth", $hash, [
    "expires" => 0,
    "path" => "/",
    "secure" => !empty($_SERVER["HTTPS"]),
    "httponly" => true,
    "samesite" => "Lax",
]);
header("Location: {$base}surveys/?s={$survey}");
exit;
