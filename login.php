<?php
// Being able to access this page means the user has logged in
// http://localhost.edu/redcap_v99.9.99/ExternalModules/?prefix=shibboleth_survey_auth&page=login&pid=16&s=1234567890
$generic_error = "Unable to authenticate user. Please contact your REDCap administrator.";
$session = null;
foreach ($_COOKIE as $key => $value) {
    $session = str_starts_with($key, "redcap_survey_session_") ? $value : $session;
}
$survey = $module->escape($_GET["s"]);
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

// Check if user is on the allowlist
if ($allowlist) {
    $q = $module->query('SELECT * FROM redcap_user_allowlist WHERE username = ?', $user);
    if (db_num_rows($q) == 0)
        die($generic_error);
}

// Build hash and redirect to survey
$hash = $module->makeHash($project_id, $session, $user, $time);
$base = "http" . (empty($_SERVER["HTTPS"]) ? "" : "s") . "://" . $_SERVER["HTTP_HOST"];

// Set cookie and redirect
setcookie("ShibbolethSurveyAuth", $hash, 0, "/");
header("Location: $base/surveys/?s=$survey&auth=$hash");
